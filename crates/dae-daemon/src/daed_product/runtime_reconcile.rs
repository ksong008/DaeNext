use super::*;
use std::sync::{Condvar, Weak};

type RuntimeReconcileResult = Result<AppliedRuntimeReload, CoordinatedRuntimeReloadError>;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct RuntimeDesiredSignal {
    epoch: u64,
    stop_epoch: u64,
}

#[derive(Clone, Debug)]
pub(in crate::daed_product) struct RuntimeReconciler {
    inner: Arc<RuntimeReconcilerInner>,
}

#[derive(Debug)]
struct RuntimeReconcilerInner {
    coordinator: RuntimeApplyCoordinator,
    next_request: AtomicU64,
    next_desired_epoch: AtomicU64,
    desired: tokio::sync::watch::Sender<RuntimeDesiredSignal>,
    flights: Mutex<HashMap<String, Weak<RuntimeReconcileFlight>>>,
    state: Mutex<RuntimeReconcileState>,
}

#[derive(Debug, Default)]
struct RuntimeReconcileState {
    preparing: BTreeMap<u64, RuntimePreparingState>,
    committing_request: Option<u64>,
    desired_epoch: u64,
    desired_fingerprint: Option<String>,
    last_completed_request: Option<u64>,
    last_result: Option<String>,
    joined_count: u64,
    coalesced_count: u64,
    superseded_count: u64,
    updated_at: Option<String>,
}

#[derive(Debug)]
struct RuntimePreparingState {
    source: &'static str,
    phase: &'static str,
    desired_epoch: Option<u64>,
}

#[derive(Debug)]
struct RuntimeReconcileFlight {
    result: Mutex<Option<RuntimeReconcileResult>>,
    completed: Condvar,
}

pub(in crate::daed_product) struct RuntimeReconcileRequest {
    reconciler: RuntimeReconciler,
    request_id: u64,
    intent: RuntimeApplyIntent,
    admitted: bool,
}

pub(in crate::daed_product) enum RuntimeReconcileAdmission {
    Lead(RuntimeReconcileLead),
    Follow(RuntimeReconcileFollower),
}

pub(in crate::daed_product) struct RuntimeReconcileLead {
    reconciler: RuntimeReconciler,
    request_id: u64,
    intent: RuntimeApplyIntent,
    desired_epoch: u64,
    accepted_stop_epoch: u64,
    fingerprint: String,
    desired: tokio::sync::watch::Receiver<RuntimeDesiredSignal>,
    flight: Arc<RuntimeReconcileFlight>,
    finished: bool,
}

pub(in crate::daed_product) struct RuntimeReconcileFollower {
    flight: Arc<RuntimeReconcileFlight>,
}

impl RuntimeReconciler {
    pub(in crate::daed_product) fn new(coordinator: RuntimeApplyCoordinator) -> Self {
        let (desired, _) = tokio::sync::watch::channel(RuntimeDesiredSignal::default());
        Self {
            inner: Arc::new(RuntimeReconcilerInner {
                coordinator,
                next_request: AtomicU64::new(1),
                next_desired_epoch: AtomicU64::new(1),
                desired,
                flights: Mutex::new(HashMap::new()),
                state: Mutex::new(RuntimeReconcileState::default()),
            }),
        }
    }

    pub(in crate::daed_product) fn begin(
        &self,
        intent: RuntimeApplyIntent,
    ) -> RuntimeReconcileRequest {
        let request_id = self.inner.next_request.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut state) = self.inner.state.lock() {
            state.preparing.insert(
                request_id,
                RuntimePreparingState {
                    source: intent.source(),
                    phase: "snapshot",
                    desired_epoch: None,
                },
            );
            state.updated_at = Some(now_text());
        }
        RuntimeReconcileRequest {
            reconciler: self.clone(),
            request_id,
            intent,
            admitted: false,
        }
    }

    #[cfg(test)]
    pub(in crate::daed_product) fn begin_exclusive(
        &self,
        intent: RuntimeApplyIntent,
    ) -> Result<RuntimeApplyPermit<'_>, String> {
        self.inner.coordinator.begin_apply(intent)
    }

    pub(in crate::daed_product) fn cancel_preparation_for_stop(&self) {
        let current = *self.inner.desired.borrow();
        let desired_epoch = self.inner.next_desired_epoch.fetch_add(1, Ordering::AcqRel);
        self.inner.desired.send_replace(RuntimeDesiredSignal {
            epoch: desired_epoch,
            stop_epoch: current.stop_epoch.wrapping_add(1),
        });
        if let Ok(mut state) = self.inner.state.lock() {
            state.desired_epoch = desired_epoch;
            state.desired_fingerprint = None;
            state.updated_at = Some(now_text());
        }
    }

    pub(in crate::daed_product) fn begin_stop(&self) -> Result<RuntimeStopPermit<'_>, String> {
        self.inner.coordinator.begin_stop()
    }

    pub(in crate::daed_product) fn summary(&self) -> Value {
        let mut summary = self.inner.coordinator.summary();
        let Ok(state) = self.inner.state.lock() else {
            summary["reconcileState"] = json!("error");
            summary["reconcileError"] = json!("runtime reconciler state lock poisoned");
            return summary;
        };
        let preparing = state
            .preparing
            .iter()
            .map(|(request_id, preparing)| {
                json!({
                    "request": request_id,
                    "source": preparing.source,
                    "phase": preparing.phase,
                    "desiredEpoch": preparing.desired_epoch,
                })
            })
            .collect::<Vec<_>>();
        if let Value::Object(map) = &mut summary {
            map.insert("desiredEpoch".to_owned(), json!(state.desired_epoch));
            map.insert(
                "desiredFingerprint".to_owned(),
                json!(state.desired_fingerprint),
            );
            map.insert("preparing".to_owned(), json!(preparing));
            map.insert("preparingCount".to_owned(), json!(state.preparing.len()));
            map.insert(
                "committingRequest".to_owned(),
                json!(state.committing_request),
            );
            map.insert("joinedCount".to_owned(), json!(state.joined_count));
            map.insert("coalescedCount".to_owned(), json!(state.coalesced_count));
            map.insert("supersededCount".to_owned(), json!(state.superseded_count));
            map.insert(
                "lastReconciledRequest".to_owned(),
                json!(state.last_completed_request),
            );
            map.insert("lastReconcileResult".to_owned(), json!(state.last_result));
            map.insert("reconcileUpdatedAt".to_owned(), json!(state.updated_at));
        }
        summary
    }
}

impl RuntimeReconcileRequest {
    pub(in crate::daed_product) fn set_phase(&self, phase: &'static str) {
        if let Ok(mut state) = self.reconciler.inner.state.lock()
            && let Some(preparing) = state.preparing.get_mut(&self.request_id)
        {
            preparing.phase = phase;
            state.updated_at = Some(now_text());
        }
    }

    pub(in crate::daed_product) fn admit(
        mut self,
        fingerprint: &ActiveRuntimeFingerprint,
    ) -> Result<RuntimeReconcileAdmission, String> {
        let fingerprint = fingerprint.as_str().to_owned();
        let mut flights = self
            .reconciler
            .inner
            .flights
            .lock()
            .map_err(|_| "runtime reconcile flight lock poisoned".to_owned())?;
        if let Some(flight) = flights.get(&fingerprint).and_then(Weak::upgrade)
            && flight
                .result
                .lock()
                .map_err(|_| "runtime reconcile result lock poisoned".to_owned())?
                .is_none()
        {
            self.admitted = true;
            if let Ok(mut state) = self.reconciler.inner.state.lock() {
                state.preparing.remove(&self.request_id);
                state.joined_count = state.joined_count.saturating_add(1);
                state.coalesced_count = state.coalesced_count.saturating_add(1);
                state.updated_at = Some(now_text());
            }
            return Ok(RuntimeReconcileAdmission::Follow(
                RuntimeReconcileFollower { flight },
            ));
        }

        let current = *self.reconciler.inner.desired.borrow();
        let desired_epoch = self
            .reconciler
            .inner
            .next_desired_epoch
            .fetch_add(1, Ordering::AcqRel);
        self.reconciler
            .inner
            .desired
            .send_replace(RuntimeDesiredSignal {
                epoch: desired_epoch,
                stop_epoch: current.stop_epoch,
            });
        let desired = self.reconciler.inner.desired.subscribe();
        let flight = Arc::new(RuntimeReconcileFlight {
            result: Mutex::new(None),
            completed: Condvar::new(),
        });
        flights.insert(fingerprint.clone(), Arc::downgrade(&flight));
        drop(flights);
        self.admitted = true;
        if let Ok(mut state) = self.reconciler.inner.state.lock() {
            if let Some(preparing) = state.preparing.get_mut(&self.request_id) {
                preparing.phase = "admitted";
                preparing.desired_epoch = Some(desired_epoch);
            }
            state.desired_epoch = desired_epoch;
            state.desired_fingerprint = Some(fingerprint.clone());
            state.updated_at = Some(now_text());
        }
        Ok(RuntimeReconcileAdmission::Lead(RuntimeReconcileLead {
            reconciler: self.reconciler.clone(),
            request_id: self.request_id,
            intent: self.intent,
            desired_epoch,
            accepted_stop_epoch: current.stop_epoch,
            fingerprint,
            desired,
            flight,
            finished: false,
        }))
    }
}

impl Drop for RuntimeReconcileRequest {
    fn drop(&mut self) {
        if self.admitted {
            return;
        }
        if let Ok(mut state) = self.reconciler.inner.state.lock() {
            state.preparing.remove(&self.request_id);
            state.last_completed_request = Some(self.request_id);
            state.last_result = Some("prepare-failed".to_owned());
            state.updated_at = Some(now_text());
        }
    }
}

impl RuntimeReconcileLead {
    pub(in crate::daed_product) fn checkpoint(
        &mut self,
        phase: &'static str,
    ) -> Result<(), CoordinatedRuntimeReloadError> {
        let signal = *self.desired.borrow_and_update();
        if signal.stop_epoch != self.accepted_stop_epoch {
            return Err(CoordinatedRuntimeReloadError::Apply(
                "runtime reload preparation was superseded by stop".to_owned(),
            ));
        }
        if signal.epoch != self.desired_epoch {
            return Err(CoordinatedRuntimeReloadError::Apply(
                "runtime reload preparation was superseded by newer desired state".to_owned(),
            ));
        }
        if let Ok(mut state) = self.reconciler.inner.state.lock()
            && let Some(preparing) = state.preparing.get_mut(&self.request_id)
        {
            preparing.phase = phase;
            state.updated_at = Some(now_text());
        }
        Ok(())
    }

    pub(in crate::daed_product) fn begin_commit(
        &mut self,
    ) -> Result<RuntimeApplyPermit<'_>, CoordinatedRuntimeReloadError> {
        let permit = self
            .reconciler
            .inner
            .coordinator
            .begin_apply(self.intent)
            .map_err(CoordinatedRuntimeReloadError::Apply)?;
        let signal = *self.desired.borrow_and_update();
        if signal.stop_epoch != self.accepted_stop_epoch {
            drop(permit);
            return Err(CoordinatedRuntimeReloadError::Apply(
                "runtime reload preparation was superseded by stop".to_owned(),
            ));
        }
        if signal.epoch != self.desired_epoch {
            drop(permit);
            return Err(CoordinatedRuntimeReloadError::Apply(
                "runtime reload preparation was superseded by newer desired state".to_owned(),
            ));
        }
        if let Ok(mut state) = self.reconciler.inner.state.lock() {
            state.committing_request = Some(self.request_id);
            if let Some(preparing) = state.preparing.get_mut(&self.request_id) {
                preparing.phase = "commit";
            }
            state.updated_at = Some(now_text());
        }
        Ok(permit)
    }

    pub(in crate::daed_product) fn finish(
        mut self,
        result: RuntimeReconcileResult,
    ) -> RuntimeReconcileResult {
        let output = result.clone();
        self.complete(result);
        output
    }

    fn complete(&mut self, result: RuntimeReconcileResult) {
        if self.finished {
            return;
        }
        if let Ok(mut flight_result) = self.flight.result.lock() {
            *flight_result = Some(result.clone());
            self.flight.completed.notify_all();
        }
        if let Ok(mut flights) = self.reconciler.inner.flights.lock()
            && flights
                .get(&self.fingerprint)
                .and_then(Weak::upgrade)
                .as_ref()
                .is_some_and(|flight| Arc::ptr_eq(flight, &self.flight))
        {
            flights.remove(&self.fingerprint);
        }
        if let Ok(mut state) = self.reconciler.inner.state.lock() {
            state.preparing.remove(&self.request_id);
            if state.committing_request == Some(self.request_id) {
                state.committing_request = None;
            }
            state.last_completed_request = Some(self.request_id);
            match &result {
                Ok(applied) => {
                    if applied.coalesced {
                        state.coalesced_count = state.coalesced_count.saturating_add(1);
                    }
                    state.last_result = Some(
                        if applied.coalesced {
                            "coalesced"
                        } else {
                            "succeeded"
                        }
                        .to_owned(),
                    );
                }
                Err(error) => {
                    if error.to_string().contains("superseded") {
                        state.superseded_count = state.superseded_count.saturating_add(1);
                        state.last_result = Some("superseded".to_owned());
                    } else {
                        state.last_result = Some("failed".to_owned());
                    }
                }
            }
            state.updated_at = Some(now_text());
        }
        self.finished = true;
    }
}

impl Drop for RuntimeReconcileLead {
    fn drop(&mut self) {
        if !self.finished {
            self.complete(Err(CoordinatedRuntimeReloadError::Apply(
                "runtime reconciliation owner was abandoned".to_owned(),
            )));
        }
    }
}

impl RuntimeReconcileFollower {
    pub(in crate::daed_product) fn wait(self) -> RuntimeReconcileResult {
        let mut result = self.flight.result.lock().map_err(|_| {
            CoordinatedRuntimeReloadError::Apply(
                "runtime reconcile result lock poisoned".to_owned(),
            )
        })?;
        while result.is_none() {
            result = self.flight.completed.wait(result).map_err(|_| {
                CoordinatedRuntimeReloadError::Apply(
                    "runtime reconcile result lock poisoned while waiting".to_owned(),
                )
            })?;
        }
        result
            .as_ref()
            .expect("runtime reconcile result is present after wait")
            .clone()
    }
}

#[cfg(test)]
#[path = "runtime_reconcile/tests.rs"]
mod tests;
