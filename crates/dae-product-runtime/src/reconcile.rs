use std::collections::BTreeMap;
use std::fmt::Display;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, Weak};

use dae_product_core::product_now_text;

use crate::{RuntimeApplyCoordinator, RuntimeApplyIntent, RuntimeApplyPermit, RuntimeStopPermit};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct RuntimeDesiredSignal {
    epoch: u64,
    stop_epoch: u64,
    latest_request: u64,
}

pub struct ProductRuntimeReconciler<T, E> {
    inner: Arc<ProductRuntimeReconcilerInner<T, E>>,
}

struct ProductRuntimeReconcilerInner<T, E> {
    coordinator: RuntimeApplyCoordinator,
    next_request: AtomicU64,
    desired: tokio::sync::watch::Sender<RuntimeDesiredSignal>,
    flight: Mutex<Option<RuntimeReconcileAdmissionState<T, E>>>,
    state: Mutex<RuntimeReconcileState>,
}

impl<T, E> std::fmt::Debug for ProductRuntimeReconciler<T, E> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProductRuntimeReconciler")
            .field("state", &self.inner.state)
            .finish_non_exhaustive()
    }
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

struct ProductRuntimeReconcileFlight<T, E> {
    result: Mutex<Option<Result<T, E>>>,
    completed: Condvar,
    abandoned: std::sync::atomic::AtomicBool,
}

struct RuntimeReconcileAdmissionState<T, E> {
    fingerprint: String,
    flight: Weak<ProductRuntimeReconcileFlight<T, E>>,
}

pub struct ProductRuntimeReconcileRequest<T, E> {
    reconciler: ProductRuntimeReconciler<T, E>,
    request_id: u64,
    accepted_stop_epoch: u64,
    started_during_stop: bool,
    intent: RuntimeApplyIntent,
    admitted: bool,
}

pub enum ProductRuntimeReconcileAdmission<T, E> {
    Lead(ProductRuntimeReconcileLead<T, E>),
    Follow(ProductRuntimeReconcileFollower<T, E>),
}

pub struct ProductRuntimeReconcileLead<T, E> {
    reconciler: ProductRuntimeReconciler<T, E>,
    request_id: u64,
    intent: RuntimeApplyIntent,
    desired_epoch: u64,
    accepted_stop_epoch: u64,
    desired: tokio::sync::watch::Receiver<RuntimeDesiredSignal>,
    flight: Arc<ProductRuntimeReconcileFlight<T, E>>,
    finished: bool,
}

pub struct ProductRuntimeReconcileFollower<T, E> {
    flight: Arc<ProductRuntimeReconcileFlight<T, E>>,
}

impl<T, E> Clone for ProductRuntimeReconciler<T, E> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<T, E> ProductRuntimeReconciler<T, E>
where
    T: Clone + Send + Sync + 'static,
    E: Clone + Send + Sync + Display + From<String> + 'static,
{
    pub fn new(coordinator: RuntimeApplyCoordinator) -> Self {
        let (desired, _) = tokio::sync::watch::channel(RuntimeDesiredSignal::default());
        Self {
            inner: Arc::new(ProductRuntimeReconcilerInner {
                coordinator,
                next_request: AtomicU64::new(1),
                desired,
                flight: Mutex::new(None),
                state: Mutex::new(RuntimeReconcileState::default()),
            }),
        }
    }

    pub fn begin(&self, intent: RuntimeApplyIntent) -> ProductRuntimeReconcileRequest<T, E> {
        let accepted_stop_epoch = self.inner.desired.borrow().stop_epoch;
        let started_during_stop = self.inner.coordinator.stop_is_pending();
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
            state.updated_at = Some(product_now_text());
        }
        ProductRuntimeReconcileRequest {
            reconciler: self.clone(),
            request_id,
            accepted_stop_epoch,
            started_during_stop,
            intent,
            admitted: false,
        }
    }

    pub fn begin_exclusive(
        &self,
        intent: RuntimeApplyIntent,
    ) -> Result<RuntimeApplyPermit<'_>, String> {
        self.inner.coordinator.begin_apply(intent)
    }

    pub fn cancel_preparation_for_stop(&self) {
        let mut flight = self
            .inner
            .flight
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *flight = None;
        let desired_epoch = self.inner.next_request.fetch_add(1, Ordering::Relaxed);
        self.inner.desired.send_modify(|signal| {
            signal.epoch = desired_epoch;
            signal.stop_epoch = signal.stop_epoch.wrapping_add(1);
        });
        if let Ok(mut state) = self.inner.state.lock() {
            state.desired_epoch = desired_epoch;
            state.desired_fingerprint = None;
            state.updated_at = Some(product_now_text());
        }
    }

    pub fn begin_stop(&self) -> Result<RuntimeStopPermit<'_>, String> {
        self.inner
            .coordinator
            .begin_stop_with(|| self.cancel_preparation_for_stop())
    }

    pub fn summary(&self) -> serde_json::Value {
        let mut summary = self.inner.coordinator.summary();
        let Ok(state) = self.inner.state.lock() else {
            summary["reconcileState"] = serde_json::json!("error");
            summary["reconcileError"] = serde_json::json!("runtime reconciler state lock poisoned");
            return summary;
        };
        let preparing = state
            .preparing
            .iter()
            .map(|(request_id, preparing)| {
                serde_json::json!({
                    "request": request_id,
                    "source": preparing.source,
                    "phase": preparing.phase,
                    "desiredEpoch": preparing.desired_epoch,
                })
            })
            .collect::<Vec<_>>();
        if let serde_json::Value::Object(map) = &mut summary {
            map.insert(
                "desiredEpoch".to_owned(),
                serde_json::json!(state.desired_epoch),
            );
            map.insert(
                "desiredFingerprint".to_owned(),
                serde_json::json!(state.desired_fingerprint),
            );
            map.insert("preparing".to_owned(), serde_json::json!(preparing));
            map.insert(
                "preparingCount".to_owned(),
                serde_json::json!(state.preparing.len()),
            );
            map.insert(
                "committingRequest".to_owned(),
                serde_json::json!(state.committing_request),
            );
            map.insert(
                "joinedCount".to_owned(),
                serde_json::json!(state.joined_count),
            );
            map.insert(
                "coalescedCount".to_owned(),
                serde_json::json!(state.coalesced_count),
            );
            map.insert(
                "supersededCount".to_owned(),
                serde_json::json!(state.superseded_count),
            );
            map.insert(
                "lastReconciledRequest".to_owned(),
                serde_json::json!(state.last_completed_request),
            );
            map.insert(
                "lastReconcileResult".to_owned(),
                serde_json::json!(state.last_result),
            );
            map.insert(
                "reconcileUpdatedAt".to_owned(),
                serde_json::json!(state.updated_at),
            );
        }
        summary
    }
}

impl<T, E> ProductRuntimeReconcileRequest<T, E>
where
    T: Clone + Send + Sync + 'static,
    E: Clone + Send + Sync + Display + From<String> + 'static,
{
    pub fn set_phase(&self, phase: &'static str) {
        if let Ok(mut state) = self.reconciler.inner.state.lock()
            && let Some(preparing) = state.preparing.get_mut(&self.request_id)
        {
            preparing.phase = phase;
            state.updated_at = Some(product_now_text());
        }
    }

    pub fn admit(
        mut self,
        fingerprint: &str,
    ) -> Result<ProductRuntimeReconcileAdmission<T, E>, String> {
        let mut active_flight = self
            .reconciler
            .inner
            .flight
            .lock()
            .map_err(|_| "runtime reconcile flight lock poisoned".to_owned())?;
        let current = *self.reconciler.inner.desired.borrow();
        let rejection = if self.started_during_stop
            || self.reconciler.inner.coordinator.stop_is_pending()
            || current.stop_epoch != self.accepted_stop_epoch
        {
            Some("runtime reload preparation was superseded by stop")
        } else if self.request_id < current.latest_request {
            Some("runtime reload preparation was superseded by newer desired state")
        } else {
            None
        };
        if let Some(error) = rejection {
            self.admitted = true;
            if let Ok(mut state) = self.reconciler.inner.state.lock() {
                state.preparing.remove(&self.request_id);
                state.superseded_count = state.superseded_count.saturating_add(1);
                state.last_completed_request = Some(self.request_id);
                state.last_result = Some("superseded".to_owned());
                state.updated_at = Some(product_now_text());
            }
            return Err(error.to_owned());
        }
        if let Some(flight) = active_flight
            .as_ref()
            .filter(|entry| entry.fingerprint == fingerprint)
            .and_then(|entry| entry.flight.upgrade())
            && !flight.abandoned.load(Ordering::Acquire)
            && flight
                .result
                .lock()
                .map_err(|_| "runtime reconcile result lock poisoned".to_owned())?
                .is_none()
        {
            self.reconciler.inner.desired.send_modify(|signal| {
                signal.latest_request = self.request_id;
            });
            self.admitted = true;
            if let Ok(mut state) = self.reconciler.inner.state.lock() {
                state.preparing.remove(&self.request_id);
                state.joined_count = state.joined_count.saturating_add(1);
                state.coalesced_count = state.coalesced_count.saturating_add(1);
                state.updated_at = Some(product_now_text());
            }
            return Ok(ProductRuntimeReconcileAdmission::Follow(
                ProductRuntimeReconcileFollower { flight },
            ));
        }

        let desired_epoch = self.request_id;
        self.reconciler
            .inner
            .desired
            .send_replace(RuntimeDesiredSignal {
                epoch: desired_epoch,
                stop_epoch: current.stop_epoch,
                latest_request: self.request_id,
            });
        let desired = self.reconciler.inner.desired.subscribe();
        let flight = Arc::new(ProductRuntimeReconcileFlight {
            result: Mutex::new(None),
            completed: Condvar::new(),
            abandoned: std::sync::atomic::AtomicBool::new(false),
        });
        *active_flight = Some(RuntimeReconcileAdmissionState {
            fingerprint: fingerprint.to_owned(),
            flight: Arc::downgrade(&flight),
        });
        self.admitted = true;
        if let Ok(mut state) = self.reconciler.inner.state.lock() {
            if let Some(preparing) = state.preparing.get_mut(&self.request_id) {
                preparing.phase = "admitted";
                preparing.desired_epoch = Some(desired_epoch);
            }
            state.desired_epoch = desired_epoch;
            state.desired_fingerprint = Some(fingerprint.to_owned());
            state.updated_at = Some(product_now_text());
        }
        Ok(ProductRuntimeReconcileAdmission::Lead(
            ProductRuntimeReconcileLead {
                reconciler: self.reconciler.clone(),
                request_id: self.request_id,
                intent: self.intent,
                desired_epoch,
                accepted_stop_epoch: current.stop_epoch,
                desired,
                flight,
                finished: false,
            },
        ))
    }
}

impl<T, E> Drop for ProductRuntimeReconcileRequest<T, E> {
    fn drop(&mut self) {
        if self.admitted {
            return;
        }
        if let Ok(mut state) = self.reconciler.inner.state.lock() {
            state.preparing.remove(&self.request_id);
            state.last_completed_request = Some(self.request_id);
            state.last_result = Some("prepare-failed".to_owned());
            state.updated_at = Some(product_now_text());
        }
    }
}

impl<T, E> ProductRuntimeReconcileLead<T, E>
where
    T: Clone + Send + Sync + 'static,
    E: Clone + Send + Sync + Display + From<String> + 'static,
{
    pub fn checkpoint(&mut self, phase: &'static str) -> Result<(), E> {
        let signal = *self.desired.borrow_and_update();
        if signal.stop_epoch != self.accepted_stop_epoch {
            return Err(E::from(
                "runtime reload preparation was superseded by stop".to_owned(),
            ));
        }
        if signal.epoch != self.desired_epoch {
            return Err(E::from(
                "runtime reload preparation was superseded by newer desired state".to_owned(),
            ));
        }
        if let Ok(mut state) = self.reconciler.inner.state.lock()
            && let Some(preparing) = state.preparing.get_mut(&self.request_id)
        {
            preparing.phase = phase;
            state.updated_at = Some(product_now_text());
        }
        Ok(())
    }

    pub fn is_superseded(&self) -> bool {
        let signal = *self.desired.borrow();
        signal.stop_epoch != self.accepted_stop_epoch || signal.epoch != self.desired_epoch
    }

    pub fn begin_commit(&mut self) -> Result<RuntimeApplyPermit<'_>, E> {
        self.begin_commit_until(|| false)
    }

    pub fn begin_commit_until(
        &mut self,
        cancelled: impl Fn() -> bool,
    ) -> Result<RuntimeApplyPermit<'_>, E> {
        let permit = self
            .reconciler
            .inner
            .coordinator
            .begin_apply_until(self.intent, || {
                let signal = *self.desired.borrow();
                if signal.stop_epoch != self.accepted_stop_epoch {
                    Some("runtime reload preparation was superseded by stop")
                } else if signal.epoch != self.desired_epoch {
                    Some("runtime reload preparation was superseded by newer desired state")
                } else if cancelled() {
                    Some("runtime reload request cancelled before commit")
                } else {
                    None
                }
            })?;
        let signal = *self.desired.borrow_and_update();
        if signal.stop_epoch != self.accepted_stop_epoch {
            drop(permit);
            return Err(E::from(
                "runtime reload preparation was superseded by stop".to_owned(),
            ));
        }
        if signal.epoch != self.desired_epoch {
            drop(permit);
            return Err(E::from(
                "runtime reload preparation was superseded by newer desired state".to_owned(),
            ));
        }
        if let Ok(mut state) = self.reconciler.inner.state.lock() {
            state.committing_request = Some(self.request_id);
            if let Some(preparing) = state.preparing.get_mut(&self.request_id) {
                preparing.phase = "commit";
            }
            state.updated_at = Some(product_now_text());
        }
        Ok(permit)
    }

    pub fn finish(self, result: Result<T, E>) -> Result<T, E> {
        self.finish_with_coalesced(result, false)
    }

    pub fn finish_with_coalesced(mut self, result: Result<T, E>, coalesced: bool) -> Result<T, E> {
        let output = result.clone();
        self.complete(result, coalesced);
        output
    }

    fn complete(&mut self, result: Result<T, E>, coalesced: bool) {
        if self.finished {
            return;
        }
        if let Ok(mut flight_result) = self.flight.result.lock() {
            *flight_result = Some(result.clone());
            self.flight.completed.notify_all();
        }
        if let Ok(mut active_flight) = self.reconciler.inner.flight.lock()
            && active_flight
                .as_ref()
                .and_then(|entry| entry.flight.upgrade())
                .as_ref()
                .is_some_and(|flight| Arc::ptr_eq(flight, &self.flight))
        {
            *active_flight = None;
        }
        if let Ok(mut state) = self.reconciler.inner.state.lock() {
            state.preparing.remove(&self.request_id);
            if state.committing_request == Some(self.request_id) {
                state.committing_request = None;
            }
            state.last_completed_request = Some(self.request_id);
            if coalesced {
                state.coalesced_count = state.coalesced_count.saturating_add(1);
            }
            state.last_result = Some(match &result {
                Ok(_) if coalesced => "coalesced".to_owned(),
                Ok(_) => "succeeded".to_owned(),
                Err(error) if error.to_string().contains("superseded") => {
                    state.superseded_count = state.superseded_count.saturating_add(1);
                    "superseded".to_owned()
                }
                Err(_) => "failed".to_owned(),
            });
            state.updated_at = Some(product_now_text());
        }
        self.finished = true;
    }
}

impl<T, E> Drop for ProductRuntimeReconcileLead<T, E> {
    fn drop(&mut self) {
        if !self.finished {
            if let Ok(result) = self.flight.result.lock()
                && result.is_none()
            {
                self.flight.abandoned.store(true, Ordering::Release);
                self.flight.completed.notify_all();
            }
            if let Ok(mut state) = self.reconciler.inner.state.lock() {
                state.preparing.remove(&self.request_id);
                if state.committing_request == Some(self.request_id) {
                    state.committing_request = None;
                }
                state.last_completed_request = Some(self.request_id);
                state.last_result = Some("abandoned".to_owned());
                state.updated_at = Some(product_now_text());
            }
        }
    }
}

impl<T, E> ProductRuntimeReconcileFollower<T, E>
where
    T: Clone + Send + Sync + 'static,
    E: Clone + Send + Sync + Display + From<String> + 'static,
{
    pub fn wait(self) -> Result<T, E> {
        self.wait_until(|| false)
    }

    pub fn wait_until(self, cancelled: impl Fn() -> bool) -> Result<T, E> {
        let mut result = self
            .flight
            .result
            .lock()
            .map_err(|_| E::from("runtime reconcile result lock poisoned".to_owned()))?;
        while result.is_none() && !self.flight.abandoned.load(Ordering::Acquire) {
            if cancelled() {
                return Err(E::from(
                    "runtime reload request cancelled before commit".to_owned(),
                ));
            }
            (result, _) = self
                .flight
                .completed
                .wait_timeout(result, std::time::Duration::from_millis(100))
                .map_err(|_| {
                    E::from("runtime reconcile result lock poisoned while waiting".to_owned())
                })?;
        }
        result.clone().ok_or_else(|| {
            E::from(
                if self.flight.abandoned.load(Ordering::Acquire) {
                    "runtime reconciliation owner was abandoned"
                } else {
                    "runtime reconcile result disappeared after wait"
                }
                .to_owned(),
            )
        })?
    }
}
