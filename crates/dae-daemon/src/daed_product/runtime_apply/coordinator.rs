use super::*;
use std::sync::{MutexGuard, TryLockError};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::daed_product) enum RuntimeApplyIntent {
    ApiReload,
    LocalControlReload,
    SubscriptionRefresh,
    StartupRestore,
    InterfaceRecovery,
}

impl RuntimeApplyIntent {
    pub(in crate::daed_product) fn source(self) -> &'static str {
        match self {
            Self::ApiReload => "api-runtime-reload",
            Self::LocalControlReload => "local-control",
            Self::SubscriptionRefresh => "subscription-refresh",
            Self::StartupRestore => "startup-restore",
            Self::InterfaceRecovery => "interface-monitor",
        }
    }

    pub(in crate::daed_product) fn requires_runtime_change(self) -> bool {
        matches!(self, Self::SubscriptionRefresh)
    }
}

#[derive(Clone, Debug)]
pub(in crate::daed_product) struct RuntimeApplyCoordinator {
    gate: Arc<Mutex<()>>,
    next_intent: Arc<AtomicU64>,
    stop_epoch: Arc<AtomicU64>,
    state: Arc<Mutex<RuntimeApplyCoordinatorState>>,
}

#[derive(Clone, Debug, Default)]
struct RuntimeApplyCoordinatorState {
    active_intent: Option<u64>,
    active_source: Option<String>,
    phase: String,
    last_completed_intent: Option<u64>,
    last_result: Option<String>,
    coalesced_count: u64,
    superseded_count: u64,
    updated_at: Option<String>,
}

pub(in crate::daed_product) struct RuntimeApplyPermit<'a> {
    coordinator: &'a RuntimeApplyCoordinator,
    _gate: MutexGuard<'a, ()>,
    intent_id: u64,
    intent: RuntimeApplyIntent,
    waited: bool,
    finished: bool,
}

pub(in crate::daed_product) struct RuntimeStopPermit<'a> {
    coordinator: &'a RuntimeApplyCoordinator,
    _gate: MutexGuard<'a, ()>,
    intent_id: u64,
    finished: bool,
}

impl RuntimeApplyCoordinator {
    pub(in crate::daed_product) fn new() -> Self {
        Self {
            gate: Arc::new(Mutex::new(())),
            next_intent: Arc::new(AtomicU64::new(1)),
            stop_epoch: Arc::new(AtomicU64::new(0)),
            state: Arc::new(Mutex::new(RuntimeApplyCoordinatorState {
                phase: "idle".to_owned(),
                ..RuntimeApplyCoordinatorState::default()
            })),
        }
    }

    pub(in crate::daed_product) fn begin_apply(
        &self,
        intent: RuntimeApplyIntent,
    ) -> Result<RuntimeApplyPermit<'_>, String> {
        let intent_id = self.next_intent.fetch_add(1, Ordering::Relaxed);
        let accepted_stop_epoch = self.stop_epoch.load(Ordering::Acquire);
        let (gate, waited) = match self.gate.try_lock() {
            Ok(gate) => (gate, false),
            Err(TryLockError::WouldBlock) => (
                self.gate
                    .lock()
                    .map_err(|_| "runtime apply coordinator lock poisoned".to_owned())?,
                true,
            ),
            Err(TryLockError::Poisoned(_)) => {
                return Err("runtime apply coordinator lock poisoned".to_owned());
            }
        };
        if self.stop_epoch.load(Ordering::Acquire) != accepted_stop_epoch {
            if let Ok(mut state) = self.state.lock() {
                state.superseded_count = state.superseded_count.saturating_add(1);
                state.last_completed_intent = Some(intent_id);
                state.last_result = Some("superseded-by-stop".to_owned());
                state.updated_at = Some(now_text());
            }
            drop(gate);
            return Err("runtime apply intent was superseded by stop".to_owned());
        }
        if let Ok(mut state) = self.state.lock() {
            state.active_intent = Some(intent_id);
            state.active_source = Some(intent.source().to_owned());
            state.phase = "accepted".to_owned();
            state.updated_at = Some(now_text());
        }
        Ok(RuntimeApplyPermit {
            coordinator: self,
            _gate: gate,
            intent_id,
            intent,
            waited,
            finished: false,
        })
    }

    pub(in crate::daed_product) fn begin_stop(&self) -> Result<RuntimeStopPermit<'_>, String> {
        let intent_id = self.next_intent.fetch_add(1, Ordering::Relaxed);
        self.stop_epoch.fetch_add(1, Ordering::AcqRel);
        let gate = self
            .gate
            .lock()
            .map_err(|_| "runtime apply coordinator lock poisoned".to_owned())?;
        if let Ok(mut state) = self.state.lock() {
            state.active_intent = Some(intent_id);
            state.active_source = Some("stop".to_owned());
            state.phase = "stopping".to_owned();
            state.updated_at = Some(now_text());
        }
        Ok(RuntimeStopPermit {
            coordinator: self,
            _gate: gate,
            intent_id,
            finished: false,
        })
    }

    pub(in crate::daed_product) fn summary(&self) -> Value {
        let Ok(state) = self.state.lock() else {
            return json!({"state": "error", "error": "runtime apply coordinator state lock poisoned"});
        };
        json!({
            "state": state.phase,
            "activeIntent": state.active_intent,
            "activeSource": state.active_source,
            "lastCompletedIntent": state.last_completed_intent,
            "lastResult": state.last_result,
            "coalescedCount": state.coalesced_count,
            "supersededCount": state.superseded_count,
            "updatedAt": state.updated_at,
        })
    }
}

impl RuntimeApplyPermit<'_> {
    pub(in crate::daed_product) fn intent(&self) -> RuntimeApplyIntent {
        self.intent
    }

    pub(in crate::daed_product) fn waited(&self) -> bool {
        self.waited
    }

    pub(in crate::daed_product) fn set_phase(&self, phase: &str) {
        if let Ok(mut state) = self.coordinator.state.lock()
            && state.active_intent == Some(self.intent_id)
        {
            state.phase = phase.to_owned();
            state.updated_at = Some(now_text());
        }
    }

    pub(in crate::daed_product) fn finish(mut self, result: &str) {
        self.record_finish(result);
        self.finished = true;
    }

    pub(in crate::daed_product) fn finish_coalesced(mut self) {
        if let Ok(mut state) = self.coordinator.state.lock() {
            state.coalesced_count = state.coalesced_count.saturating_add(1);
        }
        self.record_finish("coalesced");
        self.finished = true;
    }

    fn record_finish(&self, result: &str) {
        if let Ok(mut state) = self.coordinator.state.lock()
            && state.active_intent == Some(self.intent_id)
        {
            state.active_intent = None;
            state.active_source = None;
            state.phase = "idle".to_owned();
            state.last_completed_intent = Some(self.intent_id);
            state.last_result = Some(result.to_owned());
            state.updated_at = Some(now_text());
        }
    }
}

impl Drop for RuntimeApplyPermit<'_> {
    fn drop(&mut self) {
        if !self.finished {
            self.record_finish("abandoned");
        }
    }
}

impl RuntimeStopPermit<'_> {
    pub(in crate::daed_product) fn finish(mut self, result: &str) {
        self.record_finish(result);
        self.finished = true;
    }

    fn record_finish(&self, result: &str) {
        if let Ok(mut state) = self.coordinator.state.lock()
            && state.active_intent == Some(self.intent_id)
        {
            state.active_intent = None;
            state.active_source = None;
            state.phase = "idle".to_owned();
            state.last_completed_intent = Some(self.intent_id);
            state.last_result = Some(result.to_owned());
            state.updated_at = Some(now_text());
        }
    }
}

impl Drop for RuntimeStopPermit<'_> {
    fn drop(&mut self) {
        if !self.finished {
            self.record_finish("abandoned");
        }
    }
}

#[cfg(test)]
#[path = "coordinator/tests.rs"]
mod tests;
