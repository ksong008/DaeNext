use serde_json::Value;

use crate::ProductRuntimeState;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProductRuntimeEventIdentity {
    running: bool,
    runtime_state: &'static str,
    reload_count: u64,
    stop_count: u64,
    active_generation: Option<String>,
    pending_process_transition: Option<Value>,
    apply_generation: Option<String>,
    apply_phase: Option<String>,
    apply_rollback_result: Option<String>,
    reconciliation_required: bool,
    coordinator_state: Option<String>,
    coordinator_active_intent: Option<u64>,
    coordinator_last_completed_intent: Option<u64>,
    coordinator_last_result: Option<String>,
}

impl ProductRuntimeEventIdentity {
    pub fn from_state<R>(state: &ProductRuntimeState<R>, coordinator: &Value) -> Self {
        let apply = state.apply.summary();
        let runtime_state = if state.runtime.is_some() {
            "running"
        } else if state.cleanup.running {
            "stopping"
        } else if state.last_error.is_some() {
            "error"
        } else {
            "stopped"
        };
        Self {
            running: state.runtime.is_some(),
            runtime_state,
            reload_count: state.reload_count,
            stop_count: state.stop_count,
            active_generation: state.active_generation.clone(),
            pending_process_transition: state.pending_process_transition.clone(),
            apply_generation: optional_string(&apply, "generationId"),
            apply_phase: optional_string(&apply, "phase"),
            apply_rollback_result: optional_string(&apply, "rollbackResult"),
            reconciliation_required: apply["reconciliationRequired"].as_bool().unwrap_or(false),
            coordinator_state: optional_string(coordinator, "state"),
            coordinator_active_intent: coordinator["activeIntent"].as_u64(),
            coordinator_last_completed_intent: coordinator["lastCompletedIntent"].as_u64(),
            coordinator_last_result: optional_string(coordinator, "lastResult"),
        }
    }

    pub fn lock_error(coordinator: &Value) -> Self {
        Self {
            running: false,
            runtime_state: "error",
            reload_count: 0,
            stop_count: 0,
            active_generation: None,
            pending_process_transition: None,
            apply_generation: None,
            apply_phase: None,
            apply_rollback_result: None,
            reconciliation_required: true,
            coordinator_state: optional_string(coordinator, "state"),
            coordinator_active_intent: coordinator["activeIntent"].as_u64(),
            coordinator_last_completed_intent: coordinator["lastCompletedIntent"].as_u64(),
            coordinator_last_result: optional_string(coordinator, "lastResult"),
        }
    }

    pub fn coordinator_last_result(&self) -> Option<&str> {
        self.coordinator_last_result.as_deref()
    }
}

fn optional_string(value: &Value, key: &str) -> Option<String> {
    value[key].as_str().map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{RuntimeApplyCoordinator, RuntimeApplyIntent};
    use serde_json::json;

    #[test]
    fn identity_tracks_runtime_and_coordinator_state() {
        let state = ProductRuntimeState::<u8>::default();
        let coordinator = RuntimeApplyCoordinator::new();
        let idle = ProductRuntimeEventIdentity::from_state(&state, &coordinator.summary());
        let permit = coordinator
            .begin_apply(RuntimeApplyIntent::ApiReload)
            .unwrap();
        let admitted = ProductRuntimeEventIdentity::from_state(&state, &coordinator.summary());
        assert_ne!(idle, admitted);
        permit.finish_coalesced();
        assert_eq!(
            ProductRuntimeEventIdentity::from_state(&state, &coordinator.summary())
                .coordinator_last_result(),
            Some("coalesced")
        );
    }

    #[test]
    fn identity_includes_pending_process_transition() {
        let mut state = ProductRuntimeState::<u8>::default();
        let coordinator = json!({"state": "idle"});
        let initial = ProductRuntimeEventIdentity::from_state(&state, &coordinator);
        state.pending_process_transition = Some(json!({"state": "pending-process-transition"}));
        assert_ne!(
            initial,
            ProductRuntimeEventIdentity::from_state(&state, &coordinator)
        );
    }
}
