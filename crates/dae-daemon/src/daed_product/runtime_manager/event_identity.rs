use super::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::daed_product) struct ProductRuntimeEventIdentity {
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

impl ProductRuntimeManager {
    pub(in crate::daed_product) fn runtime_event_identity(&self) -> ProductRuntimeEventIdentity {
        let coordinator = self.reconciler().summary();
        let Ok(inner) = self.inner().lock() else {
            return ProductRuntimeEventIdentity::lock_error(&coordinator);
        };
        let apply = inner.apply.summary();
        let runtime_state = if inner.runtime.is_some() {
            "running"
        } else if inner.cleanup.running {
            "stopping"
        } else if inner.last_error.is_some() {
            "error"
        } else {
            "stopped"
        };
        ProductRuntimeEventIdentity {
            running: inner.runtime.is_some(),
            runtime_state,
            reload_count: inner.reload_count,
            stop_count: inner.stop_count,
            active_generation: inner.active_generation.clone(),
            pending_process_transition: inner.pending_process_transition.clone(),
            apply_generation: optional_string(&apply, "generationId"),
            apply_phase: optional_string(&apply, "phase"),
            apply_rollback_result: optional_string(&apply, "rollbackResult"),
            reconciliation_required: apply["reconciliationRequired"].as_bool().unwrap_or(false),
            coordinator_state: optional_string(&coordinator, "state"),
            coordinator_active_intent: coordinator["activeIntent"].as_u64(),
            coordinator_last_completed_intent: coordinator["lastCompletedIntent"].as_u64(),
            coordinator_last_result: optional_string(&coordinator, "lastResult"),
        }
    }
}

impl ProductRuntimeEventIdentity {
    fn lock_error(coordinator: &Value) -> Self {
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
}

fn optional_string(value: &Value, key: &str) -> Option<String> {
    value[key].as_str().map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_identity_changes_for_apply_phases_and_terminal_outcomes() {
        let runtime = ProductRuntimeManager::new();
        let idle = runtime.runtime_event_identity();
        let permit = runtime
            .begin_apply(RuntimeApplyIntent::ApiReload)
            .expect("begin apply");
        let admitted = runtime.runtime_event_identity();
        assert_ne!(admitted, idle);

        permit.set_phase("preflight");
        let preflight = runtime.runtime_event_identity();
        assert_ne!(preflight, admitted);

        permit.finish_coalesced();
        let coalesced = runtime.runtime_event_identity();
        assert_ne!(coalesced, preflight);
        assert_eq!(
            coalesced.coordinator_last_result.as_deref(),
            Some("coalesced")
        );
    }

    #[test]
    fn event_identity_changes_when_a_process_transition_is_published() {
        let runtime = ProductRuntimeManager::new();
        let initial = runtime.runtime_event_identity();
        runtime.publish_process_transition(Some(json!({
            "state": "pending-process-transition",
            "active": {"workers": 1},
            "desired": {"workers": 2},
        })));
        assert_ne!(runtime.runtime_event_identity(), initial);
    }
}
