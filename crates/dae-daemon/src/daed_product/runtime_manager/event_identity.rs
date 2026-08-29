use super::*;

pub(in crate::daed_product) use dae_product_runtime::ProductRuntimeEventIdentity;

impl ProductRuntimeManager {
    pub(in crate::daed_product) fn runtime_event_identity(&self) -> ProductRuntimeEventIdentity {
        let coordinator = self.reconciler().summary();
        let Ok(inner) = self.inner().lock() else {
            return ProductRuntimeEventIdentity::lock_error(&coordinator);
        };
        ProductRuntimeEventIdentity::from_state(&inner, &coordinator)
    }
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
        assert_eq!(coalesced.coordinator_last_result(), Some("coalesced"));
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
