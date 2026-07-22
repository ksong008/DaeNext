use super::*;

impl ProductRuntimeManager {
    pub(in crate::daed_product) fn set_process_http_config(&self, config: ProductHttpWorkerConfig) {
        if let Ok(mut active) = self.process_http_config.lock() {
            *active = Some(config);
        }
    }

    pub(in crate::daed_product) fn process_transition_for_config(
        &self,
        config: &Config,
    ) -> Option<Value> {
        let desired = ProductHttpWorkerConfig::from_config(Some(config));
        let http_transition = self
            .process_http_config
            .lock()
            .ok()?
            .as_ref()
            .copied()
            .filter(|active| *active != desired)
            .map(|active| active.transition_json(desired));
        let changed_fields = self
            .inner
            .lock()
            .ok()?
            .process_baseline_config
            .as_deref()
            .map(|active| process_owned_field_changes(active, config))
            .unwrap_or_default();
        let non_http_fields = changed_fields
            .iter()
            .copied()
            .filter(|field| {
                !matches!(
                    *field,
                    "http_queue" | "http_workers" | "http_worker_stack_bytes"
                )
            })
            .collect::<Vec<_>>();
        if non_http_fields.is_empty() {
            return http_transition;
        }
        Some(json!({
            "state": "pending-process-transition",
            "owner": "process-runtime-policy",
            "changedFields": changed_fields,
            "httpRuntime": http_transition,
        }))
    }

    pub(in crate::daed_product) fn publish_process_transition(&self, transition: Option<Value>) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.pending_process_transition = transition;
        }
    }

    pub(in crate::daed_product) fn pending_process_transition(&self) -> Option<Value> {
        self.inner
            .lock()
            .ok()
            .and_then(|inner| inner.pending_process_transition.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> Config {
        Config {
            global: Default::default(),
            subscription: Vec::new(),
            node: Vec::new(),
            group: Vec::new(),
            routing: Default::default(),
            dns: Default::default(),
        }
    }

    #[test]
    fn pending_process_policy_is_compared_with_the_process_baseline() {
        let runtime = ProductRuntimeManager::new();
        let active = Arc::new(test_config());
        runtime.set_process_http_config(ProductHttpWorkerConfig::from_config(Some(&active)));
        runtime.inner.lock().unwrap().process_baseline_config = Some(Arc::clone(&active));

        let mut desired = active.as_ref().clone();
        desired.global.resident_tcp_runtime_workers = Some(3);
        let pending = runtime.process_transition_for_config(&desired).unwrap();
        assert_eq!(pending["state"], json!("pending-process-transition"));
        assert_eq!(
            pending["changedFields"],
            json!(["resident_tcp_runtime_workers"])
        );

        runtime.inner.lock().unwrap().config = Some(Arc::new(desired.clone()));
        assert!(runtime.process_transition_for_config(&desired).is_some());
        assert!(runtime.process_transition_for_config(&active).is_none());
    }
}
