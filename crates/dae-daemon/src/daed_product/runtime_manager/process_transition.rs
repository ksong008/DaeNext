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
        let active_http = self.process_http_config.lock().ok()?.as_ref().copied();
        let active_process_config = self.inner().lock().ok()?.process_baseline_config.clone();
        dae_product_control::runtime::process_transition_for_config(
            active_http,
            active_process_config.as_deref(),
            config,
        )
    }

    pub(in crate::daed_product) fn publish_process_transition(&self, transition: Option<Value>) {
        if let Ok(mut inner) = self.inner().lock() {
            inner.pending_process_transition = transition;
        }
    }

    pub(in crate::daed_product) fn pending_process_transition(&self) -> Option<Value> {
        self.inner()
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
        runtime.inner().lock().unwrap().process_baseline_config = Some(Arc::clone(&active));

        let mut desired = active.as_ref().clone();
        desired.global.resident_tcp_runtime_workers = Some(3);
        let pending = runtime.process_transition_for_config(&desired).unwrap();
        assert_eq!(pending["state"], json!("pending-process-transition"));
        assert_eq!(
            pending["changedFields"],
            json!(["resident_tcp_runtime_workers"])
        );

        runtime.inner().lock().unwrap().config = Some(Arc::new(desired.clone()));
        assert!(runtime.process_transition_for_config(&desired).is_some());
        assert!(runtime.process_transition_for_config(&active).is_none());
    }

    #[test]
    fn reload_owned_pprof_and_network_gate_do_not_report_pending_restart() {
        let runtime = ProductRuntimeManager::new();
        let active = Arc::new(test_config());
        runtime.set_process_http_config(ProductHttpWorkerConfig::from_config(Some(&active)));
        runtime.inner().lock().unwrap().process_baseline_config = Some(Arc::clone(&active));

        let mut desired = active.as_ref().clone();
        desired.global.pprof_port = 6060;
        desired.global.disable_waiting_network = true;
        assert!(runtime.process_transition_for_config(&desired).is_none());
    }
}
