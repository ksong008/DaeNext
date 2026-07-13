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
        let active = self.process_http_config.lock().ok()?.as_ref().copied()?;
        (active != desired).then(|| active.transition_json(desired))
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
