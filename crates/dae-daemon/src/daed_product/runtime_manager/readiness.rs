use super::*;

impl ProductRuntimeManager {
    pub(in crate::daed_product) fn set_runtime_required_for_readiness(&self, required: bool) {
        self.runtime_required_for_readiness
            .store(required, Ordering::Release);
    }

    pub(in crate::daed_product) fn runtime_required_for_readiness(&self) -> bool {
        self.runtime_required_for_readiness.load(Ordering::Acquire)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_readiness_requirement_is_explicit_and_reversible() {
        let runtime = ProductRuntimeManager::new();
        assert!(!runtime.runtime_required_for_readiness());

        runtime.set_runtime_required_for_readiness(true);
        assert!(runtime.runtime_required_for_readiness());

        runtime.set_runtime_required_for_readiness(false);
        assert!(!runtime.runtime_required_for_readiness());
    }
}
