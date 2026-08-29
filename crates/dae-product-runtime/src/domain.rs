use std::sync::{Arc, Mutex};

use crate::{ProductRuntimeReconciler, ProductRuntimeState, RuntimeApplyCoordinator};

#[derive(Debug)]
pub struct ProductRuntimeDomain<R, T, E> {
    reconciler: ProductRuntimeReconciler<T, E>,
    lifecycle: Arc<Mutex<()>>,
    state: Arc<Mutex<ProductRuntimeState<R>>>,
}

impl<R, T, E> ProductRuntimeDomain<R, T, E>
where
    T: Clone + Send + Sync + 'static,
    E: Clone + Send + Sync + std::fmt::Display + From<String> + 'static,
{
    pub fn new(coordinator: RuntimeApplyCoordinator) -> Self {
        Self {
            reconciler: ProductRuntimeReconciler::new(coordinator),
            lifecycle: Arc::new(Mutex::new(())),
            state: Arc::new(Mutex::new(ProductRuntimeState::default())),
        }
    }

    pub fn reconciler(&self) -> &ProductRuntimeReconciler<T, E> {
        &self.reconciler
    }

    pub fn lifecycle(&self) -> &Arc<Mutex<()>> {
        &self.lifecycle
    }

    pub fn state(&self) -> &Arc<Mutex<ProductRuntimeState<R>>> {
        &self.state
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_keeps_one_shared_state_and_reconciler() {
        let domain = ProductRuntimeDomain::<u8, u64, String>::new(RuntimeApplyCoordinator::new());
        let state = domain.state().clone();
        let lifecycle = domain.lifecycle().clone();
        assert!(state.lock().unwrap().runtime.is_none());
        assert!(lifecycle.try_lock().is_ok());
        assert!(domain.reconciler().summary().is_object());
    }
}
