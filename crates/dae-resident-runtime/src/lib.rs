use std::convert::Infallible;
use std::fmt;
use std::sync::Arc;

use dae_resident_core::{ActiveGenerationSlot, GenerationGate, GenerationToken, PublicationEpoch};

mod executor;
mod task;

pub use executor::{
    ResidentRuntimeAllocatorHooks, ResidentRuntimeExecutor, ResidentRuntimeExecutorConfig,
};
pub use task::{
    ResidentAsyncRuntimeShutdown, ResidentAsyncRuntimeTask, ResidentRuntimeTaskRole,
    registered_resident_async_runtime_task,
};

pub struct ResidentRuntimeCoordinator<T> {
    active_generation: ActiveGenerationSlot<T>,
    generation_gate: Arc<GenerationGate>,
}

impl<T> Clone for ResidentRuntimeCoordinator<T> {
    fn clone(&self) -> Self {
        Self {
            active_generation: self.active_generation.clone(),
            generation_gate: Arc::clone(&self.generation_gate),
        }
    }
}

impl<T> ResidentRuntimeCoordinator<T> {
    pub fn with_gate(
        active_generation: ActiveGenerationSlot<T>,
        generation_gate: Arc<GenerationGate>,
    ) -> Self {
        Self {
            active_generation,
            generation_gate,
        }
    }

    pub fn active_generation_slot(&self) -> ActiveGenerationSlot<T> {
        self.active_generation.clone()
    }

    pub fn load(&self) -> Arc<T> {
        self.active_generation.load()
    }

    pub fn load_versioned(&self) -> (PublicationEpoch, Arc<T>) {
        self.active_generation.load_versioned()
    }

    pub fn subscribe_publication(&self) -> tokio::sync::watch::Receiver<PublicationEpoch> {
        self.active_generation.subscribe_publication()
    }

    pub fn generation_gate(&self) -> Arc<GenerationGate> {
        Arc::clone(&self.generation_gate)
    }

    pub fn is_active(&self, token: GenerationToken) -> bool {
        self.generation_gate.is_active(token)
    }

    pub fn publish(&self, token: GenerationToken, generation: Arc<T>) -> Arc<T> {
        match self.generation_gate.switch(token, || {
            Ok::<_, Infallible>(self.active_generation.publish(generation))
        }) {
            Ok(previous) => previous,
            Err(error) => match error {},
        }
    }

    pub fn clear(&self) -> Option<Arc<T>> {
        self.active_generation.clear()
    }
}

impl<T: fmt::Debug> fmt::Debug for ResidentRuntimeCoordinator<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResidentRuntimeCoordinator")
            .field("active_generation", &self.active_generation)
            .field("generation_gate", &self.generation_gate)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dae_resident_core::{LogicalGenerationId, PhysicalRuntimeId};

    fn token(logical: u64) -> GenerationToken {
        GenerationToken::new(PhysicalRuntimeId::new(1), LogicalGenerationId::new(logical))
    }

    #[test]
    fn publication_switches_gate_and_keeps_previous_generation_pinned() {
        let gate = Arc::new(GenerationGate::new(Some(token(1))));
        let first = Arc::new(String::from("first"));
        let coordinator = ResidentRuntimeCoordinator::with_gate(
            ActiveGenerationSlot::new(Arc::clone(&first)),
            Arc::clone(&gate),
        );
        let pinned = coordinator.load();

        let previous = coordinator.publish(token(2), Arc::new(String::from("second")));

        assert_eq!(pinned.as_str(), "first");
        assert!(Arc::ptr_eq(&previous, &first));
        assert_eq!(coordinator.load().as_str(), "second");
        assert!(coordinator.is_active(token(2)));
    }

    #[test]
    fn coordinator_exposes_the_single_publication_source() {
        let gate = Arc::new(GenerationGate::new(Some(token(1))));
        let coordinator = ResidentRuntimeCoordinator::with_gate(
            ActiveGenerationSlot::new(Arc::new(String::from("first"))),
            gate,
        );
        let mut publication = coordinator.subscribe_publication();
        let initial = *publication.borrow_and_update();

        coordinator.publish(token(2), Arc::new(String::from("second")));

        assert!(coordinator.load_versioned().0 > initial);
        assert!(publication.has_changed().unwrap_or(false));
    }
}
