use dae_resident_core::GenerationCoordinator;

mod cleanup_inventory;
mod executor;
mod generation_drain;
mod task;
mod thread_shutdown;
mod thread_task;

pub use cleanup_inventory::{ResidentRuntimeCleanupInventory, ResidentRuntimeCleanupReporter};
pub use executor::{
    ResidentRuntimeAllocatorHooks, ResidentRuntimeExecutor, ResidentRuntimeExecutorConfig,
};
pub use generation_drain::{
    ResidentDrainControl, ResidentDrainableGeneration, ResidentGenerationDrain,
    ResidentGenerationDrainHooks, ResidentGenerationDrainPolicy,
};
pub use task::{
    ResidentAsyncRuntimeShutdown, ResidentAsyncRuntimeTask, ResidentRuntimeTaskRole,
    registered_resident_async_runtime_task,
};
pub use thread_shutdown::{
    ResidentRuntimeThreadShutdown, elapsed_nanos, take_resident_async_runtime_tasks,
    wait_for_resident_runtime_tasks,
};
pub use thread_task::{
    ResidentRuntimeTask, ResidentRuntimeTaskExit, registered_resident_runtime_task,
    spawn_resident_runtime_thread,
};

pub type ResidentRuntimeCoordinator<T> = GenerationCoordinator<T>;

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
