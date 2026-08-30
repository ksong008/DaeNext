use dae_resident_core::GenerationCoordinator;

mod cleanup_inventory;
mod executor;
mod generation_drain;
mod generation_lifecycle;
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
pub use generation_lifecycle::{
    ResidentGenerationDrainControl, ResidentGenerationLifetime, next_resident_generation_id,
    resident_generation_lifetime_counts,
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
