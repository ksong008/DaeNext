use std::fmt;
use std::sync::{Arc, OnceLock, RwLock};

#[cfg(test)]
use serde_json::{Value, json};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResidentAllocatorReclaimReason {
    GroupHealthProbe,
    #[cfg_attr(test, allow(dead_code))]
    RetiredGenerationReleased,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResidentAllocatorBusyKind {
    GroupHealth,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResidentAllocatorWorkerKind {
    ResidentData,
}

pub trait ResidentAllocatorRuntimeHooks: fmt::Debug + Send + Sync {
    fn thread_start(&self);
    fn thread_stop(&self);
    fn activate(&self, handle: tokio::runtime::Handle);
    fn deactivate(&self);
}

pub trait ResidentAllocatorHooks: fmt::Debug + Send + Sync {
    fn request_reclaim(&self, reason: ResidentAllocatorReclaimReason);
    fn enter_busy(&self, kind: ResidentAllocatorBusyKind) -> Box<dyn Send>;
    fn runtime_hooks(
        &self,
        kind: ResidentAllocatorWorkerKind,
        worker_threads: usize,
    ) -> Arc<dyn ResidentAllocatorRuntimeHooks>;
    #[cfg(test)]
    fn stats_json(&self) -> Value;
}

#[derive(Debug)]
struct NoopResidentAllocatorHooks;

#[derive(Debug)]
struct NoopResidentAllocatorRuntimeHooks;

impl ResidentAllocatorRuntimeHooks for NoopResidentAllocatorRuntimeHooks {
    fn thread_start(&self) {}
    fn thread_stop(&self) {}
    fn activate(&self, _handle: tokio::runtime::Handle) {}
    fn deactivate(&self) {}
}

impl ResidentAllocatorHooks for NoopResidentAllocatorHooks {
    fn request_reclaim(&self, _reason: ResidentAllocatorReclaimReason) {}

    fn enter_busy(&self, _kind: ResidentAllocatorBusyKind) -> Box<dyn Send> {
        Box::new(())
    }

    fn runtime_hooks(
        &self,
        _kind: ResidentAllocatorWorkerKind,
        _worker_threads: usize,
    ) -> Arc<dyn ResidentAllocatorRuntimeHooks> {
        Arc::new(NoopResidentAllocatorRuntimeHooks)
    }

    #[cfg(test)]
    fn stats_json(&self) -> Value {
        json!({"available": false, "reason": "resident allocator hooks are not installed"})
    }
}

fn hooks() -> &'static RwLock<Arc<dyn ResidentAllocatorHooks>> {
    static HOOKS: OnceLock<RwLock<Arc<dyn ResidentAllocatorHooks>>> = OnceLock::new();
    HOOKS.get_or_init(|| RwLock::new(Arc::new(NoopResidentAllocatorHooks)))
}

pub fn set_resident_allocator_hooks(value: Arc<dyn ResidentAllocatorHooks>) {
    *hooks()
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = value;
}

pub(crate) fn resident_allocator_request_reclaim(reason: ResidentAllocatorReclaimReason) {
    hooks()
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .request_reclaim(reason);
}

pub(crate) fn resident_allocator_enter_busy(kind: ResidentAllocatorBusyKind) -> Box<dyn Send> {
    hooks()
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .enter_busy(kind)
}

pub(crate) fn resident_allocator_runtime_hooks(
    kind: ResidentAllocatorWorkerKind,
    worker_threads: usize,
) -> Arc<dyn ResidentAllocatorRuntimeHooks> {
    hooks()
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .runtime_hooks(kind, worker_threads)
}

#[cfg(test)]
pub(crate) fn resident_allocator_stats_json() -> Value {
    hooks()
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .stats_json()
}
