use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AllocatorWorkerKind {
    Http,
    Sse,
    ProductControl,
    ResidentData,
    ControlAux,
}

pub(crate) struct AllocatorReclaimWorker;

impl AllocatorReclaimWorker {
    pub(crate) fn poll(&mut self) {}
}

#[derive(Clone)]
pub(crate) struct AllocatorRuntimeReclaimHooks;

impl AllocatorRuntimeReclaimHooks {
    pub(crate) fn new(_kind: AllocatorWorkerKind, _worker_threads: usize) -> Self {
        Self
    }

    pub(crate) fn thread_start(&self) {}

    pub(crate) fn thread_stop(&self) {}

    pub(crate) fn activate(&self, _handle: tokio::runtime::Handle) {}

    pub(crate) fn deactivate(&self) {}
}

pub(crate) fn allocator_register_reclaim_worker(
    _kind: AllocatorWorkerKind,
) -> AllocatorReclaimWorker {
    AllocatorReclaimWorker
}

pub(super) fn allocator_worker_reclaim_snapshot_json() -> Value {
    json!({
        "available": false,
        "reason": "worker cache cooperation requires allocator-jemalloc",
    })
}
