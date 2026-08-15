use std::sync::Arc;

#[cfg(test)]
use serde_json::Value;

use super::resident_dataplane::{
    ResidentAllocatorBusyKind, ResidentAllocatorHooks, ResidentAllocatorReclaimReason,
    ResidentAllocatorRuntimeHooks, ResidentAllocatorWorkerKind, set_resident_allocator_hooks,
};
use crate::allocator::{
    AllocatorReclaimBusyKind, AllocatorReclaimReason, AllocatorRuntimeReclaimHooks,
    AllocatorWorkerKind, allocator_reclaim_busy, allocator_request_reclaim,
};
#[cfg(test)]
use crate::allocator::{allocator_stats_json_from, allocator_stats_snapshot};

#[derive(Debug)]
struct DaemonResidentAllocatorHooks;

struct DaemonResidentAllocatorRuntimeHooks {
    inner: AllocatorRuntimeReclaimHooks,
}

impl std::fmt::Debug for DaemonResidentAllocatorRuntimeHooks {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DaemonResidentAllocatorRuntimeHooks")
            .finish_non_exhaustive()
    }
}

impl ResidentAllocatorRuntimeHooks for DaemonResidentAllocatorRuntimeHooks {
    fn thread_start(&self) {
        self.inner.thread_start();
    }

    fn thread_stop(&self) {
        self.inner.thread_stop();
    }

    fn activate(&self, handle: tokio::runtime::Handle) {
        self.inner.activate(handle);
    }

    fn deactivate(&self) {
        self.inner.deactivate();
    }
}

impl ResidentAllocatorHooks for DaemonResidentAllocatorHooks {
    fn request_reclaim(&self, reason: ResidentAllocatorReclaimReason) {
        let reason = match reason {
            ResidentAllocatorReclaimReason::GroupHealthProbe => {
                AllocatorReclaimReason::GroupHealthProbe
            }
            ResidentAllocatorReclaimReason::RetiredGenerationReleased => {
                AllocatorReclaimReason::RetiredGenerationReleased
            }
        };
        allocator_request_reclaim(reason);
    }

    fn enter_busy(&self, kind: ResidentAllocatorBusyKind) -> Box<dyn Send> {
        let kind = match kind {
            ResidentAllocatorBusyKind::GroupHealth => AllocatorReclaimBusyKind::GroupHealth,
        };
        Box::new(allocator_reclaim_busy(kind))
    }

    fn runtime_hooks(
        &self,
        kind: ResidentAllocatorWorkerKind,
        worker_threads: usize,
    ) -> Arc<dyn ResidentAllocatorRuntimeHooks> {
        let kind = match kind {
            ResidentAllocatorWorkerKind::ResidentData => AllocatorWorkerKind::ResidentData,
        };
        Arc::new(DaemonResidentAllocatorRuntimeHooks {
            inner: AllocatorRuntimeReclaimHooks::new(kind, worker_threads),
        })
    }

    #[cfg(test)]
    fn stats_json(&self) -> Value {
        let snapshot = allocator_stats_snapshot();
        allocator_stats_json_from(snapshot.as_ref())
    }
}

pub(super) fn install_resident_allocator_hooks() {
    set_resident_allocator_hooks(Arc::new(DaemonResidentAllocatorHooks));
}
