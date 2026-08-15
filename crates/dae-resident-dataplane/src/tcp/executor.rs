use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ResidentTcpRuntimeConfig {
    pub(super) worker_threads: usize,
    pub(super) connection_limit: usize,
    pub(super) worker_stack_bytes: usize,
}

impl ResidentTcpRuntimeConfig {
    pub(crate) fn new(
        worker_threads: usize,
        connection_limit: usize,
        worker_stack_bytes: usize,
    ) -> Self {
        Self {
            worker_threads: worker_threads.max(1),
            connection_limit: connection_limit.max(1),
            worker_stack_bytes,
        }
    }

    pub(crate) fn json(self) -> Value {
        json!({
            "executor": "process-owned-shared-multi-thread",
            "workerThreads": self.worker_threads,
            "workerStackBytes": self.worker_stack_bytes,
            "workerStackScope": "resident shared data-plane runtime OS threads; not Tokio task stacks",
            "connectionLimit": self.connection_limit,
            "admission": "active-flow semaphore before accept; excess connections remain in the kernel listen backlog",
        })
    }

    pub(crate) const fn connection_limit(self) -> usize {
        self.connection_limit
    }
}
