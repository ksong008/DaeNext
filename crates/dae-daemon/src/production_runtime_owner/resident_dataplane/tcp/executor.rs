use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::production_runtime_owner::resident_dataplane) struct ResidentTcpRuntimeConfig {
    pub(super) worker_threads: usize,
    pub(super) connection_limit: usize,
    pub(super) worker_stack_bytes: usize,
}

impl ResidentTcpRuntimeConfig {
    pub(in crate::production_runtime_owner::resident_dataplane) fn new(
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

    pub(super) fn executor_kind(self) -> &'static str {
        if self.worker_threads == 1 {
            "current-thread"
        } else {
            "multi-thread"
        }
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn json(self) -> Value {
        json!({
            "executor": self.executor_kind(),
            "workerThreads": self.worker_threads,
            "workerStackBytes": self.worker_stack_bytes,
            "workerStackScope": "resident TCP runtime OS threads; not Tokio task stacks",
            "connectionLimit": self.connection_limit,
            "admission": "active-flow semaphore before accept; excess connections remain in the kernel listen backlog",
        })
    }
}

pub(super) fn build_resident_tcp_runtime(
    config: ResidentTcpRuntimeConfig,
) -> Result<runtime::Runtime, String> {
    let result = if config.worker_threads == 1 {
        runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
    } else {
        runtime::Builder::new_multi_thread()
            .worker_threads(config.worker_threads)
            .thread_stack_size(config.worker_stack_bytes)
            .thread_name("resident-tcp-runtime")
            .enable_io()
            .enable_time()
            .build()
    };
    result.map_err(|err| {
        format!(
            "build resident TCP {} runtime: {err}",
            config.executor_kind()
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_worker_keeps_current_thread_runtime() {
        let config = ResidentTcpRuntimeConfig::new(1, 64, 512 * 1024);
        assert_eq!(config.executor_kind(), "current-thread");
        let runtime = build_resident_tcp_runtime(config).unwrap();
        assert_eq!(runtime.block_on(async { 7 }), 7);
    }

    #[test]
    fn multiple_workers_build_shared_multi_thread_runtime() {
        let config = ResidentTcpRuntimeConfig::new(2, 64, 512 * 1024);
        assert_eq!(config.executor_kind(), "multi-thread");
        let runtime = build_resident_tcp_runtime(config).unwrap();
        let values = runtime.block_on(async {
            let first = tokio::spawn(async { 3 });
            let second = tokio::spawn(async { 4 });
            (first.await.unwrap(), second.await.unwrap())
        });
        assert_eq!(values, (3, 4));
    }
}
