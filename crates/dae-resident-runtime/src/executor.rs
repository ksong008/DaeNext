use futures_util::{StreamExt, stream::FuturesUnordered};
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::task::{ResidentAsyncRuntimeShutdown, ResidentAsyncRuntimeTask};

const RESIDENT_DATA_PLANE_RUNTIME_THREAD_NAME: &str = "resident-data-runtime";

pub trait ResidentRuntimeAllocatorHooks: std::fmt::Debug + Send + Sync {
    fn thread_start(&self);
    fn thread_stop(&self);
    fn activate(&self, handle: tokio::runtime::Handle);
    fn deactivate(&self);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResidentRuntimeExecutorConfig {
    pub worker_threads: usize,
    pub worker_stack_bytes: usize,
}

impl ResidentRuntimeExecutorConfig {
    pub const fn new(worker_threads: usize, worker_stack_bytes: usize) -> Self {
        Self {
            worker_threads,
            worker_stack_bytes,
        }
    }
}

pub struct ResidentRuntimeExecutor {
    runtime: Option<tokio::runtime::Runtime>,
    allocator_reclaim: Arc<dyn ResidentRuntimeAllocatorHooks>,
    config: ResidentRuntimeExecutorConfig,
}

impl std::fmt::Debug for ResidentRuntimeExecutor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ResidentRuntimeExecutor")
            .field("worker_threads", &self.config.worker_threads)
            .field("worker_stack_bytes", &self.config.worker_stack_bytes)
            .field("active", &self.runtime.is_some())
            .finish()
    }
}

impl ResidentRuntimeExecutor {
    pub fn new(
        config: ResidentRuntimeExecutorConfig,
        allocator_reclaim: Arc<dyn ResidentRuntimeAllocatorHooks>,
    ) -> Result<Self, String> {
        let worker_threads = config.worker_threads.max(1);
        let worker_stack_bytes = config.worker_stack_bytes.max(1);
        let start_reclaim = Arc::clone(&allocator_reclaim);
        let stop_reclaim = Arc::clone(&allocator_reclaim);
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(worker_threads)
            .thread_name(RESIDENT_DATA_PLANE_RUNTIME_THREAD_NAME)
            .thread_stack_size(worker_stack_bytes)
            .on_thread_start(move || start_reclaim.thread_start())
            .on_thread_stop(move || stop_reclaim.thread_stop())
            .enable_all()
            .build()
            .map_err(|error| format!("build resident data-plane Tokio runtime: {error}"))?;
        allocator_reclaim.activate(runtime.handle().clone());
        Ok(Self {
            runtime: Some(runtime),
            allocator_reclaim,
            config: ResidentRuntimeExecutorConfig::new(worker_threads, worker_stack_bytes),
        })
    }

    pub fn handle(&self) -> tokio::runtime::Handle {
        self.runtime
            .as_ref()
            .expect("resident runtime executor is available before shutdown")
            .handle()
            .clone()
    }

    pub fn worker_threads(&self) -> usize {
        self.config.worker_threads
    }

    pub fn json(&self) -> Value {
        json!({
            "executor": "process-owned-shared-multi-thread",
            "workerThreads": self.config.worker_threads,
            "workerStackBytes": self.config.worker_stack_bytes,
            "threadName": RESIDENT_DATA_PLANE_RUNTIME_THREAD_NAME,
            "scope": "resident TCP, UDP, DNS, health and transport-owner tasks across active and draining generations",
        })
    }

    pub fn join_tasks(
        &self,
        mut tasks: Vec<ResidentAsyncRuntimeTask>,
        deadline: Instant,
    ) -> ResidentAsyncRuntimeShutdown {
        let Some(runtime) = self.runtime.as_ref() else {
            return ResidentAsyncRuntimeShutdown {
                timed_out: tasks.len(),
                pending: tasks,
                ..ResidentAsyncRuntimeShutdown::default()
            };
        };
        run_runtime_blocking_operation(move || {
            runtime.block_on(async move {
                let mut shutdown = ResidentAsyncRuntimeShutdown::default();
                let abort_handles = tasks
                    .iter()
                    .map(|task| task.handle.abort_handle())
                    .collect::<Vec<_>>();
                let mut pending = tasks
                    .drain(..)
                    .map(|mut task| async move {
                        let result = (&mut task.handle).await;
                        (task, result)
                    })
                    .collect::<FuturesUnordered<_>>();
                let deadline = tokio::time::Instant::from_std(deadline);

                loop {
                    match tokio::time::timeout_at(deadline, pending.next()).await {
                        Ok(Some((task, result))) => {
                            record_async_task_completion(&mut shutdown, task, result, false);
                        }
                        Ok(None) => break,
                        Err(_) => {
                            shutdown.timed_out = shutdown.timed_out.saturating_add(pending.len());
                            for handle in &abort_handles {
                                handle.abort();
                            }
                            while let Some((task, result)) = pending.next().await {
                                record_async_task_completion(&mut shutdown, task, result, true);
                            }
                            break;
                        }
                    }
                }
                shutdown
            })
        })
    }

    pub fn shutdown(&mut self, timeout: Duration) {
        self.allocator_reclaim.deactivate();
        if let Some(runtime) = self.runtime.take() {
            run_runtime_blocking_operation(move || runtime.shutdown_timeout(timeout));
        }
    }
}

fn run_runtime_blocking_operation<T>(operation: impl FnOnce() -> T + Send) -> T
where
    T: Send,
{
    match tokio::runtime::Handle::try_current() {
        Ok(handle)
            if matches!(
                handle.runtime_flavor(),
                tokio::runtime::RuntimeFlavor::MultiThread
            ) =>
        {
            tokio::task::block_in_place(operation)
        }
        Ok(_) => std::thread::scope(|scope| match scope.spawn(operation).join() {
            Ok(result) => result,
            Err(panic) => std::panic::resume_unwind(panic),
        }),
        Err(_) => operation(),
    }
}

fn record_async_task_completion(
    shutdown: &mut ResidentAsyncRuntimeShutdown,
    task: ResidentAsyncRuntimeTask,
    result: Result<(), tokio::task::JoinError>,
    forced: bool,
) {
    let role = task.role.name();
    match result {
        Ok(()) => {
            shutdown.joined = shutdown.joined.saturating_add(1);
            shutdown.results.push(json!({
                "name": task.name,
                "kind": task.kind,
                "role": role,
                "status": "joined",
                "forced": forced,
            }));
        }
        Err(error) if error.is_cancelled() => {
            shutdown.cancelled = shutdown.cancelled.saturating_add(1);
            shutdown.results.push(json!({
                "name": task.name,
                "kind": task.kind,
                "role": role,
                "status": if forced { "aborted" } else { "cancelled" },
                "forced": forced,
                "error": error.to_string(),
            }));
        }
        Err(error) => {
            shutdown.panicked = shutdown.panicked.saturating_add(1);
            shutdown.results.push(json!({
                "name": task.name,
                "kind": task.kind,
                "role": role,
                "status": "panicked",
                "forced": forced,
                "error": error.to_string(),
            }));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ResidentRuntimeTaskRole;

    #[derive(Debug)]
    struct NoopHooks;

    impl ResidentRuntimeAllocatorHooks for NoopHooks {
        fn thread_start(&self) {}
        fn thread_stop(&self) {}
        fn activate(&self, _handle: tokio::runtime::Handle) {}
        fn deactivate(&self) {}
    }

    fn executor() -> ResidentRuntimeExecutor {
        ResidentRuntimeExecutor::new(
            ResidentRuntimeExecutorConfig::new(1, 2 * 1024 * 1024),
            Arc::new(NoopHooks),
        )
        .expect("runtime executor")
    }

    #[test]
    fn executor_uses_at_least_one_worker_and_reports_config() {
        let mut executor = ResidentRuntimeExecutor::new(
            ResidentRuntimeExecutorConfig::new(0, 0),
            Arc::new(NoopHooks),
        )
        .expect("runtime executor");
        assert_eq!(executor.worker_threads(), 1);
        assert_eq!(executor.json()["workerStackBytes"], 1);
        executor.shutdown(Duration::from_millis(100));
    }

    #[test]
    fn executor_joins_ready_tasks_without_head_of_line_blocking() {
        let mut executor = executor();
        let runtime = executor.handle();
        let tasks = vec![
            crate::registered_resident_async_runtime_task(
                "blocked",
                "test",
                ResidentRuntimeTaskRole::Workload,
                runtime.spawn(std::future::pending()),
            ),
            crate::registered_resident_async_runtime_task(
                "ready",
                "test",
                ResidentRuntimeTaskRole::Workload,
                runtime.spawn(async {}),
            ),
        ];
        let shutdown = executor.join_tasks(tasks, Instant::now() + Duration::from_millis(25));
        assert_eq!(shutdown.joined, 1);
        assert_eq!(shutdown.cancelled, 1);
        assert_eq!(shutdown.timed_out, 1);
        executor.shutdown(Duration::from_millis(100));
    }

    #[test]
    fn executor_can_shutdown_twice() {
        let mut executor = executor();
        executor.shutdown(Duration::from_millis(100));
        executor.shutdown(Duration::from_millis(100));
    }
}
