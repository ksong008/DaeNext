use super::*;
use futures_util::{StreamExt, stream::FuturesUnordered};

const RESIDENT_DATA_PLANE_RUNTIME_THREAD_NAME: &str = "resident-data-runtime";

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

pub(super) struct ResidentDataPlaneExecutor {
    runtime: Option<tokio::runtime::Runtime>,
    _allocator_reclaim: crate::allocator::AllocatorRuntimeReclaimHooks,
    worker_threads: usize,
    worker_stack_bytes: usize,
}

impl std::fmt::Debug for ResidentDataPlaneExecutor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ResidentDataPlaneExecutor")
            .field("worker_threads", &self.worker_threads)
            .field("worker_stack_bytes", &self.worker_stack_bytes)
            .field("active", &self.runtime.is_some())
            .finish()
    }
}

impl ResidentDataPlaneExecutor {
    pub(super) fn new(resources: &ResidentRuntimeResourceConfig) -> Result<Self, String> {
        let worker_threads = resources.tcp_runtime_workers.value().max(1);
        let worker_stack_bytes = resources
            .tcp_flow_stack_bytes
            .value()
            .max(RESIDENT_DNS_TRANSPORT_WORKER_STACK_BYTES_MIN);
        let allocator_reclaim = crate::allocator::AllocatorRuntimeReclaimHooks::new(
            crate::allocator::AllocatorWorkerKind::ResidentData,
            worker_threads,
        );
        let start_reclaim = allocator_reclaim.clone();
        let stop_reclaim = allocator_reclaim.clone();
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
            _allocator_reclaim: allocator_reclaim,
            worker_threads,
            worker_stack_bytes,
        })
    }

    pub(super) fn handle(&self) -> tokio::runtime::Handle {
        self.runtime
            .as_ref()
            .expect("resident data-plane runtime is available before shutdown")
            .handle()
            .clone()
    }

    pub(super) fn worker_threads(&self) -> usize {
        self.worker_threads
    }

    pub(super) fn json(&self) -> Value {
        json!({
            "executor": "process-owned-shared-multi-thread",
            "workerThreads": self.worker_threads,
            "workerStackBytes": self.worker_stack_bytes,
            "threadName": RESIDENT_DATA_PLANE_RUNTIME_THREAD_NAME,
            "scope": "resident TCP, UDP, DNS, health and transport-owner tasks across active and draining generations",
        })
    }

    pub(super) fn join_tasks(
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

    pub(super) fn shutdown(&mut self, timeout: Duration) {
        self._allocator_reclaim.deactivate();
        if let Some(runtime) = self.runtime.take() {
            run_runtime_blocking_operation(move || runtime.shutdown_timeout(timeout));
        }
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

#[derive(Default)]
pub(in crate::production_runtime_owner::resident_dataplane) struct ResidentTaskSetShutdown {
    pub(in crate::production_runtime_owner::resident_dataplane) joined: usize,
    pub(in crate::production_runtime_owner::resident_dataplane) cancelled: usize,
    pub(in crate::production_runtime_owner::resident_dataplane) panicked: usize,
    pub(in crate::production_runtime_owner::resident_dataplane) forced: usize,
}

pub(in crate::production_runtime_owner::resident_dataplane) async fn shutdown_resident_task_set<
    T: 'static,
>(
    tasks: &mut tokio::task::JoinSet<T>,
    grace: Duration,
) -> ResidentTaskSetShutdown {
    let mut shutdown = ResidentTaskSetShutdown::default();
    let deadline = tokio::time::Instant::now() + grace;
    while !tasks.is_empty() {
        match tokio::time::timeout_at(deadline, tasks.join_next()).await {
            Ok(Some(completed)) => record_resident_task_completion(&mut shutdown, completed),
            Ok(None) => break,
            Err(_) => {
                shutdown.forced = shutdown.forced.saturating_add(tasks.len());
                tasks.abort_all();
                while let Some(completed) = tasks.join_next().await {
                    record_resident_task_completion(&mut shutdown, completed);
                }
                break;
            }
        }
    }
    shutdown
}

pub(in crate::production_runtime_owner::resident_dataplane) fn record_resident_task_completion<
    T,
>(
    shutdown: &mut ResidentTaskSetShutdown,
    completed: Result<T, tokio::task::JoinError>,
) {
    match completed {
        Ok(_) => shutdown.joined = shutdown.joined.saturating_add(1),
        Err(error) if error.is_cancelled() => {
            shutdown.cancelled = shutdown.cancelled.saturating_add(1);
        }
        Err(_) => shutdown.panicked = shutdown.panicked.saturating_add(1),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_executor_uses_profile_workers_and_dns_safe_stack() {
        let config = Config {
            global: dae_config::Global::default(),
            subscription: Vec::new(),
            node: Vec::new(),
            group: Vec::new(),
            routing: dae_config::Routing::default(),
            dns: dae_config::Dns::default(),
        };
        let resources = ResidentRuntimeResourceConfig::from_config(&config);
        let mut executor = ResidentDataPlaneExecutor::new(&resources).unwrap();
        assert_eq!(
            executor.worker_threads(),
            resources.tcp_runtime_workers.value()
        );
        assert!(
            executor.json()["workerStackBytes"]
                .as_u64()
                .unwrap_or_default()
                >= RESIDENT_DNS_TRANSPORT_WORKER_STACK_BYTES_MIN as u64
        );
        executor.shutdown(Duration::from_millis(100));
    }

    #[test]
    fn shared_executor_joins_ready_tasks_without_vec_order_head_of_line_blocking() {
        let config = Config {
            global: dae_config::Global::default(),
            subscription: Vec::new(),
            node: Vec::new(),
            group: Vec::new(),
            routing: dae_config::Routing::default(),
            dns: dae_config::Dns::default(),
        };
        let resources = ResidentRuntimeResourceConfig::from_config(&config);
        let mut executor = ResidentDataPlaneExecutor::new(&resources).unwrap();
        let runtime = executor.handle();
        let tasks = vec![
            registered_resident_async_runtime_task(
                "blocked",
                "test",
                ResidentRuntimeTaskRole::Workload,
                runtime.spawn(std::future::pending()),
            ),
            registered_resident_async_runtime_task(
                "ready",
                "test",
                ResidentRuntimeTaskRole::Workload,
                runtime.spawn(async {}),
            ),
        ];

        let shutdown = executor.join_tasks(tasks, Instant::now() + Duration::from_millis(25));

        assert_eq!(shutdown.joined, 1);
        assert_eq!(shutdown.cancelled, 1);
        assert_eq!(shutdown.panicked, 0);
        assert_eq!(shutdown.timed_out, 1);
        assert!(shutdown.pending.is_empty());
        assert!(
            shutdown
                .results
                .iter()
                .any(|result| { result["name"] == "ready" && result["status"] == "joined" })
        );
        executor.shutdown(Duration::from_millis(100));
    }

    #[test]
    fn shared_executor_reports_pre_cancelled_task_without_panic() {
        let config = Config {
            global: dae_config::Global::default(),
            subscription: Vec::new(),
            node: Vec::new(),
            group: Vec::new(),
            routing: dae_config::Routing::default(),
            dns: dae_config::Dns::default(),
        };
        let resources = ResidentRuntimeResourceConfig::from_config(&config);
        let mut executor = ResidentDataPlaneExecutor::new(&resources).unwrap();
        let handle = executor.handle().spawn(std::future::pending());
        handle.abort();
        let task = registered_resident_async_runtime_task(
            "cancelled",
            "test",
            ResidentRuntimeTaskRole::Workload,
            handle,
        );

        let shutdown = executor.join_tasks(vec![task], Instant::now() + Duration::from_millis(100));

        assert_eq!(shutdown.cancelled, 1);
        assert_eq!(shutdown.panicked, 0);
        assert_eq!(shutdown.timed_out, 0);
        executor.shutdown(Duration::from_millis(100));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shared_executor_can_join_and_shutdown_from_multi_thread_runtime_worker() {
        let config = Config {
            global: dae_config::Global::default(),
            subscription: Vec::new(),
            node: Vec::new(),
            group: Vec::new(),
            routing: dae_config::Routing::default(),
            dns: dae_config::Dns::default(),
        };
        let resources = ResidentRuntimeResourceConfig::from_config(&config);
        let mut executor = ResidentDataPlaneExecutor::new(&resources).unwrap();
        let runtime = executor.handle();
        let tasks = vec![
            registered_resident_async_runtime_task(
                "ready",
                "test",
                ResidentRuntimeTaskRole::Workload,
                runtime.spawn(async {}),
            ),
            registered_resident_async_runtime_task(
                "blocked",
                "test",
                ResidentRuntimeTaskRole::Workload,
                runtime.spawn(std::future::pending()),
            ),
        ];

        let shutdown = executor.join_tasks(tasks, Instant::now() + Duration::from_millis(25));

        assert_eq!(shutdown.joined, 1);
        assert_eq!(shutdown.cancelled, 1);
        assert_eq!(shutdown.panicked, 0);
        assert_eq!(shutdown.timed_out, 1);
        assert!(shutdown.pending.is_empty());
        executor.shutdown(Duration::from_millis(100));
        executor.shutdown(Duration::from_millis(100));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn shared_executor_can_join_and_shutdown_from_current_thread_runtime_worker() {
        let config = Config {
            global: dae_config::Global::default(),
            subscription: Vec::new(),
            node: Vec::new(),
            group: Vec::new(),
            routing: dae_config::Routing::default(),
            dns: dae_config::Dns::default(),
        };
        let resources = ResidentRuntimeResourceConfig::from_config(&config);
        let mut executor = ResidentDataPlaneExecutor::new(&resources).unwrap();
        let runtime = executor.handle();
        let task = registered_resident_async_runtime_task(
            "ready",
            "test",
            ResidentRuntimeTaskRole::Workload,
            runtime.spawn(async {}),
        );

        let shutdown = executor.join_tasks(vec![task], Instant::now() + Duration::from_millis(100));

        assert_eq!(shutdown.joined, 1);
        assert_eq!(shutdown.cancelled, 0);
        assert_eq!(shutdown.panicked, 0);
        assert_eq!(shutdown.timed_out, 0);
        executor.shutdown(Duration::from_millis(100));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn task_set_shutdown_reaps_ready_and_forces_only_remaining_tasks() {
        let mut tasks = tokio::task::JoinSet::new();
        tasks.spawn(async {});
        tasks.spawn(std::future::pending());

        let shutdown = shutdown_resident_task_set(&mut tasks, Duration::from_millis(20)).await;

        assert_eq!(shutdown.joined, 1);
        assert_eq!(shutdown.cancelled, 1);
        assert_eq!(shutdown.panicked, 0);
        assert_eq!(shutdown.forced, 1);
        assert!(tasks.is_empty());
    }
}
