use super::*;

const RESIDENT_DATA_PLANE_RUNTIME_THREAD_NAME: &str = "resident-data-runtime";

pub(super) struct ResidentDataPlaneExecutor {
    runtime: Option<tokio::runtime::Runtime>,
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
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(worker_threads)
            .thread_name(RESIDENT_DATA_PLANE_RUNTIME_THREAD_NAME)
            .thread_stack_size(worker_stack_bytes)
            .enable_all()
            .build()
            .map_err(|error| format!("build resident data-plane Tokio runtime: {error}"))?;
        Ok(Self {
            runtime: Some(runtime),
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
            "executor": "generation-owned-shared-multi-thread",
            "workerThreads": self.worker_threads,
            "workerStackBytes": self.worker_stack_bytes,
            "threadName": RESIDENT_DATA_PLANE_RUNTIME_THREAD_NAME,
            "scope": "resident TCP, UDP, DNS, health and transport-owner tasks for one reload generation",
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
        runtime.block_on(async {
            let mut shutdown = ResidentAsyncRuntimeShutdown::default();
            for mut task in tasks.drain(..) {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    task.handle.abort();
                    shutdown.timed_out = shutdown.timed_out.saturating_add(1);
                    shutdown.pending.push(task);
                    continue;
                }
                match tokio::time::timeout(remaining, &mut task.handle).await {
                    Ok(Ok(())) => {
                        shutdown.joined = shutdown.joined.saturating_add(1);
                        shutdown.results.push(json!({
                            "name": task.name,
                            "kind": task.kind,
                            "status": "joined",
                        }));
                    }
                    Ok(Err(error)) => {
                        shutdown.panicked = shutdown.panicked.saturating_add(1);
                        shutdown.results.push(json!({
                            "name": task.name,
                            "kind": task.kind,
                            "status": if error.is_cancelled() { "cancelled" } else { "panicked" },
                            "error": error.to_string(),
                        }));
                    }
                    Err(_) => {
                        task.handle.abort();
                        shutdown.timed_out = shutdown.timed_out.saturating_add(1);
                        shutdown.results.push(json!({
                            "name": task.name,
                            "kind": task.kind,
                            "status": "timed-out",
                        }));
                        shutdown.pending.push(task);
                    }
                }
            }
            for mut task in shutdown.pending.drain(..) {
                let _ = tokio::time::timeout(Duration::from_millis(1), &mut task.handle).await;
            }
            shutdown
        })
    }

    pub(super) fn shutdown(&mut self, timeout: Duration) {
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_timeout(timeout);
        }
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
}
