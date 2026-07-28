use super::*;

mod admission;
use admission::*;
mod benchmark;
pub use benchmark::{ProductControlBenchmarkFixture, product_control_benchmark_fixture};
mod cancellation;
pub(in crate::daed_product) use cancellation::*;
mod config;
use config::*;
mod metrics;
use metrics::*;
mod supervisor;
use supervisor::*;
mod task;
pub(in crate::daed_product) use task::*;
#[cfg(test)]
mod tests;

const PRODUCT_CONTROL_RUNTIME_THREAD_NAME: &str = "product-control-runtime";

#[derive(Clone, Copy)]
enum ProductControlWait {
    Timeout(Duration),
    Completion,
}

pub(in crate::daed_product) struct ProductControlRuntime {
    config: ProductControlRuntimeConfig,
    runtime: Mutex<Option<tokio::runtime::Runtime>>,
    _allocator_reclaim: crate::allocator::AllocatorRuntimeReclaimHooks,
    sender: Mutex<Option<tokio::sync::mpsc::Sender<ProductControlTaskCommand>>>,
    supervisor: Mutex<Option<tokio::task::JoinHandle<ProductControlTaskShutdown>>>,
    stop: ProductControlCancellation,
    admission: Arc<ProductControlAdmission>,
    metrics: Arc<ProductControlRuntimeMetrics>,
    stopping: AtomicBool,
    shutdown_evidence: Mutex<Option<Value>>,
}

impl ProductControlRuntime {
    pub(in crate::daed_product) fn start_for_http_config(
        http_config: ProductHttpWorkerConfig,
    ) -> io::Result<Arc<Self>> {
        Self::start(ProductControlRuntimeConfig::from_http_config(http_config))
    }

    #[cfg(test)]
    pub(in crate::daed_product) fn start_for_test() -> io::Result<Arc<Self>> {
        Self::start(ProductControlRuntimeConfig::for_test())
    }

    fn start(config: ProductControlRuntimeConfig) -> io::Result<Arc<Self>> {
        let allocator_reclaim = crate::allocator::AllocatorRuntimeReclaimHooks::new(
            crate::allocator::AllocatorWorkerKind::ProductControl,
            config.worker_threads,
        );
        let start_reclaim = allocator_reclaim.clone();
        let stop_reclaim = allocator_reclaim.clone();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(config.worker_threads)
            .max_blocking_threads(config.maximum_blocking_threads)
            .thread_name(PRODUCT_CONTROL_RUNTIME_THREAD_NAME)
            .thread_stack_size(config.worker_stack_bytes)
            .on_thread_start(move || start_reclaim.thread_start())
            .on_thread_stop(move || stop_reclaim.thread_stop())
            .enable_all()
            .build()
            .map_err(|error| io::Error::other(format!("start product control runtime: {error}")))?;
        allocator_reclaim.activate(runtime.handle().clone());
        let (sender, receiver) = tokio::sync::mpsc::channel(config.queue_capacity);
        let stop = ProductControlCancellation::new();
        let admission = Arc::new(ProductControlAdmission::new(config));
        let metrics = Arc::new(ProductControlRuntimeMetrics::new());
        let supervisor = runtime.handle().spawn(run_product_control_task_supervisor(
            receiver,
            stop.clone(),
            Arc::clone(&metrics),
            config.shutdown_timeout,
        ));
        Ok(Arc::new(Self {
            config,
            runtime: Mutex::new(Some(runtime)),
            _allocator_reclaim: allocator_reclaim,
            sender: Mutex::new(Some(sender)),
            supervisor: Mutex::new(Some(supervisor)),
            stop,
            admission,
            metrics,
            stopping: AtomicBool::new(false),
            shutdown_evidence: Mutex::new(None),
        }))
    }

    pub(in crate::daed_product) fn execute<T, F, Fut>(
        &self,
        kind: ProductControlTaskKind,
        timeout: Duration,
        action: F,
    ) -> Result<T, ProductControlExecutionError>
    where
        T: Send + 'static,
        F: FnOnce(ProductControlCancellation) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = T> + Send + 'static,
    {
        self.execute_with_wait(kind, ProductControlWait::Timeout(timeout), action)
    }

    pub(in crate::daed_product) fn execute_to_completion<T, F, Fut>(
        &self,
        kind: ProductControlTaskKind,
        action: F,
    ) -> Result<T, ProductControlExecutionError>
    where
        T: Send + 'static,
        F: FnOnce(ProductControlCancellation) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = T> + Send + 'static,
    {
        self.execute_with_wait(kind, ProductControlWait::Completion, action)
    }

    fn execute_with_wait<T, F, Fut>(
        &self,
        kind: ProductControlTaskKind,
        wait: ProductControlWait,
        action: F,
    ) -> Result<T, ProductControlExecutionError>
    where
        T: Send + 'static,
        F: FnOnce(ProductControlCancellation) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = T> + Send + 'static,
    {
        self.metrics.submitted();
        if self.stopping.load(Ordering::Acquire) {
            self.metrics.rejected();
            return Err(ProductControlExecutionError::Unavailable);
        }
        let permit = self.admission.try_acquire(kind).ok_or_else(|| {
            self.metrics.rejected();
            ProductControlExecutionError::Busy
        })?;
        let sender = self
            .sender
            .lock()
            .ok()
            .and_then(|sender| sender.as_ref().cloned())
            .ok_or_else(|| {
                self.metrics.rejected();
                ProductControlExecutionError::Unavailable
            })?;
        let cancellation = ProductControlCancellation::new();
        let task_cancellation = cancellation.clone();
        let (result_sender, result_receiver) = std::sync::mpsc::sync_channel(1);
        let metrics = Arc::clone(&self.metrics);
        let future = Box::pin(async move {
            let active = metrics.active();
            let result = action(task_cancellation).await;
            drop(permit);
            drop(active);
            let _ = result_sender.send(result);
        });
        let command = ProductControlTaskCommand {
            cancellation: cancellation.clone(),
            future,
        };
        self.metrics.queued();
        match sender.try_send(command) {
            Ok(()) => self.metrics.enqueued(),
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                self.metrics.dequeued();
                self.metrics.rejected();
                return Err(ProductControlExecutionError::Busy);
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                self.metrics.dequeued();
                self.metrics.rejected();
                return Err(ProductControlExecutionError::Unavailable);
            }
        }
        let received = match wait {
            ProductControlWait::Timeout(timeout) => result_receiver.recv_timeout(timeout),
            ProductControlWait::Completion => result_receiver
                .recv()
                .map_err(|_| std::sync::mpsc::RecvTimeoutError::Disconnected),
        };
        match received {
            Ok(result) => Ok(result),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                cancellation.request();
                self.metrics.timed_out();
                Err(ProductControlExecutionError::TimedOut)
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                cancellation.request();
                Err(ProductControlExecutionError::Unavailable)
            }
        }
    }

    pub(in crate::daed_product) fn snapshot(&self) -> Value {
        let shutdown = self
            .shutdown_evidence
            .lock()
            .ok()
            .and_then(|evidence| evidence.clone());
        self.metrics.snapshot(
            self.config,
            &self.admission,
            self.stopping.load(Ordering::Acquire),
            shutdown.as_ref(),
        )
    }

    pub(in crate::daed_product) fn startup_fields(&self) -> BTreeMap<String, String> {
        self.config.startup_fields()
    }

    pub(in crate::daed_product) fn shutdown(&self) -> io::Result<Value> {
        if self.stopping.swap(true, Ordering::AcqRel) {
            return Ok(self
                .shutdown_evidence
                .lock()
                .ok()
                .and_then(|evidence| evidence.clone())
                .unwrap_or_else(|| json!({"status": "stopping"})));
        }
        self.sender
            .lock()
            .map_err(|_| io::Error::other("product control sender lock poisoned"))?
            .take();
        self.stop.request();
        self._allocator_reclaim.deactivate();
        let mut supervisor = self
            .supervisor
            .lock()
            .map_err(|_| io::Error::other("product control supervisor lock poisoned"))?
            .take();
        let runtime = self
            .runtime
            .lock()
            .map_err(|_| io::Error::other("product control runtime lock poisoned"))?
            .take();
        let started = Instant::now();
        let mut supervisor_forced = false;
        let task_shutdown = match (&runtime, supervisor.as_mut()) {
            (Some(runtime), Some(supervisor)) => runtime.block_on(async {
                let outer_timeout = self
                    .config
                    .shutdown_timeout
                    .saturating_add(Duration::from_secs(1));
                match tokio::time::timeout(outer_timeout, &mut *supervisor).await {
                    Ok(Ok(shutdown)) => shutdown,
                    Ok(Err(error)) => {
                        let mut shutdown = ProductControlTaskShutdown::default();
                        if error.is_cancelled() {
                            shutdown.cancelled = 1;
                        } else {
                            shutdown.panicked = 1;
                        }
                        shutdown
                    }
                    Err(_) => {
                        supervisor_forced = true;
                        supervisor.abort();
                        let _ = supervisor.await;
                        ProductControlTaskShutdown {
                            forced: 1,
                            ..ProductControlTaskShutdown::default()
                        }
                    }
                }
            }),
            _ => ProductControlTaskShutdown::default(),
        };
        if supervisor_forced {
            self.metrics.forced(1);
        }
        if let Some(runtime) = runtime {
            runtime.shutdown_timeout(self.config.shutdown_timeout);
        }
        let evidence = json!({
            "status": if task_shutdown.panicked == 0 && task_shutdown.forced == 0 {
                "stopped"
            } else {
                "degraded"
            },
            "elapsedMs": started.elapsed().as_millis().to_string(),
            "tasks": task_shutdown.json(),
        });
        *self
            .shutdown_evidence
            .lock()
            .map_err(|_| io::Error::other("product control shutdown evidence lock poisoned"))? =
            Some(evidence.clone());
        Ok(evidence)
    }
}

impl std::fmt::Debug for ProductControlRuntime {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProductControlRuntime")
            .field("config", &self.config)
            .field("stopping", &self.stopping.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}

impl Drop for ProductControlRuntime {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}
