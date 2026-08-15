use super::*;

mod command;
use self::command::*;
mod config;
use self::config::*;
mod metrics;
use self::metrics::*;
mod policy;
pub(crate) use self::policy::ProductLogPolicy;
mod queue;
use self::queue::*;
mod registry;
pub(crate) use self::registry::product_log_runtime_for;
use self::registry::{register_product_log_runtime, unregister_product_log_runtime};
mod worker;
use self::worker::*;
mod writer;
use self::writer::*;
#[cfg(test)]
mod tests;

pub(crate) struct ProductLogRuntime {
    config: ProductLogRuntimeConfig,
    registry_key: PathBuf,
    queue: Arc<ProductLogQueue>,
    worker: Mutex<Option<ProductLogWorkerHandle>>,
    metrics: Arc<ProductLogRuntimeMetrics>,
    updates: tokio::sync::watch::Sender<u64>,
}

impl ProductLogRuntime {
    fn start_with_config(
        config_dir: &Path,
        state: &Path,
        config: ProductLogRuntimeConfig,
    ) -> io::Result<Arc<Self>> {
        let policy = ProductLogPolicy::load(state)?;
        let queue = Arc::new(ProductLogQueue::new(config.queue_capacity));
        let metrics = Arc::new(ProductLogRuntimeMetrics::default());
        metrics.configure(config);
        let (updates, _) = tokio::sync::watch::channel(0_u64);
        let worker = start_product_log_worker(
            config,
            config_dir.to_path_buf(),
            policy,
            Arc::clone(&queue),
            Arc::clone(&metrics),
            updates.clone(),
        )?;
        let runtime = Arc::new(Self {
            config,
            registry_key: product_log_file(config_dir),
            queue,
            worker: Mutex::new(Some(worker)),
            metrics,
            updates,
        });
        register_product_log_runtime(&runtime)?;
        Ok(runtime)
    }

    pub(crate) fn append(
        &self,
        level: String,
        message: &str,
        fields: BTreeMap<String, String>,
        respect_runtime_log_level: bool,
    ) -> io::Result<()> {
        self.submit(ProductLogAction::Append(ProductLogAppendRequest {
            level,
            message: trim_log_string(message, MAX_LOG_LINE_BYTES),
            fields: trim_log_fields(fields, MAX_LOG_FIELD_VALUE_LEN),
            respect_runtime_log_level,
        }))
    }

    pub(crate) fn append_detached(
        &self,
        level: String,
        message: &str,
        fields: BTreeMap<String, String>,
        respect_runtime_log_level: bool,
    ) -> io::Result<()> {
        self.submit_detached(ProductLogAction::Append(ProductLogAppendRequest {
            level,
            message: trim_log_string(message, MAX_LOG_LINE_BYTES),
            fields: trim_log_fields(fields, MAX_LOG_FIELD_VALUE_LEN),
            respect_runtime_log_level,
        }))
    }

    pub(crate) fn clear(&self) -> io::Result<()> {
        self.submit(ProductLogAction::Clear)
    }

    pub(crate) fn clear_preserving_lifecycle(&self) -> io::Result<()> {
        self.submit(ProductLogAction::ClearPreservingLifecycle)
    }

    pub(crate) fn replace_policy(&self, policy: ProductLogPolicy) -> io::Result<()> {
        self.submit(ProductLogAction::ReplacePolicy(policy))
    }

    pub(crate) fn apply_limits(&self, max_entries: i64, max_bytes: i64) -> io::Result<()> {
        self.submit(ProductLogAction::ApplyLimits {
            max_entries,
            max_bytes,
        })
    }

    pub(crate) fn subscribe(&self) -> tokio::sync::watch::Receiver<u64> {
        self.updates.subscribe()
    }

    pub(crate) fn snapshot(&self) -> Value {
        self.metrics.snapshot()
    }

    fn submit(&self, action: ProductLogAction) -> io::Result<()> {
        let (completion, completed) = mpsc::sync_channel(1);
        self.metrics.enqueued();
        if let Err(error) = self.queue.submit(
            ProductLogCommand { action, completion },
            self.config.submit_timeout,
        ) {
            self.metrics.enqueue_rollback();
            return Err(error);
        }
        match completed.recv_timeout(self.config.completion_timeout) {
            Ok(result) => result,
            Err(RecvTimeoutError::Timeout) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "product log writer completion timed out",
            )),
            Err(RecvTimeoutError::Disconnected) => Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "product log writer stopped before completing the request",
            )),
        }
    }

    fn submit_detached(&self, action: ProductLogAction) -> io::Result<()> {
        let (completion, _completed) = mpsc::sync_channel(1);
        self.metrics.enqueued();
        self.queue
            .submit(ProductLogCommand { action, completion }, Duration::ZERO)
            .inspect_err(|_| self.metrics.enqueue_rollback())
    }

    pub(super) fn registry_key(&self) -> &Path {
        &self.registry_key
    }
}

impl Drop for ProductLogRuntime {
    fn drop(&mut self) {
        unregister_product_log_runtime(self);
        self.queue.close();
        let worker = self
            .worker
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        let Some(worker) = worker else {
            return;
        };
        let deadline = Instant::now()
            .checked_add(self.config.shutdown_timeout)
            .unwrap_or_else(Instant::now);
        if worker.join_until(deadline) {
            self.metrics.runtime_joined();
        } else {
            self.metrics.runtime_detached();
        }
    }
}

pub(crate) fn start_product_log_runtime(
    config_dir: &Path,
    state: &Path,
) -> io::Result<Arc<ProductLogRuntime>> {
    ProductLogRuntime::start_with_config(
        config_dir,
        state,
        ProductLogRuntimeConfig::from_environment(),
    )
}

#[cfg(test)]
pub(crate) fn start_product_log_runtime_for_test(
    config_dir: &Path,
    state: &Path,
) -> io::Result<Arc<ProductLogRuntime>> {
    ProductLogRuntime::start_with_config(config_dir, state, ProductLogRuntimeConfig::for_test())
}

pub(crate) fn product_log_runtime_snapshot(config_dir: &Path) -> Value {
    product_log_runtime_for(config_dir)
        .map(|runtime| runtime.snapshot())
        .unwrap_or(Value::Null)
}

pub(crate) fn product_log_update_receiver(
    config_dir: &Path,
) -> Option<tokio::sync::watch::Receiver<u64>> {
    product_log_runtime_for(config_dir).map(|runtime| runtime.subscribe())
}
