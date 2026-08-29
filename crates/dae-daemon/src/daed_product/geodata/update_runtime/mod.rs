use super::update::update_geodata_with_lease_using;
use super::*;

use dae_product_geodata::{ProductGeodataUpdateMetrics, ProductGeodataUpdateRuntimeConfig};
mod worker;
use self::worker::*;
#[cfg(test)]
mod tests;

pub(in crate::daed_product) struct ProductGeodataUpdateRuntime {
    config: ProductGeodataUpdateRuntimeConfig,
    context: ProductGeodataUpdateContext,
    sender: Mutex<Option<std::sync::mpsc::SyncSender<ProductGeodataUpdateJob>>>,
    receiver: Arc<Mutex<std::sync::mpsc::Receiver<ProductGeodataUpdateJob>>>,
    workers: Mutex<Vec<ProductGeodataUpdateWorkerHandle>>,
    metrics: Arc<ProductGeodataUpdateMetrics>,
    stopping: Arc<std::sync::atomic::AtomicBool>,
}

#[derive(Debug)]
pub(in crate::daed_product) struct ProductGeodataUpdateSubmissionError {
    pub(in crate::daed_product) stream: TcpStream,
    pub(in crate::daed_product) request: HttpRequest,
    pub(in crate::daed_product) response: HttpResponse,
}

impl ProductGeodataUpdateRuntime {
    pub(in crate::daed_product) fn start_for_app(
        http_config: ProductHttpWorkerConfig,
        app: &AppState,
    ) -> io::Result<Arc<Self>> {
        Self::start(http_config, ProductGeodataUpdateContext::from_app(app))
    }

    fn start(
        http_config: ProductHttpWorkerConfig,
        context: ProductGeodataUpdateContext,
    ) -> io::Result<Arc<Self>> {
        let config = ProductGeodataUpdateRuntimeConfig::from_http_config(http_config);
        Self::start_with_config(config, context)
    }

    fn start_with_config(
        config: ProductGeodataUpdateRuntimeConfig,
        context: ProductGeodataUpdateContext,
    ) -> io::Result<Arc<Self>> {
        let metrics = Arc::new(ProductGeodataUpdateMetrics::new(config));
        let stopping = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (sender, receiver) = std::sync::mpsc::sync_channel(config.queue_capacity);
        let receiver = Arc::new(Mutex::new(receiver));
        Ok(Arc::new(Self {
            config,
            context,
            sender: Mutex::new(Some(sender)),
            receiver,
            workers: Mutex::new(Vec::new()),
            metrics,
            stopping,
        }))
    }

    fn ensure_workers(&self) -> io::Result<()> {
        let mut workers = self
            .workers
            .lock()
            .map_err(|_| io::Error::other("geodata update worker lock poisoned"))?;
        if !workers.is_empty() {
            return Ok(());
        }
        let mut started = Vec::with_capacity(self.config.worker_count);
        for index in 0..self.config.worker_count {
            match start_product_geodata_update_worker(
                index,
                self.config,
                self.context.clone(),
                Arc::clone(&self.receiver),
                Arc::clone(&self.metrics),
                Arc::clone(&self.stopping),
            ) {
                Ok(worker) => started.push(worker),
                Err(error) => {
                    self.stopping.store(true, Ordering::Release);
                    for worker in started {
                        worker.join_if_finished();
                    }
                    return Err(error);
                }
            }
        }
        *workers = started;
        Ok(())
    }

    pub(in crate::daed_product) fn submit(
        &self,
        kind: GeodataKind,
        stream: TcpStream,
        request: HttpRequest,
        http_metrics: Arc<ProductHttpMetrics>,
    ) -> Result<(), Box<ProductGeodataUpdateSubmissionError>> {
        if self.stopping.load(Ordering::Acquire) {
            self.metrics.rejected_unavailable();
            return Err(submission_error(
                stream,
                request,
                503,
                "geodata update runtime is unavailable",
            ));
        }
        if let Err(error) = self.ensure_workers() {
            self.metrics.rejected_unavailable();
            return Err(submission_error(
                stream,
                request,
                503,
                &format!("geodata update runtime is unavailable: {error}"),
            ));
        }
        let lease = match self.context.updates.acquire(kind) {
            Ok(lease) => lease,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                self.metrics.rejected_same_kind();
                return Err(Box::new(ProductGeodataUpdateSubmissionError {
                    stream,
                    request,
                    response: geodata_update_http_response(kind, Err(error)),
                }));
            }
            Err(error) => {
                self.metrics.rejected_unavailable();
                return Err(submission_error(
                    stream,
                    request,
                    503,
                    &format!("geodata update runtime is unavailable: {error}"),
                ));
            }
        };
        let sender = match self
            .sender
            .lock()
            .ok()
            .and_then(|sender| sender.as_ref().cloned())
        {
            Some(sender) => sender,
            None => {
                self.metrics.rejected_unavailable();
                drop(lease);
                return Err(submission_error(
                    stream,
                    request,
                    503,
                    "geodata update runtime is unavailable",
                ));
            }
        };
        let generation = self.metrics.submitted(kind);
        let job = ProductGeodataUpdateJob {
            stream,
            request,
            kind,
            generation,
            lease,
            http_metrics,
        };
        self.metrics.enqueued();
        match sender.try_send(job) {
            Ok(()) => Ok(()),
            Err(std::sync::mpsc::TrySendError::Full(job)) => {
                self.metrics.dequeue_rollback(kind, generation);
                self.metrics.rejected_capacity();
                Err(job.into_submission_error(503, "geodata update queue is full; retry later"))
            }
            Err(std::sync::mpsc::TrySendError::Disconnected(job)) => {
                self.metrics.dequeue_rollback(kind, generation);
                self.metrics.rejected_unavailable();
                Err(job.into_submission_error(503, "geodata update runtime is unavailable"))
            }
        }
    }

    pub(in crate::daed_product) fn snapshot(&self) -> Value {
        self.metrics.snapshot(self.config)
    }

    pub(in crate::daed_product) fn startup_fields(&self) -> BTreeMap<String, String> {
        let mut fields = BTreeMap::new();
        let active_workers = self.workers.lock().ok().map_or(0, |workers| workers.len());
        fields.insert(
            "geodataUpdateWorkers".to_owned(),
            self.config.worker_count.to_string(),
        );
        fields.insert(
            "geodataUpdateWorkersActive".to_owned(),
            active_workers.to_string(),
        );
        fields.insert(
            "geodataUpdateQueueCapacity".to_owned(),
            self.config.queue_capacity.to_string(),
        );
        fields
    }

    pub(in crate::daed_product) fn shutdown(&self) -> io::Result<()> {
        self.stopping.store(true, Ordering::Release);
        self.sender
            .lock()
            .map_err(|_| io::Error::other("geodata update sender lock poisoned"))?
            .take();
        let deadline = Instant::now()
            .checked_add(self.config.shutdown_timeout)
            .unwrap_or_else(Instant::now);
        let workers = std::mem::take(
            &mut *self
                .workers
                .lock()
                .map_err(|_| io::Error::other("geodata update worker lock poisoned"))?,
        );
        join_product_geodata_update_workers(workers, deadline, &self.metrics);
        Ok(())
    }
}

impl std::fmt::Debug for ProductGeodataUpdateRuntime {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProductGeodataUpdateRuntime")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl Drop for ProductGeodataUpdateRuntime {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

fn submission_error(
    stream: TcpStream,
    request: HttpRequest,
    status: u16,
    message: &str,
) -> Box<ProductGeodataUpdateSubmissionError> {
    Box::new(ProductGeodataUpdateSubmissionError {
        stream,
        request,
        response: HttpResponse::json(status, json!({"error": message})),
    })
}
