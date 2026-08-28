use super::*;

mod admission;
use self::admission::*;
mod config;
use self::config::*;
mod group_selection_events;
use self::group_selection_events::RuntimeGroupSelectionEventTracker;
pub(in crate::daed_product) use self::group_selection_events::{
    RUNTIME_GROUP_SELECTION_EVENT, initial_group_selection_event,
};
mod overview_feed;
use self::overview_feed::*;
mod stream_io;
use self::stream_io::*;
mod streams;
use self::streams::*;
mod worker;
use self::worker::*;
#[cfg(test)]
mod tests;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ProductSseStreamKind {
    Logs,
    Runtime,
}

pub(super) struct ProductSseJob {
    stream: TcpStream,
    request: HttpRequest,
    kind: ProductSseStreamKind,
    admission: ProductSseAdmissionLease,
    ui_session: Option<ProductUiStreamLease>,
    overview: Option<tokio::sync::broadcast::Receiver<Arc<ProductRuntimeOverviewTick>>>,
    http_metrics: Arc<ProductHttpMetrics>,
}

impl ProductSseJob {
    fn into_submission_error(self, status: u16, message: &str) -> Box<ProductSseSubmissionError> {
        let Self {
            stream,
            request,
            admission,
            ui_session,
            overview,
            ..
        } = self;
        drop(admission);
        drop(ui_session);
        drop(overview);
        Box::new(ProductSseSubmissionError {
            stream,
            request,
            response: HttpResponse::json(status, json!({"error": message})),
        })
    }

    fn close_queued(self) {
        self.http_metrics.closed();
    }
}

#[derive(Debug)]
pub(super) struct ProductSseSubmissionError {
    pub(super) stream: TcpStream,
    pub(super) request: HttpRequest,
    pub(super) response: HttpResponse,
}

pub(super) struct ProductSseRuntime {
    config: ProductSseRuntimeConfig,
    app: std::sync::Weak<AppState>,
    sender: Mutex<Option<tokio::sync::mpsc::Sender<ProductSseJob>>>,
    receiver: Mutex<Option<tokio::sync::mpsc::Receiver<ProductSseJob>>>,
    stop: tokio::sync::watch::Sender<bool>,
    worker: Mutex<Option<ProductSseWorkerHandle>>,
    admission: Arc<ProductSseAdmission>,
    metrics: Arc<ProductHttpMetrics>,
    overview: tokio::sync::broadcast::Sender<Arc<ProductRuntimeOverviewTick>>,
    overview_full_cache: Arc<ProductRuntimeOverviewFullCache>,
}

impl ProductSseRuntime {
    pub(super) fn start(
        http_config: ProductHttpWorkerConfig,
        app: std::sync::Weak<AppState>,
        metrics: Arc<ProductHttpMetrics>,
    ) -> io::Result<Arc<Self>> {
        let config = ProductSseRuntimeConfig::from_http_config(http_config);
        if let Some(app) = app.upgrade() {
            app.ui_runtime
                .configure(config.connection_limit, config.per_user_limit);
        }
        Self::start_with_config(config, app, metrics)
    }

    fn start_with_config(
        config: ProductSseRuntimeConfig,
        app: std::sync::Weak<AppState>,
        metrics: Arc<ProductHttpMetrics>,
    ) -> io::Result<Arc<Self>> {
        metrics.configure_sse(
            config.connection_limit,
            config.per_user_limit,
            config.queue_capacity,
            config.worker_stack_bytes,
        );
        let admission = Arc::new(ProductSseAdmission::new(config));
        let (sender, receiver) = tokio::sync::mpsc::channel(config.queue_capacity);
        let (overview, _) = runtime_overview_feed();
        let overview_full_cache = Arc::new(ProductRuntimeOverviewFullCache::default());
        let (stop, _) = tokio::sync::watch::channel(false);
        Ok(Arc::new(Self {
            config,
            app,
            sender: Mutex::new(Some(sender)),
            receiver: Mutex::new(Some(receiver)),
            stop,
            worker: Mutex::new(None),
            admission,
            metrics,
            overview,
            overview_full_cache,
        }))
    }

    fn ensure_worker(&self) -> io::Result<()> {
        let mut worker = self
            .worker
            .lock()
            .map_err(|_| io::Error::other("SSE worker lock poisoned"))?;
        if worker.is_some() {
            return Ok(());
        }
        let receiver = self
            .receiver
            .lock()
            .map_err(|_| io::Error::other("SSE receiver lock poisoned"))?
            .take()
            .ok_or_else(|| io::Error::other("SSE receiver is unavailable"))?;
        let stop_receiver = self.stop.subscribe();
        let started = start_product_sse_worker(
            self.config,
            self.app.clone(),
            receiver,
            stop_receiver,
            Arc::clone(&self.metrics),
            self.overview.clone(),
            Arc::clone(&self.overview_full_cache),
        )?;
        *worker = Some(started);
        Ok(())
    }

    pub(super) fn submit(
        &self,
        user_id: i64,
        kind: ProductSseStreamKind,
        stream: TcpStream,
        request: HttpRequest,
        http_metrics: Arc<ProductHttpMetrics>,
        ui_runtime: &Arc<ProductUiRuntime>,
    ) -> Result<(), Box<ProductSseSubmissionError>> {
        if *self.stop.borrow() {
            self.metrics.sse_rejected_unavailable();
            return Err(Box::new(ProductSseSubmissionError {
                stream,
                request,
                response: HttpResponse::json(503, json!({"error": "SSE runtime is unavailable"})),
            }));
        }
        if let Err(error) = self.ensure_worker() {
            self.metrics.sse_rejected_unavailable();
            return Err(Box::new(ProductSseSubmissionError {
                stream,
                request,
                response: HttpResponse::json(503, json!({"error": error.to_string()})),
            }));
        }
        let admission = match self.admission.acquire(user_id) {
            Ok(lease) => lease,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                self.metrics.sse_rejected_limit();
                return Err(Box::new(ProductSseSubmissionError {
                    stream,
                    request,
                    response: HttpResponse::json(429, json!({"error": error.to_string()})),
                }));
            }
            Err(error) => {
                self.metrics.sse_rejected_unavailable();
                return Err(Box::new(ProductSseSubmissionError {
                    stream,
                    request,
                    response: HttpResponse::json(503, json!({"error": error.to_string()})),
                }));
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
                self.metrics.sse_rejected_unavailable();
                drop(admission);
                return Err(Box::new(ProductSseSubmissionError {
                    stream,
                    request,
                    response: HttpResponse::json(
                        503,
                        json!({"error": "SSE runtime is unavailable"}),
                    ),
                }));
            }
        };
        let ui_session = match ui_runtime.open_stream(user_id, &request) {
            Ok(session) => session,
            Err(error) => {
                drop(admission);
                let status = match error.kind() {
                    io::ErrorKind::InvalidInput => 400,
                    io::ErrorKind::WouldBlock => 429,
                    _ => 503,
                };
                return Err(Box::new(ProductSseSubmissionError {
                    stream,
                    request,
                    response: HttpResponse::json(status, json!({"error": error.to_string()})),
                }));
            }
        };
        let job = ProductSseJob {
            stream,
            request,
            kind,
            admission,
            ui_session,
            overview: matches!(kind, ProductSseStreamKind::Runtime)
                .then(|| self.overview.subscribe()),
            http_metrics,
        };
        self.metrics.sse_enqueued();
        match sender.try_send(job) {
            Ok(()) => Ok(()),
            Err(tokio::sync::mpsc::error::TrySendError::Full(job)) => {
                self.metrics.sse_submission_rollback();
                self.metrics.sse_rejected_capacity();
                Err(job.into_submission_error(503, "SSE queue is full; retry later"))
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(job)) => {
                self.metrics.sse_submission_rollback();
                self.metrics.sse_rejected_unavailable();
                Err(job.into_submission_error(503, "SSE runtime is unavailable"))
            }
        }
    }

    pub(super) fn startup_fields(&self) -> BTreeMap<String, String> {
        let mut fields = BTreeMap::new();
        let workers = self
            .worker
            .lock()
            .ok()
            .map(|worker| usize::from(worker.is_some()))
            .unwrap_or(0);
        fields.insert("sseRuntimeWorkers".to_owned(), workers.to_string());
        fields.insert(
            "sseConnectionLimit".to_owned(),
            self.config.connection_limit.to_string(),
        );
        fields.insert(
            "ssePerUserLimit".to_owned(),
            self.config.per_user_limit.to_string(),
        );
        fields.insert(
            "sseQueueCapacity".to_owned(),
            self.config.queue_capacity.to_string(),
        );
        fields
    }
}

impl std::fmt::Debug for ProductSseRuntime {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProductSseRuntime")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl Drop for ProductSseRuntime {
    fn drop(&mut self) {
        self.sender
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        let _ = self.stop.send(true);
        let worker = self
            .worker
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        let Some(worker) = worker else {
            return;
        };
        if worker.join_until(
            Instant::now()
                .checked_add(self.config.shutdown_timeout)
                .unwrap_or_else(Instant::now),
        ) {
            self.metrics.sse_runtime_joined();
        } else {
            self.metrics.sse_runtime_detached();
        }
    }
}
