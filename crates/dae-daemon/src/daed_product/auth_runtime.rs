use super::*;

mod admission;
use self::admission::*;
mod config;
use self::config::*;
mod metrics;
use self::metrics::*;
mod worker;
use self::worker::*;
#[cfg(test)]
mod tests;

type ProductAuthAction = Box<dyn FnOnce() -> ProductAuthJobOutcome + Send + 'static>;

pub(in crate::daed_product) struct ProductAuthJobOutcome {
    response: HttpResponse,
    attempt: ProductAuthAttemptOutcome,
}

impl ProductAuthJobOutcome {
    pub(in crate::daed_product) fn success(response: HttpResponse) -> Self {
        Self {
            response,
            attempt: ProductAuthAttemptOutcome::Success,
        }
    }

    pub(in crate::daed_product) fn credential_failure(response: HttpResponse) -> Self {
        Self {
            response,
            attempt: ProductAuthAttemptOutcome::CredentialFailure,
        }
    }

    pub(in crate::daed_product) fn neutral(response: HttpResponse) -> Self {
        Self {
            response,
            attempt: ProductAuthAttemptOutcome::Neutral,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProductAuthAttemptOutcome {
    Success,
    CredentialFailure,
    Neutral,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::daed_product) enum ProductAuthExecutionError {
    Busy { retry_after: Duration },
    Unavailable,
    TimedOut,
}

pub(in crate::daed_product) struct ProductAuthRuntime {
    config: ProductAuthRuntimeConfig,
    sender: Mutex<Option<std::sync::mpsc::SyncSender<ProductAuthJob>>>,
    workers: Mutex<Vec<ProductAuthWorkerHandle>>,
    admission: Arc<ProductAuthAdmission>,
    metrics: Arc<ProductAuthMetrics>,
    stopping: Arc<std::sync::atomic::AtomicBool>,
}

impl ProductAuthRuntime {
    pub(in crate::daed_product) fn start_for_http_config(
        http_config: ProductHttpWorkerConfig,
    ) -> io::Result<Arc<Self>> {
        Self::start(ProductAuthRuntimeConfig::from_http_config(http_config))
    }

    fn start(config: ProductAuthRuntimeConfig) -> io::Result<Arc<Self>> {
        let admission = Arc::new(ProductAuthAdmission::new(config));
        let metrics = Arc::new(ProductAuthMetrics::new(config));
        let stopping = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (sender, receiver) = std::sync::mpsc::sync_channel(config.queue_capacity);
        let receiver = Arc::new(Mutex::new(receiver));
        let mut workers = Vec::with_capacity(config.worker_count);
        for index in 0..config.worker_count {
            match start_product_auth_worker(
                index,
                config,
                Arc::clone(&receiver),
                Arc::clone(&metrics),
                Arc::clone(&stopping),
            ) {
                Ok(worker) => workers.push(worker),
                Err(error) => {
                    stopping.store(true, Ordering::Release);
                    drop(sender);
                    for worker in workers {
                        worker.join_if_finished();
                    }
                    return Err(error);
                }
            }
        }
        Ok(Arc::new(Self {
            config,
            sender: Mutex::new(Some(sender)),
            workers: Mutex::new(workers),
            admission,
            metrics,
            stopping,
        }))
    }

    pub(in crate::daed_product) fn execute<F>(
        &self,
        source: Option<IpAddr>,
        username: &str,
        action: F,
    ) -> Result<HttpResponse, ProductAuthExecutionError>
    where
        F: FnOnce() -> ProductAuthJobOutcome + Send + 'static,
    {
        if self.stopping.load(Ordering::Acquire) {
            return Err(ProductAuthExecutionError::Unavailable);
        }
        let lease = match self.admission.acquire(source, username) {
            Ok(lease) => lease,
            Err(ProductAuthAdmissionRejection::Capacity) => {
                self.metrics.rejected_capacity();
                return Err(ProductAuthExecutionError::Busy {
                    retry_after: self.config.capacity_retry_after,
                });
            }
            Err(ProductAuthAdmissionRejection::Backoff(retry_after)) => {
                self.metrics.rejected_backoff();
                return Err(ProductAuthExecutionError::Busy { retry_after });
            }
            Err(ProductAuthAdmissionRejection::Unavailable) => {
                self.metrics.rejected_unavailable();
                return Err(ProductAuthExecutionError::Unavailable);
            }
        };
        let sender = self
            .sender
            .lock()
            .ok()
            .and_then(|sender| sender.as_ref().cloned())
            .ok_or(ProductAuthExecutionError::Unavailable)?;
        let (response_sender, response_receiver) = std::sync::mpsc::sync_channel(1);
        let job = ProductAuthJob {
            action: Some(Box::new(action) as ProductAuthAction),
            response: response_sender,
            lease,
        };
        self.metrics.submitted();
        self.metrics.enqueued();
        match sender.try_send(job) {
            Ok(()) => {}
            Err(std::sync::mpsc::TrySendError::Full(job)) => {
                self.metrics.dequeue_rollback();
                self.metrics.rejected_capacity();
                drop(job);
                return Err(ProductAuthExecutionError::Busy {
                    retry_after: self.config.capacity_retry_after,
                });
            }
            Err(std::sync::mpsc::TrySendError::Disconnected(job)) => {
                self.metrics.dequeue_rollback();
                self.metrics.rejected_unavailable();
                drop(job);
                return Err(ProductAuthExecutionError::Unavailable);
            }
        }
        match response_receiver.recv_timeout(self.config.job_timeout) {
            Ok(response) => Ok(response),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                self.metrics.wait_timed_out();
                Err(ProductAuthExecutionError::TimedOut)
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                self.metrics.rejected_unavailable();
                Err(ProductAuthExecutionError::Unavailable)
            }
        }
    }

    pub(in crate::daed_product) fn snapshot(&self) -> Value {
        self.metrics
            .snapshot(self.config, self.admission.snapshot())
    }

    pub(in crate::daed_product) fn startup_fields(&self) -> BTreeMap<String, String> {
        let mut fields = BTreeMap::new();
        fields.insert(
            "authWorkers".to_owned(),
            self.config.worker_count.to_string(),
        );
        fields.insert(
            "authQueueCapacity".to_owned(),
            self.config.queue_capacity.to_string(),
        );
        fields.insert(
            "authHttpWaiterLimit".to_owned(),
            self.config.waiter_limit.to_string(),
        );
        fields
    }
}

impl std::fmt::Debug for ProductAuthRuntime {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProductAuthRuntime")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl Drop for ProductAuthRuntime {
    fn drop(&mut self) {
        self.stopping.store(true, Ordering::Release);
        self.sender
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        let deadline = Instant::now()
            .checked_add(self.config.shutdown_timeout)
            .unwrap_or_else(Instant::now);
        let workers = std::mem::take(
            self.workers
                .get_mut()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        for worker in workers {
            if worker.join_until(deadline) {
                self.metrics.worker_joined();
            } else {
                self.metrics.worker_detached();
            }
        }
    }
}

#[cfg(test)]
pub(in crate::daed_product) fn product_test_auth_runtime() -> Arc<ProductAuthRuntime> {
    ProductAuthRuntime::start(ProductAuthRuntimeConfig::for_test())
        .expect("start product test auth runtime")
}

pub(in crate::daed_product) fn product_auth_defaults_json() -> Value {
    auth_defaults_json()
}
