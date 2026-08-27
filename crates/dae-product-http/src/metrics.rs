use super::*;
use dae_product_core::ProductHttpWorkerConfig;

#[derive(Debug, Default)]
pub struct ProductHttpRequestReadMetrics {
    idle_header_timeout_total: AtomicU64,
    partial_header_timeout_total: AtomicU64,
    body_timeout_total: AtomicU64,
    connection_closed_total: AtomicU64,
    invalid_request_total: AtomicU64,
    io_error_total: AtomicU64,
}

impl ProductHttpRequestReadMetrics {
    pub fn record(&self, kind: HttpRequestReadErrorKind) {
        let counter = match kind {
            HttpRequestReadErrorKind::IdleHeaderTimeout => &self.idle_header_timeout_total,
            HttpRequestReadErrorKind::PartialHeaderTimeout => &self.partial_header_timeout_total,
            HttpRequestReadErrorKind::BodyTimeout => &self.body_timeout_total,
            HttpRequestReadErrorKind::ConnectionClosed => &self.connection_closed_total,
            HttpRequestReadErrorKind::InvalidRequest => &self.invalid_request_total,
            HttpRequestReadErrorKind::Io => &self.io_error_total,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> Value {
        json!({
            "idleHeaderTimeoutTotal": self.idle_header_timeout_total.load(Ordering::Relaxed),
            "partialHeaderTimeoutTotal": self.partial_header_timeout_total.load(Ordering::Relaxed),
            "bodyTimeoutTotal": self.body_timeout_total.load(Ordering::Relaxed),
            "connectionClosedTotal": self.connection_closed_total.load(Ordering::Relaxed),
            "invalidRequestTotal": self.invalid_request_total.load(Ordering::Relaxed),
            "ioErrorTotal": self.io_error_total.load(Ordering::Relaxed),
        })
    }
}

#[derive(Debug, Default)]
pub struct ProductHttpMetrics {
    configured_workers: AtomicU64,
    queue_capacity: AtomicU64,
    worker_stack_bytes: AtomicU64,
    active_connections: AtomicU64,
    active_sse_connections: AtomicU64,
    accepted_total: AtomicU64,
    enqueued_total: AtomicU64,
    rejected_total: AtomicU64,
    worker_panicked_total: AtomicU64,
    queue_depth: AtomicU64,
    sse_connection_limit: AtomicU64,
    sse_per_user_limit: AtomicU64,
    sse_queue_capacity: AtomicU64,
    sse_worker_stack_bytes: AtomicU64,
    sse_queue_depth: AtomicU64,
    sse_submitted_total: AtomicU64,
    sse_completed_total: AtomicU64,
    sse_rejected_limit_total: AtomicU64,
    sse_rejected_capacity_total: AtomicU64,
    sse_rejected_unavailable_total: AtomicU64,
    sse_runtime_joined_total: AtomicU64,
    sse_runtime_detached_total: AtomicU64,
    pub request_read: ProductHttpRequestReadMetrics,
}

impl ProductHttpMetrics {
    pub fn configure(&self, config: ProductHttpWorkerConfig) {
        self.configured_workers
            .store(config.worker_count as u64, Ordering::Relaxed);
        self.queue_capacity
            .store(config.queue_capacity as u64, Ordering::Relaxed);
        self.worker_stack_bytes
            .store(config.worker_stack_bytes as u64, Ordering::Relaxed);
    }

    pub fn accepted(&self) {
        self.accepted_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn configure_sse(
        &self,
        connection_limit: usize,
        per_user_limit: usize,
        queue_capacity: usize,
        worker_stack_bytes: usize,
    ) {
        self.sse_connection_limit
            .store(connection_limit as u64, Ordering::Relaxed);
        self.sse_per_user_limit
            .store(per_user_limit as u64, Ordering::Relaxed);
        self.sse_queue_capacity
            .store(queue_capacity as u64, Ordering::Relaxed);
        self.sse_worker_stack_bytes
            .store(worker_stack_bytes as u64, Ordering::Relaxed);
    }

    pub fn enqueued(&self) {
        self.enqueued_total.fetch_add(1, Ordering::Relaxed);
        self.queue_depth.fetch_add(1, Ordering::Relaxed);
    }

    pub fn dequeued(&self) {
        let _ = self
            .queue_depth
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |depth| {
                Some(depth.saturating_sub(1))
            });
    }

    pub fn rejected(&self) {
        self.rejected_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn worker_panicked(&self) {
        self.worker_panicked_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn opened(&self) {
        self.active_connections.fetch_add(1, Ordering::Relaxed);
    }

    pub fn closed(&self) {
        let _ = self.active_connections.fetch_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |connections| Some(connections.saturating_sub(1)),
        );
    }

    pub fn sse_opened(&self) {
        self.active_sse_connections.fetch_add(1, Ordering::Relaxed);
    }

    pub fn sse_closed(&self) {
        let _ = self.active_sse_connections.fetch_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |connections| Some(connections.saturating_sub(1)),
        );
    }

    pub fn sse_enqueued(&self) {
        self.sse_submitted_total.fetch_add(1, Ordering::Relaxed);
        self.sse_queue_depth.fetch_add(1, Ordering::Relaxed);
    }

    pub fn sse_dequeued(&self) {
        let _ = self
            .sse_queue_depth
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |depth| {
                Some(depth.saturating_sub(1))
            });
        self.sse_opened();
    }

    pub fn sse_submission_rollback(&self) {
        let _ = self
            .sse_queue_depth
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |depth| {
                Some(depth.saturating_sub(1))
            });
    }

    pub fn sse_completed(&self) {
        self.sse_closed();
        self.sse_completed_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn sse_rejected_limit(&self) {
        self.sse_rejected_limit_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn sse_rejected_capacity(&self) {
        self.sse_rejected_capacity_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn sse_rejected_unavailable(&self) {
        self.sse_rejected_unavailable_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn sse_runtime_joined(&self) {
        self.sse_runtime_joined_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn sse_runtime_detached(&self) {
        self.sse_runtime_detached_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> Value {
        json!({
            "configuredWorkers": self.configured_workers.load(Ordering::Relaxed),
            "queueCapacity": self.queue_capacity.load(Ordering::Relaxed),
            "workerStackBytes": self.worker_stack_bytes.load(Ordering::Relaxed),
            "activeConnections": self.active_connections.load(Ordering::Relaxed),
            "activeSseConnections": self.active_sse_connections.load(Ordering::Relaxed),
            "acceptedTotal": self.accepted_total.load(Ordering::Relaxed),
            "enqueuedTotal": self.enqueued_total.load(Ordering::Relaxed),
            "rejectedTotal": self.rejected_total.load(Ordering::Relaxed),
            "workerPanickedTotal": self.worker_panicked_total.load(Ordering::Relaxed),
            "queueDepth": self.queue_depth.load(Ordering::Relaxed),
            "requestRead": self.request_read.snapshot(),
            "sseRuntime": {
                "connectionLimit": self.sse_connection_limit.load(Ordering::Relaxed),
                "perUserLimit": self.sse_per_user_limit.load(Ordering::Relaxed),
                "queueCapacity": self.sse_queue_capacity.load(Ordering::Relaxed),
                "workerStackBytes": self.sse_worker_stack_bytes.load(Ordering::Relaxed),
                "queueDepth": self.sse_queue_depth.load(Ordering::Relaxed),
                "submittedTotal": self.sse_submitted_total.load(Ordering::Relaxed),
                "completedTotal": self.sse_completed_total.load(Ordering::Relaxed),
                "rejectedLimitTotal": self.sse_rejected_limit_total.load(Ordering::Relaxed),
                "rejectedCapacityTotal": self.sse_rejected_capacity_total.load(Ordering::Relaxed),
                "rejectedUnavailableTotal": self.sse_rejected_unavailable_total.load(Ordering::Relaxed),
                "runtimeJoinedTotal": self.sse_runtime_joined_total.load(Ordering::Relaxed),
                "runtimeDetachedTotal": self.sse_runtime_detached_total.load(Ordering::Relaxed),
            },
        })
    }

    pub fn is_idle(&self) -> bool {
        self.active_connections.load(Ordering::Acquire) == 0
            && self.active_sse_connections.load(Ordering::Acquire) == 0
            && self.queue_depth.load(Ordering::Acquire) == 0
            && self.sse_queue_depth.load(Ordering::Acquire) == 0
    }

    pub fn active_connection_count(&self) -> u64 {
        self.active_connections.load(Ordering::Acquire)
    }
}
