use super::*;

pub(super) struct ProductAuthMetrics {
    configured_workers: u64,
    queue_capacity: u64,
    waiter_limit: u64,
    queue_depth: AtomicU64,
    active_workers: AtomicU64,
    submitted_total: AtomicU64,
    completed_total: AtomicU64,
    rejected_capacity_total: AtomicU64,
    rejected_backoff_total: AtomicU64,
    rejected_unavailable_total: AtomicU64,
    wait_timeout_total: AtomicU64,
    worker_panic_total: AtomicU64,
    workers_joined_total: AtomicU64,
    workers_detached_total: AtomicU64,
}

impl ProductAuthMetrics {
    pub(super) fn new(config: ProductAuthRuntimeConfig) -> Self {
        Self {
            configured_workers: config.worker_count as u64,
            queue_capacity: config.queue_capacity as u64,
            waiter_limit: config.waiter_limit as u64,
            queue_depth: AtomicU64::new(0),
            active_workers: AtomicU64::new(0),
            submitted_total: AtomicU64::new(0),
            completed_total: AtomicU64::new(0),
            rejected_capacity_total: AtomicU64::new(0),
            rejected_backoff_total: AtomicU64::new(0),
            rejected_unavailable_total: AtomicU64::new(0),
            wait_timeout_total: AtomicU64::new(0),
            worker_panic_total: AtomicU64::new(0),
            workers_joined_total: AtomicU64::new(0),
            workers_detached_total: AtomicU64::new(0),
        }
    }

    pub(super) fn submitted(&self) {
        self.submitted_total.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn enqueued(&self) {
        self.queue_depth.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn dequeued(&self) {
        decrement_saturating(&self.queue_depth);
        self.active_workers.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn dequeue_rollback(&self) {
        decrement_saturating(&self.queue_depth);
    }

    pub(super) fn completed(&self) {
        decrement_saturating(&self.active_workers);
        self.completed_total.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn rejected_capacity(&self) {
        self.rejected_capacity_total.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn rejected_backoff(&self) {
        self.rejected_backoff_total.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn rejected_unavailable(&self) {
        self.rejected_unavailable_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn wait_timed_out(&self) {
        self.wait_timeout_total.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn worker_panicked(&self) {
        self.worker_panic_total.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn worker_joined(&self) {
        self.workers_joined_total.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn worker_detached(&self) {
        self.workers_detached_total.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn snapshot(
        &self,
        config: ProductAuthRuntimeConfig,
        admission: ProductAuthAdmissionSnapshot,
    ) -> Value {
        json!({
            "profile": config.profile.name(),
            "configuredWorkers": self.configured_workers,
            "queueCapacity": self.queue_capacity,
            "httpWaiterLimit": self.waiter_limit,
            "perSourceLimit": config.per_source_limit,
            "perUsernameLimit": config.per_username_limit,
            "trackedKeyCapacity": config.tracked_key_capacity,
            "queueDepth": self.queue_depth.load(Ordering::Relaxed),
            "activeWorkers": self.active_workers.load(Ordering::Relaxed),
            "inFlight": admission.in_flight,
            "activeSources": admission.active_sources,
            "activeUsernames": admission.active_usernames,
            "trackedSourceBackoffs": admission.tracked_source_backoffs,
            "trackedUsernameBackoffs": admission.tracked_username_backoffs,
            "submittedTotal": self.submitted_total.load(Ordering::Relaxed),
            "completedTotal": self.completed_total.load(Ordering::Relaxed),
            "rejectedCapacityTotal": self.rejected_capacity_total.load(Ordering::Relaxed),
            "rejectedBackoffTotal": self.rejected_backoff_total.load(Ordering::Relaxed),
            "rejectedUnavailableTotal": self.rejected_unavailable_total.load(Ordering::Relaxed),
            "waitTimeoutTotal": self.wait_timeout_total.load(Ordering::Relaxed),
            "workerPanicTotal": self.worker_panic_total.load(Ordering::Relaxed),
            "workersJoinedTotal": self.workers_joined_total.load(Ordering::Relaxed),
            "workersDetachedTotal": self.workers_detached_total.load(Ordering::Relaxed),
        })
    }
}

fn decrement_saturating(value: &AtomicU64) {
    let _ = value.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
        Some(current.saturating_sub(1))
    });
}
