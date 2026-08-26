use super::*;

pub(super) struct ProductControlRuntimeMetrics {
    submitted_total: AtomicU64,
    enqueued_total: AtomicU64,
    queued_tasks: AtomicU64,
    active_tasks: AtomicU64,
    completed_total: AtomicU64,
    rejected_total: AtomicU64,
    timed_out_total: AtomicU64,
    cancelled_total: AtomicU64,
    panicked_total: AtomicU64,
    forced_shutdown_total: AtomicU64,
}

impl ProductControlRuntimeMetrics {
    pub(super) fn new() -> Self {
        Self {
            submitted_total: AtomicU64::new(0),
            enqueued_total: AtomicU64::new(0),
            queued_tasks: AtomicU64::new(0),
            active_tasks: AtomicU64::new(0),
            completed_total: AtomicU64::new(0),
            rejected_total: AtomicU64::new(0),
            timed_out_total: AtomicU64::new(0),
            cancelled_total: AtomicU64::new(0),
            panicked_total: AtomicU64::new(0),
            forced_shutdown_total: AtomicU64::new(0),
        }
    }

    pub(super) fn submitted(&self) {
        self.submitted_total.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn queued(&self) {
        self.queued_tasks.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn enqueued(&self) {
        self.enqueued_total.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn dequeued(&self) {
        let previous = self.queued_tasks.fetch_sub(1, Ordering::Relaxed);
        debug_assert!(previous > 0, "product control queued task underflow");
    }

    pub(super) fn rejected(&self) {
        self.rejected_total.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn timed_out(&self) {
        self.timed_out_total.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn cancelled(&self) {
        self.cancelled_total.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn panicked(&self) {
        self.panicked_total.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn forced(&self, count: usize) {
        self.forced_shutdown_total
            .fetch_add(count as u64, Ordering::Relaxed);
    }

    pub(super) fn active(self: &Arc<Self>) -> ProductControlActiveTask {
        self.active_tasks.fetch_add(1, Ordering::Relaxed);
        ProductControlActiveTask {
            metrics: Arc::clone(self),
        }
    }

    pub(super) fn snapshot(
        &self,
        config: ProductControlRuntimeConfig,
        admission: &ProductControlAdmission,
        stopping: bool,
        shutdown: Option<&Value>,
    ) -> Value {
        json!({
            "resources": config.json(),
            "activeByClass": admission.snapshot(),
            "activeTasks": self.active_tasks.load(Ordering::Relaxed),
            "queuedTasks": self.queued_tasks.load(Ordering::Relaxed),
            "submittedTotal": self.submitted_total.load(Ordering::Relaxed),
            "enqueuedTotal": self.enqueued_total.load(Ordering::Relaxed),
            "completedTotal": self.completed_total.load(Ordering::Relaxed),
            "rejectedTotal": self.rejected_total.load(Ordering::Relaxed),
            "timedOutTotal": self.timed_out_total.load(Ordering::Relaxed),
            "cancelledTotal": self.cancelled_total.load(Ordering::Relaxed),
            "panickedTotal": self.panicked_total.load(Ordering::Relaxed),
            "forcedShutdownTotal": self.forced_shutdown_total.load(Ordering::Relaxed),
            "shutdownState": if shutdown.is_some() {
                "stopped"
            } else if stopping {
                "stopping"
            } else {
                "running"
            },
            "stopping": stopping,
            "shutdown": shutdown.cloned().unwrap_or(Value::Null),
        })
    }
}

pub(super) struct ProductControlActiveTask {
    metrics: Arc<ProductControlRuntimeMetrics>,
}

impl Drop for ProductControlActiveTask {
    fn drop(&mut self) {
        self.metrics.active_tasks.fetch_sub(1, Ordering::Relaxed);
        self.metrics.completed_total.fetch_add(1, Ordering::Relaxed);
    }
}
