use super::*;

#[derive(Debug, Default)]
pub(super) struct ProductLogRuntimeMetrics {
    queue_capacity: AtomicU64,
    queue_depth: AtomicU64,
    submitted_total: AtomicU64,
    completed_total: AtomicU64,
    rejected_total: AtomicU64,
    failed_total: AtomicU64,
    appended_total: AtomicU64,
    filtered_total: AtomicU64,
    prune_total: AtomicU64,
    runtime_joined_total: AtomicU64,
    runtime_detached_total: AtomicU64,
}

macro_rules! counters {
    ($($method:ident => $field:ident,)*) => {$(
        pub(super) fn $method(&self) { self.$field.fetch_add(1, Ordering::Relaxed); }
    )*};
}

impl ProductLogRuntimeMetrics {
    pub(super) fn configure(&self, config: ProductLogRuntimeConfig) {
        self.queue_capacity
            .store(config.queue_capacity as u64, Ordering::Relaxed);
    }

    pub(super) fn enqueued(&self) {
        self.submitted_total.fetch_add(1, Ordering::Relaxed);
        self.queue_depth.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn enqueue_rollback(&self) {
        self.dequeued();
        self.rejected_total.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn dequeued(&self) {
        let _ = self
            .queue_depth
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |depth| {
                Some(depth.saturating_sub(1))
            });
    }

    counters! {
        completed => completed_total,
        failed => failed_total,
        appended => appended_total,
        filtered => filtered_total,
        pruned => prune_total,
        runtime_joined => runtime_joined_total,
        runtime_detached => runtime_detached_total,
    }

    pub(super) fn snapshot(&self) -> Value {
        json!({
            "queueCapacity": self.queue_capacity.load(Ordering::Relaxed),
            "queueDepth": self.queue_depth.load(Ordering::Relaxed),
            "submittedTotal": self.submitted_total.load(Ordering::Relaxed),
            "completedTotal": self.completed_total.load(Ordering::Relaxed),
            "rejectedTotal": self.rejected_total.load(Ordering::Relaxed),
            "failedTotal": self.failed_total.load(Ordering::Relaxed),
            "appendedTotal": self.appended_total.load(Ordering::Relaxed),
            "filteredTotal": self.filtered_total.load(Ordering::Relaxed),
            "pruneTotal": self.prune_total.load(Ordering::Relaxed),
            "runtimeJoinedTotal": self.runtime_joined_total.load(Ordering::Relaxed),
            "runtimeDetachedTotal": self.runtime_detached_total.load(Ordering::Relaxed),
        })
    }
}
