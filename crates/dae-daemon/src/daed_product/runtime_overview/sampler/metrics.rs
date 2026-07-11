use super::*;

#[derive(Debug, Default)]
pub(super) struct ProductRuntimeSamplerMetrics {
    interval_millis: AtomicU64,
    retention_seconds: AtomicU64,
    history_capacity: AtomicU64,
    sample_total: AtomicU64,
    process_read_failure_total: AtomicU64,
    schedule_miss_total: AtomicU64,
    runtime_joined_total: AtomicU64,
    runtime_detached_total: AtomicU64,
}

impl ProductRuntimeSamplerMetrics {
    pub(super) fn configure(&self, config: ProductRuntimeSamplerConfig) {
        self.interval_millis.store(
            u64::try_from(config.interval.as_millis()).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
        self.retention_seconds
            .store(config.retention.as_secs(), Ordering::Relaxed);
        self.history_capacity
            .store(config.history_capacity as u64, Ordering::Relaxed);
    }

    pub(super) fn sampled(&self) {
        self.sample_total.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn process_read_failed(&self) {
        self.process_read_failure_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn schedule_missed(&self) {
        self.schedule_miss_total.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn runtime_joined(&self) {
        self.runtime_joined_total.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn runtime_detached(&self) {
        self.runtime_detached_total.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn snapshot(&self, history_length: usize) -> Value {
        json!({
            "intervalMillis": self.interval_millis.load(Ordering::Relaxed),
            "retentionSeconds": self.retention_seconds.load(Ordering::Relaxed),
            "historyCapacity": self.history_capacity.load(Ordering::Relaxed),
            "historyLength": history_length,
            "sampleTotal": self.sample_total.load(Ordering::Relaxed),
            "processReadFailureTotal": self.process_read_failure_total.load(Ordering::Relaxed),
            "scheduleMissTotal": self.schedule_miss_total.load(Ordering::Relaxed),
            "runtimeJoinedTotal": self.runtime_joined_total.load(Ordering::Relaxed),
            "runtimeDetachedTotal": self.runtime_detached_total.load(Ordering::Relaxed),
        })
    }
}
