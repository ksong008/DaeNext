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
    worker_alive: AtomicBool,
    last_tick_at: AtomicU64,
    last_runtime_counter_at: AtomicU64,
    counter_read_failure_total: AtomicU64,
    generation_gap_total: AtomicU64,
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

    pub(super) fn worker_started(&self) {
        self.worker_alive.store(true, Ordering::Release);
    }

    pub(super) fn worker_stopped(&self) {
        self.worker_alive.store(false, Ordering::Release);
    }

    pub(super) fn tick(&self, timestamp: u64) {
        self.last_tick_at.store(timestamp, Ordering::Relaxed);
    }

    pub(super) fn runtime_counter_sampled(&self, timestamp: u64) {
        self.last_runtime_counter_at
            .store(timestamp, Ordering::Relaxed);
    }

    pub(super) fn state_lock_failed(&self) {
        self.counter_read_failure_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn generation_gap(&self) {
        self.generation_gap_total.fetch_add(1, Ordering::Relaxed);
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
            "workerAlive": self.worker_alive.load(Ordering::Acquire),
            "lastTickAt": optional_unix_timestamp(self.last_tick_at.load(Ordering::Relaxed)),
            "lastRuntimeCounterAt": optional_unix_timestamp(self.last_runtime_counter_at.load(Ordering::Relaxed)),
            "counterReadFailureTotal": self.counter_read_failure_total.load(Ordering::Relaxed),
            "generationGapTotal": self.generation_gap_total.load(Ordering::Relaxed),
        })
    }
}

fn optional_unix_timestamp(timestamp: u64) -> Value {
    if timestamp == 0 {
        Value::Null
    } else {
        json!(iso8601_utc(timestamp))
    }
}
