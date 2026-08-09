use super::*;

const PRODUCT_RUNTIME_SAMPLE_INTERVAL: Duration = Duration::from_secs(1);
const PRODUCT_RUNTIME_SAMPLE_RETENTION: Duration = Duration::from_secs(15 * 60);
const PRODUCT_RUNTIME_LOW_MEMORY_SAMPLE_RETENTION: Duration = Duration::from_secs(5 * 60);
const PRODUCT_RUNTIME_STANDARD_HISTORY_CAPACITY: usize = 1_000;
const PRODUCT_RUNTIME_LOW_MEMORY_HISTORY_CAPACITY: usize = 360;
const PRODUCT_RUNTIME_SAMPLER_STACK_BYTES: usize = 512 * 1024;
const PRODUCT_RUNTIME_SAMPLER_START_TIMEOUT: Duration = Duration::from_secs(5);
const PRODUCT_RUNTIME_SAMPLER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug)]
pub(super) struct ProductRuntimeSamplerConfig {
    pub(super) interval: Duration,
    pub(super) retention: Duration,
    pub(super) history_capacity: usize,
    pub(super) worker_stack_bytes: usize,
    pub(super) start_timeout: Duration,
    pub(super) shutdown_timeout: Duration,
}

impl ProductRuntimeSamplerConfig {
    pub(super) fn product_default() -> Self {
        let profile = ProductHttpProfile::from_env().0;
        let (retention, history_capacity) = match profile {
            ProductHttpProfile::Standard => (
                PRODUCT_RUNTIME_SAMPLE_RETENTION,
                PRODUCT_RUNTIME_STANDARD_HISTORY_CAPACITY,
            ),
            ProductHttpProfile::LowMemory => (
                PRODUCT_RUNTIME_LOW_MEMORY_SAMPLE_RETENTION,
                PRODUCT_RUNTIME_LOW_MEMORY_HISTORY_CAPACITY,
            ),
        };
        Self::with_history_capacity(
            PRODUCT_RUNTIME_SAMPLE_INTERVAL,
            retention,
            history_capacity,
            PRODUCT_RUNTIME_SAMPLER_STACK_BYTES,
            PRODUCT_RUNTIME_SAMPLER_START_TIMEOUT,
            PRODUCT_RUNTIME_SAMPLER_SHUTDOWN_TIMEOUT,
        )
    }

    fn new(
        interval: Duration,
        retention: Duration,
        worker_stack_bytes: usize,
        start_timeout: Duration,
        shutdown_timeout: Duration,
    ) -> Self {
        let interval_millis = interval.as_millis().max(1);
        let retention_millis = retention.as_millis();
        let history_capacity = usize::try_from(retention_millis / interval_millis)
            .unwrap_or(usize::MAX)
            .saturating_add(2)
            .max(2);
        Self {
            interval,
            retention,
            history_capacity,
            worker_stack_bytes,
            start_timeout,
            shutdown_timeout,
        }
    }

    fn with_history_capacity(
        interval: Duration,
        retention: Duration,
        history_capacity: usize,
        worker_stack_bytes: usize,
        start_timeout: Duration,
        shutdown_timeout: Duration,
    ) -> Self {
        let mut config = Self::new(
            interval,
            retention,
            worker_stack_bytes,
            start_timeout,
            shutdown_timeout,
        );
        config.history_capacity = history_capacity.max(2);
        config
    }

    #[cfg(test)]
    pub(super) fn for_test() -> Self {
        Self::new(
            Duration::from_millis(20),
            Duration::from_secs(1),
            PRODUCT_RUNTIME_SAMPLER_STACK_BYTES,
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
    }
}
