use super::*;

const PRODUCT_RUNTIME_SAMPLE_INTERVAL: Duration = Duration::from_secs(1);
const PRODUCT_RUNTIME_SAMPLE_RETENTION: Duration = Duration::from_secs(60 * 60);
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
        Self::new(
            PRODUCT_RUNTIME_SAMPLE_INTERVAL,
            PRODUCT_RUNTIME_SAMPLE_RETENTION,
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
