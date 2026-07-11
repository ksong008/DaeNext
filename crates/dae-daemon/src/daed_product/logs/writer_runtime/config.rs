use super::*;

const PRODUCT_LOG_STANDARD_QUEUE_CAPACITY: usize = 128;
const PRODUCT_LOG_LOW_MEMORY_QUEUE_CAPACITY: usize = 32;
const PRODUCT_LOG_WRITER_STACK_BYTES: usize = 512 * 1024;
const PRODUCT_LOG_SUBMIT_TIMEOUT: Duration = Duration::from_secs(5);
const PRODUCT_LOG_COMPLETION_TIMEOUT: Duration = Duration::from_secs(10);
const PRODUCT_LOG_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug)]
pub(super) struct ProductLogRuntimeConfig {
    pub(super) queue_capacity: usize,
    pub(super) worker_stack_bytes: usize,
    pub(super) submit_timeout: Duration,
    pub(super) completion_timeout: Duration,
    pub(super) shutdown_timeout: Duration,
}

impl ProductLogRuntimeConfig {
    pub(super) fn from_environment() -> Self {
        let (profile, _) = ProductHttpProfile::from_env();
        let queue_capacity = match profile {
            ProductHttpProfile::Standard => PRODUCT_LOG_STANDARD_QUEUE_CAPACITY,
            ProductHttpProfile::LowMemory => PRODUCT_LOG_LOW_MEMORY_QUEUE_CAPACITY,
        };
        Self {
            queue_capacity,
            worker_stack_bytes: PRODUCT_LOG_WRITER_STACK_BYTES,
            submit_timeout: PRODUCT_LOG_SUBMIT_TIMEOUT,
            completion_timeout: PRODUCT_LOG_COMPLETION_TIMEOUT,
            shutdown_timeout: PRODUCT_LOG_SHUTDOWN_TIMEOUT,
        }
    }

    #[cfg(test)]
    pub(super) fn for_test() -> Self {
        Self {
            queue_capacity: 8,
            worker_stack_bytes: PRODUCT_LOG_WRITER_STACK_BYTES,
            submit_timeout: Duration::from_secs(1),
            completion_timeout: Duration::from_secs(2),
            shutdown_timeout: Duration::from_secs(1),
        }
    }
}
