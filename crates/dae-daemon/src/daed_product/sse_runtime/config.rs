use super::*;

const PRODUCT_SSE_STANDARD_CONNECTION_LIMIT: usize = 64;
const PRODUCT_SSE_STANDARD_PER_USER_LIMIT: usize = 8;
const PRODUCT_SSE_LOW_MEMORY_CONNECTION_LIMIT: usize = 16;
const PRODUCT_SSE_LOW_MEMORY_PER_USER_LIMIT: usize = 4;
const PRODUCT_SSE_RUNTIME_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug)]
pub(super) struct ProductSseRuntimeConfig {
    pub(super) connection_limit: usize,
    pub(super) per_user_limit: usize,
    pub(super) queue_capacity: usize,
    pub(super) worker_stack_bytes: usize,
    pub(super) shutdown_timeout: Duration,
}

impl ProductSseRuntimeConfig {
    pub(super) fn from_http_config(http: ProductHttpWorkerConfig) -> Self {
        let (connection_limit, per_user_limit) = match http.profile {
            ProductHttpProfile::Standard => (
                PRODUCT_SSE_STANDARD_CONNECTION_LIMIT,
                PRODUCT_SSE_STANDARD_PER_USER_LIMIT,
            ),
            ProductHttpProfile::LowMemory => (
                PRODUCT_SSE_LOW_MEMORY_CONNECTION_LIMIT,
                PRODUCT_SSE_LOW_MEMORY_PER_USER_LIMIT,
            ),
        };
        Self {
            connection_limit,
            per_user_limit,
            queue_capacity: connection_limit,
            worker_stack_bytes: http.worker_stack_bytes,
            shutdown_timeout: PRODUCT_SSE_RUNTIME_SHUTDOWN_TIMEOUT,
        }
    }

    #[cfg(test)]
    pub(super) fn for_test() -> Self {
        Self {
            connection_limit: 4,
            per_user_limit: 2,
            queue_capacity: 4,
            worker_stack_bytes: PRODUCT_HTTP_LOW_MEMORY_WORKER_STACK_BYTES_DEFAULT,
            shutdown_timeout: Duration::from_millis(200),
        }
    }
}
