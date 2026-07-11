use super::*;

pub(super) const PRODUCT_AUTH_STANDARD_WORKER_MAX: usize = 2;
const PRODUCT_AUTH_STANDARD_QUEUE_CAPACITY: usize = 4;
const PRODUCT_AUTH_STANDARD_WAITER_MAX: usize = 4;
const PRODUCT_AUTH_STANDARD_PER_SOURCE_LIMIT: usize = 2;
pub(super) const PRODUCT_AUTH_LOW_MEMORY_WORKERS: usize = 1;
const PRODUCT_AUTH_LOW_MEMORY_QUEUE_CAPACITY: usize = 2;
pub(super) const PRODUCT_AUTH_LOW_MEMORY_WAITER_MAX: usize = 1;
const PRODUCT_AUTH_LOW_MEMORY_PER_SOURCE_LIMIT: usize = 1;
const PRODUCT_AUTH_PER_USERNAME_LIMIT: usize = 1;
const PRODUCT_AUTH_STANDARD_TRACKED_KEY_CAPACITY: usize = 1_024;
const PRODUCT_AUTH_LOW_MEMORY_TRACKED_KEY_CAPACITY: usize = 128;
const PRODUCT_AUTH_WORKER_STACK_BYTES: usize = 512 * 1024;
const PRODUCT_AUTH_JOB_TIMEOUT: Duration = Duration::from_secs(60);
const PRODUCT_AUTH_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);
const PRODUCT_AUTH_CAPACITY_RETRY_AFTER: Duration = Duration::from_secs(1);
const PRODUCT_AUTH_BACKOFF_BASE: Duration = Duration::from_millis(250);
const PRODUCT_AUTH_BACKOFF_MAX: Duration = Duration::from_secs(30);
const PRODUCT_AUTH_BACKOFF_TTL: Duration = Duration::from_secs(15 * 60);
const PRODUCT_AUTH_WORKER_RECV_TIMEOUT: Duration = Duration::from_millis(100);

#[derive(Clone, Copy, Debug)]
pub(super) struct ProductAuthRuntimeConfig {
    pub(super) profile: ProductHttpProfile,
    pub(super) worker_count: usize,
    pub(super) queue_capacity: usize,
    pub(super) waiter_limit: usize,
    pub(super) per_source_limit: usize,
    pub(super) per_username_limit: usize,
    pub(super) tracked_key_capacity: usize,
    pub(super) worker_stack_bytes: usize,
    pub(super) job_timeout: Duration,
    pub(super) shutdown_timeout: Duration,
    pub(super) capacity_retry_after: Duration,
    pub(super) backoff_base: Duration,
    pub(super) backoff_max: Duration,
    pub(super) backoff_ttl: Duration,
    pub(super) worker_recv_timeout: Duration,
}

impl ProductAuthRuntimeConfig {
    pub(in crate::daed_product) fn from_http_config(http: ProductHttpWorkerConfig) -> Self {
        let available = thread::available_parallelism()
            .map(|parallelism| parallelism.get())
            .unwrap_or(1);
        let (worker_count, queue_capacity, waiter_max, per_source_limit, tracked_key_capacity) =
            match http.profile {
                ProductHttpProfile::Standard => (
                    available.clamp(1, PRODUCT_AUTH_STANDARD_WORKER_MAX),
                    PRODUCT_AUTH_STANDARD_QUEUE_CAPACITY,
                    PRODUCT_AUTH_STANDARD_WAITER_MAX,
                    PRODUCT_AUTH_STANDARD_PER_SOURCE_LIMIT,
                    PRODUCT_AUTH_STANDARD_TRACKED_KEY_CAPACITY,
                ),
                ProductHttpProfile::LowMemory => (
                    PRODUCT_AUTH_LOW_MEMORY_WORKERS,
                    PRODUCT_AUTH_LOW_MEMORY_QUEUE_CAPACITY,
                    PRODUCT_AUTH_LOW_MEMORY_WAITER_MAX,
                    PRODUCT_AUTH_LOW_MEMORY_PER_SOURCE_LIMIT,
                    PRODUCT_AUTH_LOW_MEMORY_TRACKED_KEY_CAPACITY,
                ),
            };
        let reserved_http_workers = http.worker_count.saturating_sub(1).max(1);
        let waiter_limit = waiter_max
            .min(reserved_http_workers)
            .min(worker_count.saturating_add(queue_capacity))
            .max(1);
        Self {
            profile: http.profile,
            worker_count,
            queue_capacity,
            waiter_limit,
            per_source_limit,
            per_username_limit: PRODUCT_AUTH_PER_USERNAME_LIMIT,
            tracked_key_capacity,
            worker_stack_bytes: PRODUCT_AUTH_WORKER_STACK_BYTES,
            job_timeout: PRODUCT_AUTH_JOB_TIMEOUT,
            shutdown_timeout: PRODUCT_AUTH_SHUTDOWN_TIMEOUT,
            capacity_retry_after: PRODUCT_AUTH_CAPACITY_RETRY_AFTER,
            backoff_base: PRODUCT_AUTH_BACKOFF_BASE,
            backoff_max: PRODUCT_AUTH_BACKOFF_MAX,
            backoff_ttl: PRODUCT_AUTH_BACKOFF_TTL,
            worker_recv_timeout: PRODUCT_AUTH_WORKER_RECV_TIMEOUT,
        }
    }

    #[cfg(test)]
    pub(super) fn for_test() -> Self {
        Self {
            profile: ProductHttpProfile::LowMemory,
            worker_count: 1,
            queue_capacity: 2,
            waiter_limit: 1,
            per_source_limit: 1,
            per_username_limit: 1,
            tracked_key_capacity: 32,
            worker_stack_bytes: PRODUCT_AUTH_WORKER_STACK_BYTES,
            job_timeout: Duration::from_secs(5),
            shutdown_timeout: Duration::from_secs(2),
            capacity_retry_after: Duration::from_millis(10),
            backoff_base: Duration::from_millis(100),
            backoff_max: Duration::from_millis(800),
            backoff_ttl: Duration::from_secs(2),
            worker_recv_timeout: Duration::from_millis(10),
        }
    }
}

pub(super) fn auth_defaults_json() -> Value {
    json!({
        "scope": "AppState-owned bounded Argon2 worker runtime",
        "standard": {
            "workerPolicy": format!("available_parallelism clamped to 1..{PRODUCT_AUTH_STANDARD_WORKER_MAX}"),
            "queueCapacity": PRODUCT_AUTH_STANDARD_QUEUE_CAPACITY,
            "httpWaiterMax": PRODUCT_AUTH_STANDARD_WAITER_MAX,
            "perSourceLimit": PRODUCT_AUTH_STANDARD_PER_SOURCE_LIMIT,
            "trackedKeyCapacity": PRODUCT_AUTH_STANDARD_TRACKED_KEY_CAPACITY,
        },
        "lowMemory": {
            "workers": PRODUCT_AUTH_LOW_MEMORY_WORKERS,
            "queueCapacity": PRODUCT_AUTH_LOW_MEMORY_QUEUE_CAPACITY,
            "httpWaiterMax": PRODUCT_AUTH_LOW_MEMORY_WAITER_MAX,
            "perSourceLimit": PRODUCT_AUTH_LOW_MEMORY_PER_SOURCE_LIMIT,
            "trackedKeyCapacity": PRODUCT_AUTH_LOW_MEMORY_TRACKED_KEY_CAPACITY,
        },
        "perUsernameLimit": PRODUCT_AUTH_PER_USERNAME_LIMIT,
        "workerStackBytes": PRODUCT_AUTH_WORKER_STACK_BYTES,
        "jobTimeoutSeconds": PRODUCT_AUTH_JOB_TIMEOUT.as_secs(),
        "backoffBaseMilliseconds": PRODUCT_AUTH_BACKOFF_BASE.as_millis().to_string(),
        "backoffMaxSeconds": PRODUCT_AUTH_BACKOFF_MAX.as_secs(),
        "backoffTtlSeconds": PRODUCT_AUTH_BACKOFF_TTL.as_secs(),
    })
}
