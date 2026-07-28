use super::*;

const PRODUCT_CONTROL_STANDARD_WORKER_MAX: usize = 4;
const PRODUCT_CONTROL_LOW_MEMORY_WORKER_MAX: usize = 2;
const PRODUCT_CONTROL_STANDARD_BLOCKING_THREAD_MAX: usize = 4;
const PRODUCT_CONTROL_LOW_MEMORY_BLOCKING_THREAD_MAX: usize = 1;
const PRODUCT_CONTROL_STANDARD_DNS_LIMIT: usize = 8;
const PRODUCT_CONTROL_LOW_MEMORY_DNS_LIMIT: usize = 2;
const PRODUCT_CONTROL_STANDARD_DIRECT_HTTP_LIMIT: usize = 4;
const PRODUCT_CONTROL_LOW_MEMORY_DIRECT_HTTP_LIMIT: usize = 1;
const PRODUCT_CONTROL_STANDARD_PROXY_HTTP_LIMIT: usize = 2;
const PRODUCT_CONTROL_LOW_MEMORY_PROXY_HTTP_LIMIT: usize = 1;
const PRODUCT_CONTROL_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ProductControlRuntimeConfig {
    pub(super) profile: ProductHttpProfile,
    pub(super) worker_threads: usize,
    pub(super) maximum_blocking_threads: usize,
    pub(super) worker_stack_bytes: usize,
    pub(super) queue_capacity: usize,
    pub(super) dns_limit: usize,
    pub(super) direct_http_limit: usize,
    pub(super) proxy_http_limit: usize,
    pub(super) runtime_lifecycle_limit: usize,
    pub(super) shutdown_timeout: Duration,
}

impl ProductControlRuntimeConfig {
    pub(super) fn from_http_config(http: ProductHttpWorkerConfig) -> Self {
        let available_parallelism = thread::available_parallelism()
            .map(|parallelism| parallelism.get())
            .unwrap_or(1);
        Self::from_parallelism(http, available_parallelism)
    }

    fn from_parallelism(http: ProductHttpWorkerConfig, available_parallelism: usize) -> Self {
        let available_parallelism = available_parallelism.max(1);
        let (worker_max, blocking_thread_max, dns_limit, direct_http_limit, proxy_http_limit) =
            match http.profile {
                ProductHttpProfile::Standard => (
                    PRODUCT_CONTROL_STANDARD_WORKER_MAX,
                    PRODUCT_CONTROL_STANDARD_BLOCKING_THREAD_MAX,
                    PRODUCT_CONTROL_STANDARD_DNS_LIMIT,
                    PRODUCT_CONTROL_STANDARD_DIRECT_HTTP_LIMIT,
                    PRODUCT_CONTROL_STANDARD_PROXY_HTTP_LIMIT,
                ),
                ProductHttpProfile::LowMemory => (
                    PRODUCT_CONTROL_LOW_MEMORY_WORKER_MAX,
                    PRODUCT_CONTROL_LOW_MEMORY_BLOCKING_THREAD_MAX,
                    PRODUCT_CONTROL_LOW_MEMORY_DNS_LIMIT,
                    PRODUCT_CONTROL_LOW_MEMORY_DIRECT_HTTP_LIMIT,
                    PRODUCT_CONTROL_LOW_MEMORY_PROXY_HTTP_LIMIT,
                ),
            };
        let maximum_admitted_work = dns_limit
            .saturating_add(direct_http_limit)
            .saturating_add(proxy_http_limit)
            .saturating_add(http.worker_count.max(1))
            .max(1);
        let worker_threads = available_parallelism
            .min(worker_max)
            .min(maximum_admitted_work)
            .max(1);
        let maximum_blocking_threads = available_parallelism
            .min(blocking_thread_max)
            .min(dns_limit.max(1))
            .max(1);
        Self {
            profile: http.profile,
            worker_threads,
            maximum_blocking_threads,
            worker_stack_bytes: http.worker_stack_bytes,
            queue_capacity: maximum_admitted_work,
            dns_limit,
            direct_http_limit,
            proxy_http_limit,
            runtime_lifecycle_limit: http.worker_count.max(1),
            shutdown_timeout: PRODUCT_CONTROL_SHUTDOWN_TIMEOUT,
        }
    }

    #[cfg(test)]
    pub(super) fn for_test() -> Self {
        Self::for_benchmark()
    }

    pub(super) fn for_benchmark() -> Self {
        Self {
            profile: ProductHttpProfile::LowMemory,
            worker_threads: 1,
            maximum_blocking_threads: 1,
            worker_stack_bytes: PRODUCT_HTTP_LOW_MEMORY_WORKER_STACK_BYTES_DEFAULT,
            queue_capacity: 4,
            dns_limit: 1,
            direct_http_limit: 1,
            proxy_http_limit: 1,
            runtime_lifecycle_limit: 1,
            shutdown_timeout: Duration::from_millis(250),
        }
    }

    pub(super) fn json(self) -> Value {
        json!({
            "profile": self.profile.name(),
            "executor": "process-owned-bounded-multi-thread",
            "workerThreads": self.worker_threads,
            "maximumBlockingThreads": self.maximum_blocking_threads,
            "workerStackBytes": self.worker_stack_bytes,
            "queueCapacity": self.queue_capacity,
            "admission": {
                "dns": self.dns_limit,
                "directHttp": self.direct_http_limit,
                "proxyHttp": self.proxy_http_limit,
                "runtimeLifecycle": self.runtime_lifecycle_limit,
            },
        })
    }

    pub(super) fn startup_fields(self) -> BTreeMap<String, String> {
        BTreeMap::from([
            (
                "controlRuntimeProfile".to_owned(),
                self.profile.name().to_owned(),
            ),
            (
                "controlRuntimeWorkers".to_owned(),
                self.worker_threads.to_string(),
            ),
            (
                "controlRuntimeBlockingThreads".to_owned(),
                self.maximum_blocking_threads.to_string(),
            ),
            (
                "controlRuntimeQueueCapacity".to_owned(),
                self.queue_capacity.to_string(),
            ),
            (
                "controlRuntimeDnsAdmission".to_owned(),
                self.dns_limit.to_string(),
            ),
            (
                "controlRuntimeDirectHttpAdmission".to_owned(),
                self.direct_http_limit.to_string(),
            ),
            (
                "controlRuntimeProxyHttpAdmission".to_owned(),
                self.proxy_http_limit.to_string(),
            ),
            (
                "controlRuntimeLifecycleAdmission".to_owned(),
                self.runtime_lifecycle_limit.to_string(),
            ),
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn http_config(profile: ProductHttpProfile) -> ProductHttpWorkerConfig {
        ProductHttpWorkerConfig::from_config_with_profile(None, profile, "test")
    }

    #[test]
    fn single_core_control_runtime_uses_one_worker_and_blocking_thread() {
        for profile in [ProductHttpProfile::Standard, ProductHttpProfile::LowMemory] {
            let config = ProductControlRuntimeConfig::from_parallelism(http_config(profile), 1);
            assert_eq!(config.worker_threads, 1);
            assert_eq!(config.maximum_blocking_threads, 1);
        }
    }

    #[test]
    fn control_runtime_resources_follow_profile_and_parallelism_bounds() {
        let standard = ProductControlRuntimeConfig::from_parallelism(
            http_config(ProductHttpProfile::Standard),
            64,
        );
        assert_eq!(standard.worker_threads, PRODUCT_CONTROL_STANDARD_WORKER_MAX);
        assert_eq!(
            standard.maximum_blocking_threads,
            PRODUCT_CONTROL_STANDARD_BLOCKING_THREAD_MAX
        );
        assert_eq!(
            standard.queue_capacity,
            standard.dns_limit
                + standard.direct_http_limit
                + standard.proxy_http_limit
                + standard.runtime_lifecycle_limit
        );

        let low_memory = ProductControlRuntimeConfig::from_parallelism(
            http_config(ProductHttpProfile::LowMemory),
            64,
        );
        assert_eq!(
            low_memory.worker_threads,
            PRODUCT_CONTROL_LOW_MEMORY_WORKER_MAX
        );
        assert_eq!(
            low_memory.maximum_blocking_threads,
            PRODUCT_CONTROL_LOW_MEMORY_BLOCKING_THREAD_MAX
        );
        assert!(low_memory.queue_capacity < standard.queue_capacity);
    }
}
