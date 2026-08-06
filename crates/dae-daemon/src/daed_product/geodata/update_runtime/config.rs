use super::*;

const PRODUCT_GEODATA_UPDATE_WORKERS: usize = 2;
const PRODUCT_GEODATA_UPDATE_QUEUE_CAPACITY: usize = 2;
const PRODUCT_GEODATA_UPDATE_WORKER_RECV_TIMEOUT: Duration = Duration::from_millis(100);
const PRODUCT_GEODATA_UPDATE_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug)]
pub(super) struct ProductGeodataUpdateRuntimeConfig {
    pub(super) profile: ProductHttpProfile,
    pub(super) worker_count: usize,
    pub(super) queue_capacity: usize,
    pub(super) worker_stack_bytes: usize,
    pub(super) worker_recv_timeout: Duration,
    pub(super) shutdown_timeout: Duration,
    pub(super) preparation_mode: GeodataPreparationMode,
}

impl ProductGeodataUpdateRuntimeConfig {
    pub(super) fn from_http_config(http: ProductHttpWorkerConfig) -> Self {
        Self {
            profile: http.profile,
            worker_count: PRODUCT_GEODATA_UPDATE_WORKERS,
            queue_capacity: PRODUCT_GEODATA_UPDATE_QUEUE_CAPACITY,
            worker_stack_bytes: http.worker_stack_bytes,
            worker_recv_timeout: PRODUCT_GEODATA_UPDATE_WORKER_RECV_TIMEOUT,
            shutdown_timeout: PRODUCT_GEODATA_UPDATE_SHUTDOWN_TIMEOUT,
            preparation_mode: GeodataPreparationMode::IsolatedProcess,
        }
    }

    #[cfg(test)]
    pub(super) fn for_test() -> Self {
        Self {
            profile: ProductHttpProfile::LowMemory,
            worker_count: PRODUCT_GEODATA_UPDATE_WORKERS,
            queue_capacity: PRODUCT_GEODATA_UPDATE_QUEUE_CAPACITY,
            worker_stack_bytes: PRODUCT_HTTP_LOW_MEMORY_WORKER_STACK_BYTES_DEFAULT,
            worker_recv_timeout: Duration::from_millis(10),
            shutdown_timeout: Duration::from_millis(100),
            preparation_mode: GeodataPreparationMode::Inline,
        }
    }
}
