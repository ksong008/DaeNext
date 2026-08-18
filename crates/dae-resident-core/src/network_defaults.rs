use std::time::Duration;

pub const RESIDENT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
pub const RESIDENT_TCP_CANDIDATE_ATTEMPT_DELAY: Duration = Duration::from_millis(250);
pub const RESIDENT_TCP_CANDIDATE_MAX_IN_FLIGHT: usize = 2;
pub const RESIDENT_UDP_RESPONSE_TIMEOUT: Duration = Duration::from_secs(8);

pub fn resident_udp_runtime_topology(
    requested_shards: usize,
    available_parallelism: usize,
) -> (usize, usize) {
    let available_parallelism = available_parallelism.max(1);
    let runtime_shards = requested_shards.max(1).min(available_parallelism);
    let worker_threads = if runtime_shards > 1 {
        runtime_shards.min(available_parallelism.saturating_sub(1))
    } else {
        0
    };
    (runtime_shards, worker_threads)
}
