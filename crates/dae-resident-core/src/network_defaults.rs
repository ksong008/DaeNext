use std::time::Duration;

pub const RESIDENT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
pub const RESIDENT_TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(300);
pub const RESIDENT_TCP_HALF_CLOSE_DRAIN_IDLE_TIMEOUT: Duration = Duration::from_secs(1);
pub const RESIDENT_ANYTLS_RELAY_BUFFER_SIZE: usize = 32 * 1024;
pub const ANYTLS_LOCAL_CLOSE_DRAIN_TIMEOUT: Duration = Duration::from_millis(500);
pub const VISION_COMMAND_CONTINUE: u8 = 0;
pub const VISION_COMMAND_END: u8 = 1;
pub const VISION_COMMAND_DIRECT: u8 = 2;
pub const TLS_RECORD_HEADER_LEN: usize = 5;
pub const TLS_RECORD_MAX_PAYLOAD_LEN: usize = 16 * 1024 + 2048;
pub const RESIDENT_IDLE_SLEEP: Duration = Duration::from_millis(5);
pub const RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE: Duration = Duration::from_millis(1_500);
pub const RESIDENT_RUNTIME_TASK_JOIN_GRACE: Duration = Duration::from_secs(2);
pub const RESIDENT_RUNTIME_FORCED_TASK_JOIN_GRACE: Duration = Duration::from_millis(250);
pub const RESIDENT_TCP_CANDIDATE_ATTEMPT_DELAY: Duration = Duration::from_millis(250);
pub const RESIDENT_TCP_CANDIDATE_MAX_IN_FLIGHT: usize = 2;
pub const RESIDENT_TCP_FLOW_STACK_BYTES_DEFAULT: usize = 512 * 1024;
pub const RESIDENT_UDP_RESPONSE_TIMEOUT: Duration = Duration::from_secs(8);
pub const RESIDENT_UDP_DNS_SESSION_IDLE_TIMEOUT: Duration =
    Duration::from_millis(dae_core_types::DNS_NAT_TIMEOUT_MS as u64);
pub const RESIDENT_UDP_SOCKET_BUFFER_BYTES_ENV: &str = "RESIDENT_UDP_SOCKET_BUFFER_BYTES";
pub const RESIDENT_UDP_SOCKET_BUFFER_BYTES_DEFAULT: usize = 512 * 1024;
pub const RESIDENT_UDP_SOCKET_BUFFER_BYTES_MIN: usize = 64 * 1024;
pub const RESIDENT_UDP_SOCKET_BUFFER_BYTES_MAX: usize = 8 * 1024 * 1024;
pub const VLESS_RESPONSE_VERSION: u8 = 0;
pub const XUDP_MUX_TARGET: &str = "v1.mux.cool:666";
pub const XUDP_COMMAND_NEW: u8 = 1;
pub const XUDP_COMMAND_KEEP: u8 = 2;
pub const XUDP_OPTION_DATA: u8 = 1;
pub const XUDP_NETWORK_UDP: u8 = 2;

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
