pub const DEFAULT_UDP_ENDPOINT_POOL_MAX_ENTRIES: i32 = 4096;
pub const DEFAULT_NAT_TIMEOUT_MS: i64 = 180_000;
pub use dae_core_types::DNS_NAT_TIMEOUT_MS;
pub const ANYFROM_TIMEOUT_MS: i64 = 5_000;
pub const MAX_RETRY: i32 = 2;

pub fn normalize_udp_endpoint_pool_max_entries(max_entries: i32) -> i32 {
    if max_entries <= 0 {
        DEFAULT_UDP_ENDPOINT_POOL_MAX_ENTRIES
    } else {
        max_entries
    }
}

pub fn udp_endpoint_pool_trim_target(max_entries: i32) -> i32 {
    let mut trim_window = max_entries / 20;
    if trim_window < 1 {
        trim_window = 1;
    }
    let target = max_entries - trim_window;
    target.max(0)
}
