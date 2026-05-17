pub const PACKET_SNIFFER_TTL_MS: i64 = 3_000;
pub const PACKET_SNIFFER_POOL_MAX_ENTRIES: usize = 1024;

pub fn packet_sniffer_expired(last_active_ms: i64, now_ms: i64, ttl_ms: i64) -> bool {
    last_active_ms + ttl_ms <= now_ms
}
