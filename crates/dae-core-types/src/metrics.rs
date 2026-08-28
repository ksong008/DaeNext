#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Ss2022UdpReplayMetricsSnapshot {
    pub active_windows: usize,
    pub quarantined_sessions: usize,
    pub retained_sessions: usize,
    pub estimated_bytes: usize,
    pub high_water_retained_sessions: usize,
    pub high_water_estimated_bytes: usize,
    pub replay_rejections: u64,
    pub lru_evictions: u64,
    pub ttl_expirations: u64,
    pub saturation_rejections: u64,
}
