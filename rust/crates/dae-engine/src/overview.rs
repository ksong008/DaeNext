#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RuntimeTrafficSample {
    pub timestamp_unix: i64,
    pub upload_rate: u64,
    pub download_rate: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DnsObservabilityStats {
    pub dns_cache_hit_total: u64,
    pub dns_cache_expired_removal_total: u64,
    pub dns_udp_retry_total: u64,
    pub dns_truncated_tcp_fallback_total: u64,
    pub dns_doh_status_failure_total: u64,
    pub dns_doh_content_type_failure_total: u64,
    pub dns_upstream_refresh_success_total: u64,
    pub dns_upstream_refresh_failure_total: u64,
    pub dns_upstream_refresh_stale_reuse_total: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RuntimeStatsSnapshot {
    pub updated_at_unix: i64,
    pub upload_rate: u64,
    pub download_rate: u64,
    pub upload_total: u64,
    pub download_total: u64,
    pub active_connections: i32,
    pub udp_sessions: i32,
    pub udp_task_queues: i32,
    pub udp_task_drop_total: u64,
    pub packet_sniffer_sessions: i32,
    pub rss_bytes: u64,
    pub heap_alloc_bytes: u64,
    pub goroutines: i32,
    pub dns: DnsObservabilityStats,
    pub samples: Vec<RuntimeTrafficSample>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RuntimeOverview {
    pub updated_at_unix: i64,
    pub upload_rate: u64,
    pub download_rate: u64,
    pub upload_total: u64,
    pub download_total: u64,
    pub active_connections: i32,
    pub udp_sessions: i32,
    pub udp_task_queues: i32,
    pub udp_task_drop_total: u64,
    pub packet_sniffer_sessions: i32,
    pub rss_bytes: u64,
    pub heap_alloc_bytes: u64,
    pub goroutines: i32,
    pub dns: DnsObservabilityStats,
    pub samples: Vec<RuntimeTrafficSample>,
}

impl RuntimeOverview {
    pub fn from_snapshot(
        snapshot: RuntimeStatsSnapshot,
        scoped_udp_task_pool: Option<(i32, u64)>,
    ) -> Self {
        let (udp_task_queues, udp_task_drop_total) = scoped_udp_task_pool
            .unwrap_or((snapshot.udp_task_queues, snapshot.udp_task_drop_total));
        Self {
            updated_at_unix: snapshot.updated_at_unix,
            upload_rate: snapshot.upload_rate,
            download_rate: snapshot.download_rate,
            upload_total: snapshot.upload_total,
            download_total: snapshot.download_total,
            active_connections: snapshot.active_connections,
            udp_sessions: snapshot.udp_sessions,
            udp_task_queues,
            udp_task_drop_total,
            packet_sniffer_sessions: snapshot.packet_sniffer_sessions,
            rss_bytes: snapshot.rss_bytes,
            heap_alloc_bytes: snapshot.heap_alloc_bytes,
            goroutines: snapshot.goroutines,
            dns: snapshot.dns,
            samples: snapshot.samples,
        }
    }
}
