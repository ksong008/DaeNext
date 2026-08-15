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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_overview_matches_golden_fixture() {
        let fixture = dae_golden::load_json("engine/runtime_overview/basic.json").unwrap();
        let no_control = &fixture["no_control_plane"];
        let snapshot = RuntimeStatsSnapshot {
            updated_at_unix: no_control["updated_at_unix"].as_i64().unwrap(),
            upload_rate: no_control["upload_rate"].as_u64().unwrap(),
            download_rate: no_control["download_rate"].as_u64().unwrap(),
            upload_total: no_control["upload_total"].as_u64().unwrap(),
            download_total: no_control["download_total"].as_u64().unwrap(),
            active_connections: no_control["active_connections"].as_i64().unwrap() as i32,
            udp_sessions: no_control["udp_sessions"].as_i64().unwrap() as i32,
            udp_task_queues: no_control["udp_task_queues"].as_i64().unwrap() as i32,
            udp_task_drop_total: no_control["udp_task_drop_total"].as_u64().unwrap(),
            packet_sniffer_sessions: no_control["packet_sniffer_sessions"].as_i64().unwrap() as i32,
            rss_bytes: no_control["rss_bytes"].as_u64().unwrap(),
            heap_alloc_bytes: no_control["heap_alloc_bytes"].as_u64().unwrap(),
            goroutines: no_control["goroutines"].as_i64().unwrap() as i32,
            dns: DnsObservabilityStats {
                dns_cache_hit_total: no_control["dns_cache_hit_total"].as_u64().unwrap(),
                ..DnsObservabilityStats::default()
            },
            samples: vec![RuntimeTrafficSample {
                timestamp_unix: no_control["samples"][0]["timestamp_unix"].as_i64().unwrap(),
                upload_rate: no_control["samples"][0]["upload_rate"].as_u64().unwrap(),
                download_rate: no_control["samples"][0]["download_rate"].as_u64().unwrap(),
            }],
        };
        let overview = RuntimeOverview::from_snapshot(snapshot, None);
        assert_eq!(
            overview.upload_rate,
            no_control["upload_rate"].as_u64().unwrap()
        );
        assert_eq!(
            overview.dns.dns_cache_hit_total,
            no_control["dns_cache_hit_total"].as_u64().unwrap()
        );

        let scoped = &fixture["scoped_udp_task_pool"];
        let overview = RuntimeOverview::from_snapshot(
            RuntimeStatsSnapshot {
                udp_task_queues: scoped["snapshot_queue_input"].as_i64().unwrap() as i32,
                udp_task_drop_total: scoped["snapshot_drop_input"].as_u64().unwrap(),
                packet_sniffer_sessions: scoped["packet_sniffer_kept"].as_i64().unwrap() as i32,
                ..RuntimeStatsSnapshot::default()
            },
            Some((
                scoped["udp_task_queues"].as_i64().unwrap() as i32,
                scoped["udp_task_drop_total"].as_u64().unwrap(),
            )),
        );
        assert_eq!(
            overview.udp_task_queues,
            scoped["udp_task_queues"].as_i64().unwrap() as i32
        );
        assert_eq!(
            overview.packet_sniffer_sessions,
            scoped["packet_sniffer_kept"].as_i64().unwrap() as i32
        );
    }
}
