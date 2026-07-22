use super::*;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct ResidentTrafficCounters {
    pub(crate) upload_total: u64,
    pub(crate) download_total: u64,
    pub(crate) active_tcp_connections: u64,
    pub(crate) active_udp_sessions: u64,
}

impl ResidentDataplaneMetrics {
    pub(crate) fn traffic_counters(&self) -> ResidentTrafficCounters {
        ResidentTrafficCounters {
            upload_total: self.upload_total.load(Ordering::Relaxed),
            download_total: self.download_total.load(Ordering::Relaxed),
            active_tcp_connections: self.active_tcp_connections.load(Ordering::Relaxed),
            active_udp_sessions: self.active_udp_sessions.load(Ordering::Relaxed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_traffic_counters_match_detailed_metrics_json() {
        let metrics = ResidentDataplaneMetrics::default();
        metrics.upload_total.store(101, Ordering::Relaxed);
        metrics.download_total.store(202, Ordering::Relaxed);
        metrics.active_tcp_connections.store(3, Ordering::Relaxed);
        metrics.active_udp_sessions.store(4, Ordering::Relaxed);

        let traffic = metrics.traffic_counters();
        let detailed = metrics.snapshot();

        assert_eq!(
            traffic,
            ResidentTrafficCounters {
                upload_total: 101,
                download_total: 202,
                active_tcp_connections: 3,
                active_udp_sessions: 4,
            }
        );
        assert_eq!(detailed["uploadTotal"], traffic.upload_total);
        assert_eq!(detailed["downloadTotal"], traffic.download_total);
        assert_eq!(
            detailed["activeTcpConnections"],
            traffic.active_tcp_connections
        );
        assert_eq!(detailed["activeUdpSessions"], traffic.active_udp_sessions);
    }
}
