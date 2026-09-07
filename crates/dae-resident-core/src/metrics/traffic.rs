use super::*;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ResidentTrafficCounters {
    pub upload_total: u64,
    pub download_total: u64,
    pub packet_total: u64,
    pub request_total: u64,
    pub queue_depth: u64,
    pub inflight_work: u64,
    pub udp_inflight_work: u64,
    pub active_tcp_connections: u64,
    pub active_udp_sessions: u64,
}

impl ResidentDataplaneMetrics {
    pub fn traffic_counters(&self) -> ResidentTrafficCounters {
        ResidentTrafficCounters {
            upload_total: self.upload_total.load(Ordering::Relaxed),
            download_total: self.download_total.load(Ordering::Relaxed),
            packet_total: self
                .udp_ingress_packets
                .load(Ordering::Relaxed)
                .saturating_add(self.udp_response_packets.load(Ordering::Relaxed)),
            request_total: self
                .tcp_admission_accepted_total
                .load(Ordering::Relaxed)
                .saturating_add(self.dns_fast_path_completed.load(Ordering::Relaxed)),
            queue_depth: self
                .dns_udp_pending_current
                .load(Ordering::Relaxed)
                .saturating_add(self.proxy_dns_udp_queued_current.load(Ordering::Relaxed))
                .saturating_add(self.proxy_dns_udp_pending_current.load(Ordering::Relaxed))
                .saturating_add(self.udp_dispatch_queued_current.load(Ordering::Relaxed))
                .saturating_add(self.udp_session_queued_current.load(Ordering::Relaxed))
                .saturating_add(self.udp_reply_queued_current.load(Ordering::Relaxed)),
            inflight_work: self
                .tcp_admission_active
                .load(Ordering::Relaxed)
                .saturating_add(self.dns_fast_path_active.load(Ordering::Relaxed))
                .saturating_add(self.health_rounds_active.load(Ordering::Relaxed))
                .saturating_add(self.udp_processing_current.load(Ordering::Relaxed)),
            udp_inflight_work: self.udp_processing_current.load(Ordering::Relaxed),
            active_tcp_connections: self.active_tcp_connections.load(Ordering::Relaxed),
            active_udp_sessions: self.active_udp_sessions.load(Ordering::Relaxed),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResidentUdpWorkStage {
    Dispatch,
    Session,
    Reply,
    Processing,
}

/// Follows ownership through queues, failures, and cancellation. Creating the
/// guard before enqueue prevents a fast receiver from decrementing first.
pub struct ResidentUdpWorkGuard {
    metrics: Arc<ResidentDataplaneMetrics>,
    stage: ResidentUdpWorkStage,
}

impl ResidentUdpWorkGuard {
    pub fn new(metrics: Arc<ResidentDataplaneMetrics>, stage: ResidentUdpWorkStage) -> Self {
        let guard = Self { metrics, stage };
        guard.counter().fetch_add(1, Ordering::Relaxed);
        guard
    }

    pub fn transition(&mut self, stage: ResidentUdpWorkStage) {
        if self.stage != stage {
            let previous = self.stage;
            self.stage = stage;
            self.counter().fetch_add(1, Ordering::Relaxed);
            self.stage = previous;
            self.counter().fetch_sub(1, Ordering::Relaxed);
            self.stage = stage;
        }
    }

    fn counter(&self) -> &AtomicU64 {
        match self.stage {
            ResidentUdpWorkStage::Dispatch => &self.metrics.udp_dispatch_queued_current,
            ResidentUdpWorkStage::Session => &self.metrics.udp_session_queued_current,
            ResidentUdpWorkStage::Reply => &self.metrics.udp_reply_queued_current,
            ResidentUdpWorkStage::Processing => &self.metrics.udp_processing_current,
        }
    }
}

impl Drop for ResidentUdpWorkGuard {
    fn drop(&mut self) {
        self.counter().fetch_sub(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn udp_work_gauges_follow_failed_enqueue_and_cancelled_processing() {
        let metrics = Arc::new(ResidentDataplaneMetrics::default());
        let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
        sender
            .try_send(ResidentUdpWorkGuard::new(
                Arc::clone(&metrics),
                ResidentUdpWorkStage::Dispatch,
            ))
            .unwrap_or_else(|_| panic!("first enqueue"));
        let failed = sender.try_send(ResidentUdpWorkGuard::new(
            Arc::clone(&metrics),
            ResidentUdpWorkStage::Dispatch,
        ));
        assert!(failed.is_err());
        drop(failed);
        assert_eq!(metrics.traffic_counters().queue_depth, 1);
        let mut work = receiver.recv().await.unwrap();
        work.transition(ResidentUdpWorkStage::Session);
        assert_eq!(metrics.traffic_counters().queue_depth, 1);
        work.transition(ResidentUdpWorkStage::Processing);
        assert_eq!(metrics.traffic_counters().queue_depth, 0);
        assert_eq!(metrics.traffic_counters().udp_inflight_work, 1);
        let task = tokio::spawn(async move {
            let _work = work;
            std::future::pending::<()>().await;
        });
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert_eq!(metrics.traffic_counters().udp_inflight_work, 0);
        let (sender, receiver) = tokio::sync::mpsc::channel(1);
        sender
            .try_send(ResidentUdpWorkGuard::new(
                Arc::clone(&metrics),
                ResidentUdpWorkStage::Reply,
            ))
            .unwrap_or_else(|_| panic!("reply enqueue"));
        drop(receiver);
        assert_eq!(metrics.traffic_counters().queue_depth, 0);
    }

    #[test]
    fn udp_work_releases_during_unwind_and_downstream_counts_empty_packets() {
        let metrics = Arc::new(ResidentDataplaneMetrics::default());
        let result = std::panic::catch_unwind({
            let metrics = Arc::clone(&metrics);
            move || {
                let _work = ResidentUdpWorkGuard::new(metrics, ResidentUdpWorkStage::Processing);
                panic!("injected processing panic");
            }
        });
        assert!(result.is_err());
        assert_eq!(metrics.traffic_counters().udp_inflight_work, 0);
        metrics.udp_response_received();
        assert_eq!(metrics.traffic_counters().packet_total, 1);
        assert_eq!(metrics.traffic_counters().download_total, 0);
    }

    #[test]
    fn typed_traffic_counters_match_detailed_metrics_json() {
        let metrics = ResidentDataplaneMetrics::default();
        metrics.upload_total.store(101, Ordering::Relaxed);
        metrics.download_total.store(202, Ordering::Relaxed);
        metrics.udp_ingress_packets.store(303, Ordering::Relaxed);
        metrics
            .tcp_admission_accepted_total
            .store(10, Ordering::Relaxed);
        metrics.dns_fast_path_completed.store(20, Ordering::Relaxed);
        metrics.dns_udp_pending_current.store(2, Ordering::Relaxed);
        metrics
            .proxy_dns_udp_queued_current
            .store(3, Ordering::Relaxed);
        metrics
            .proxy_dns_udp_pending_current
            .store(4, Ordering::Relaxed);
        metrics.tcp_admission_active.store(5, Ordering::Relaxed);
        metrics.dns_fast_path_active.store(6, Ordering::Relaxed);
        metrics.health_rounds_active.store(7, Ordering::Relaxed);
        metrics.active_tcp_connections.store(3, Ordering::Relaxed);
        metrics.active_udp_sessions.store(4, Ordering::Relaxed);

        let traffic = metrics.traffic_counters();
        let detailed = metrics.snapshot();

        assert_eq!(
            traffic,
            ResidentTrafficCounters {
                upload_total: 101,
                download_total: 202,
                packet_total: 303,
                request_total: 30,
                queue_depth: 9,
                inflight_work: 18,
                udp_inflight_work: 0,
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
