use super::*;
#[derive(Debug, Default)]
pub(crate) struct ResidentDataplaneMetrics {
    pub(super) upload_total: AtomicU64,
    pub(super) download_total: AtomicU64,
    pub(super) active_tcp_connections: AtomicU64,
    tcp_admission_active: AtomicU64,
    tcp_admission_maximum_active: AtomicU64,
    tcp_admission_accepted_total: AtomicU64,
    tcp_admission_wait_cycles: AtomicU64,
    health_rounds_active: AtomicU64,
    health_rounds_maximum_active: AtomicU64,
    health_rounds_started_total: AtomicU64,
    health_rounds_completed_total: AtomicU64,
    health_rounds_cancelled_total: AtomicU64,
    health_resuscitation_queued: AtomicU64,
    health_resuscitation_queue_full: AtomicU64,
    health_resuscitation_disconnected: AtomicU64,
    pub(super) active_udp_sessions: AtomicU64,
    udp_ingress_packets: AtomicU64,
    udp_ingress_drain_batches: AtomicU64,
    udp_ingress_drain_budget_hits: AtomicU64,
    udp_ingress_truncated: AtomicU64,
    udp_reply_queued: AtomicU64,
    udp_reply_queue_full: AtomicU64,
    udp_reply_sent: AtomicU64,
    udp_reply_send_would_block: AtomicU64,
    udp_reply_socket_recreated: AtomicU64,
    udp_reply_failed: AtomicU64,
}

impl ResidentDataplaneMetrics {
    pub(super) fn tcp_opened(&self) {
        self.active_tcp_connections.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn tcp_closed(&self) {
        self.active_tcp_connections.fetch_sub(1, Ordering::Relaxed);
    }

    pub(super) fn tcp_admitted(&self) {
        let active = self
            .tcp_admission_active
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        self.tcp_admission_maximum_active
            .fetch_max(active, Ordering::Relaxed);
        self.tcp_admission_accepted_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn tcp_admission_released(&self) {
        let _ = self.tcp_admission_active.fetch_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |active| Some(active.saturating_sub(1)),
        );
    }

    pub(super) fn tcp_admission_waited(&self) {
        self.tcp_admission_wait_cycles
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn health_round_started(&self) {
        let active = self
            .health_rounds_active
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        self.health_rounds_maximum_active
            .fetch_max(active, Ordering::Relaxed);
        self.health_rounds_started_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn health_round_finished(&self, cancelled: bool) {
        let _ = self.health_rounds_active.fetch_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |active| Some(active.saturating_sub(1)),
        );
        if cancelled {
            self.health_rounds_cancelled_total
                .fetch_add(1, Ordering::Relaxed);
        } else {
            self.health_rounds_completed_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    pub(super) fn health_resuscitation_queued(&self) {
        self.health_resuscitation_queued
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn health_resuscitation_queue_full(&self) {
        self.health_resuscitation_queue_full
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn health_resuscitation_disconnected(&self) {
        self.health_resuscitation_disconnected
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn udp_opened(&self) {
        self.active_udp_sessions.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn udp_closed(&self) {
        self.active_udp_sessions.fetch_sub(1, Ordering::Relaxed);
    }

    pub(super) fn add_upload(&self, bytes: usize) {
        self.upload_total.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    pub(super) fn add_download(&self, bytes: usize) {
        self.download_total
            .fetch_add(bytes as u64, Ordering::Relaxed);
    }

    pub(super) fn record_udp_ingress_batch(
        &self,
        packets: usize,
        truncated: usize,
        budget_hit: bool,
    ) {
        self.udp_ingress_packets
            .fetch_add(packets as u64, Ordering::Relaxed);
        self.udp_ingress_truncated
            .fetch_add(truncated as u64, Ordering::Relaxed);
        self.udp_ingress_drain_batches
            .fetch_add(1, Ordering::Relaxed);
        if budget_hit {
            self.udp_ingress_drain_budget_hits
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    pub(super) fn udp_reply_queued(&self) {
        self.udp_reply_queued.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn udp_reply_queue_full(&self) {
        self.udp_reply_queue_full.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn udp_reply_sent(&self) {
        self.udp_reply_sent.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn udp_reply_send_would_block(&self) {
        self.udp_reply_send_would_block
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn udp_reply_socket_recreated(&self) {
        self.udp_reply_socket_recreated
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn udp_reply_failed(&self) {
        self.udp_reply_failed.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn snapshot(&self) -> Value {
        json!({
            "uploadTotal": self.upload_total.load(Ordering::Relaxed),
            "downloadTotal": self.download_total.load(Ordering::Relaxed),
            "activeTcpConnections": self.active_tcp_connections.load(Ordering::Relaxed),
            "tcpAdmissionActive": self.tcp_admission_active.load(Ordering::Relaxed),
            "tcpAdmissionMaximumActive": self.tcp_admission_maximum_active.load(Ordering::Relaxed),
            "tcpAdmissionAcceptedTotal": self.tcp_admission_accepted_total.load(Ordering::Relaxed),
            "tcpAdmissionWaitCycles": self.tcp_admission_wait_cycles.load(Ordering::Relaxed),
            "healthRoundsActive": self.health_rounds_active.load(Ordering::Relaxed),
            "healthRoundsMaximumActive": self.health_rounds_maximum_active.load(Ordering::Relaxed),
            "healthRoundsStartedTotal": self.health_rounds_started_total.load(Ordering::Relaxed),
            "healthRoundsCompletedTotal": self.health_rounds_completed_total.load(Ordering::Relaxed),
            "healthRoundsCancelledTotal": self.health_rounds_cancelled_total.load(Ordering::Relaxed),
            "healthResuscitationQueued": self.health_resuscitation_queued.load(Ordering::Relaxed),
            "healthResuscitationQueueFull": self.health_resuscitation_queue_full.load(Ordering::Relaxed),
            "healthResuscitationDisconnected": self.health_resuscitation_disconnected.load(Ordering::Relaxed),
            "activeUdpSessions": self.active_udp_sessions.load(Ordering::Relaxed),
            "udpIngressPackets": self.udp_ingress_packets.load(Ordering::Relaxed),
            "udpIngressDrainBatches": self.udp_ingress_drain_batches.load(Ordering::Relaxed),
            "udpIngressDrainBudgetHits": self.udp_ingress_drain_budget_hits.load(Ordering::Relaxed),
            "udpIngressTruncated": self.udp_ingress_truncated.load(Ordering::Relaxed),
            "udpReplyQueued": self.udp_reply_queued.load(Ordering::Relaxed),
            "udpReplyQueueFull": self.udp_reply_queue_full.load(Ordering::Relaxed),
            "udpReplySent": self.udp_reply_sent.load(Ordering::Relaxed),
            "udpReplySendWouldBlock": self.udp_reply_send_would_block.load(Ordering::Relaxed),
            "udpReplySocketRecreated": self.udp_reply_socket_recreated.load(Ordering::Relaxed),
            "udpReplyFailed": self.udp_reply_failed.load(Ordering::Relaxed),
        })
    }
}

pub(crate) struct ResidentTcpConnectionGuard {
    metrics: Arc<ResidentDataplaneMetrics>,
}

impl ResidentTcpConnectionGuard {
    pub(super) fn new(metrics: Arc<ResidentDataplaneMetrics>) -> Self {
        metrics.tcp_opened();
        Self { metrics }
    }
}

impl Drop for ResidentTcpConnectionGuard {
    fn drop(&mut self) {
        self.metrics.tcp_closed();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp_connection_guard_closes_on_drop() {
        let metrics = Arc::new(ResidentDataplaneMetrics::default());
        {
            let _guard = ResidentTcpConnectionGuard::new(Arc::clone(&metrics));
            assert_eq!(metrics.active_tcp_connections.load(Ordering::Relaxed), 1);
        }
        assert_eq!(metrics.active_tcp_connections.load(Ordering::Relaxed), 0);
    }
}
