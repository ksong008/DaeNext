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
    udp_session_dispatch_queued: AtomicU64,
    udp_session_dispatch_queue_full: AtomicU64,
    udp_session_created: AtomicU64,
    udp_session_reused: AtomicU64,
    udp_session_admission_rejected: AtomicU64,
    udp_session_queue_full: AtomicU64,
    udp_session_stale_recreated: AtomicU64,
    udp_session_actor_panicked: AtomicU64,
    udp_session_cleanup_notification_failed: AtomicU64,
    udp_session_shutdown_deadline_hits: AtomicU64,
    udp_ingress_packets: AtomicU64,
    udp_ingress_drain_batches: AtomicU64,
    udp_ingress_drain_budget_hits: AtomicU64,
    udp_ingress_truncated: AtomicU64,
    dns_fast_path_active: AtomicU64,
    dns_fast_path_maximum_active: AtomicU64,
    dns_fast_path_queued: AtomicU64,
    dns_fast_path_queue_full: AtomicU64,
    dns_fast_path_completed: AtomicU64,
    dns_fast_path_failed: AtomicU64,
    dns_fast_path_cancelled: AtomicU64,
    dns_udp_actors_opened: AtomicU64,
    dns_udp_actors_closed: AtomicU64,
    dns_udp_actor_fatal_exits: AtomicU64,
    dns_udp_forwarder_recreated: AtomicU64,
    dns_udp_queue_wait_timeouts: AtomicU64,
    dns_udp_pending_current: AtomicU64,
    dns_udp_pending_maximum: AtomicU64,
    dns_udp_pending_rejected: AtomicU64,
    dns_udp_id_exhausted: AtomicU64,
    dns_udp_retries: AtomicU64,
    dns_udp_shutdown_requests_failed: AtomicU64,
    proxy_dns_udp_executors_opened: AtomicU64,
    proxy_dns_udp_executors_reused: AtomicU64,
    proxy_dns_udp_executors_reset: AtomicU64,
    proxy_dns_udp_queued_current: AtomicU64,
    proxy_dns_udp_queued_bytes_current: AtomicU64,
    proxy_dns_udp_pending_current: AtomicU64,
    proxy_dns_udp_pending_bytes_current: AtomicU64,
    proxy_dns_udp_abandoned: AtomicU64,
    proxy_dns_udp_abandoned_bytes: AtomicU64,
    proxy_dns_udp_expired: AtomicU64,
    proxy_dns_udp_expired_bytes: AtomicU64,
    udp_response_validated: AtomicU64,
    udp_response_compatibility_unverified: AtomicU64,
    udp_response_dropped: AtomicU64,
    udp_response_dropped_bytes: AtomicU64,
    udp_reply_queued: AtomicU64,
    udp_reply_queue_full: AtomicU64,
    udp_reply_sent: AtomicU64,
    udp_reply_send_would_block: AtomicU64,
    udp_reply_socket_recreated: AtomicU64,
    udp_reply_socket_idle_evicted: AtomicU64,
    udp_reply_failed: AtomicU64,
}

fn subtract_metric(metric: &AtomicU64, value: u64) {
    let updated = metric.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
        current.checked_sub(value)
    });
    debug_assert!(updated.is_ok(), "resident dataplane metric underflow");
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

    pub(super) fn udp_session_dispatch_queued(&self) {
        self.udp_session_dispatch_queued
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn udp_session_dispatch_queue_full(&self) {
        self.udp_session_dispatch_queue_full
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn udp_session_created(&self) {
        self.udp_session_created.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn udp_session_reused(&self) {
        self.udp_session_reused.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn udp_session_admission_rejected(&self) {
        self.udp_session_admission_rejected
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn udp_session_queue_full(&self) {
        self.udp_session_queue_full.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn udp_session_stale_recreated(&self) {
        self.udp_session_stale_recreated
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn udp_session_actor_panicked(&self) {
        self.udp_session_actor_panicked
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn udp_session_cleanup_notification_failed(&self) {
        self.udp_session_cleanup_notification_failed
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn udp_session_shutdown_deadline_hit(&self) {
        self.udp_session_shutdown_deadline_hits
            .fetch_add(1, Ordering::Relaxed);
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

    pub(super) fn dns_udp_actor_opened(&self) {
        self.dns_udp_actors_opened.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn dns_udp_actor_closed(&self, fatal: bool) {
        self.dns_udp_actors_closed.fetch_add(1, Ordering::Relaxed);
        if fatal {
            self.dns_udp_actor_fatal_exits
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    pub(super) fn dns_udp_forwarder_recreated(&self) {
        self.dns_udp_forwarder_recreated
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn dns_udp_queue_wait_timeout(&self) {
        self.dns_udp_queue_wait_timeouts
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn dns_udp_pending_added(&self) {
        let current = self
            .dns_udp_pending_current
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        self.dns_udp_pending_maximum
            .fetch_max(current, Ordering::Relaxed);
    }

    pub(super) fn dns_udp_pending_removed(&self, count: usize) {
        let count = count as u64;
        let _ = self.dns_udp_pending_current.fetch_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |current| Some(current.saturating_sub(count)),
        );
    }

    pub(super) fn dns_udp_pending_rejected(&self) {
        self.dns_udp_pending_rejected
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn dns_udp_id_exhausted(&self) {
        self.dns_udp_id_exhausted.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn dns_udp_retry(&self) {
        self.dns_udp_retries.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn dns_udp_shutdown_failed_requests(&self, count: usize) {
        self.dns_udp_shutdown_requests_failed
            .fetch_add(count as u64, Ordering::Relaxed);
    }

    pub(super) fn proxy_dns_udp_executor_opened(&self) {
        self.proxy_dns_udp_executors_opened
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn proxy_dns_udp_executor_reused(&self) {
        self.proxy_dns_udp_executors_reused
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn proxy_dns_udp_executor_reset(&self) {
        self.proxy_dns_udp_executors_reset
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn proxy_dns_udp_queued_added(&self, bytes: usize) {
        self.proxy_dns_udp_queued_current
            .fetch_add(1, Ordering::Relaxed);
        self.proxy_dns_udp_queued_bytes_current
            .fetch_add(bytes as u64, Ordering::Relaxed);
    }

    pub(super) fn proxy_dns_udp_queued_removed(&self, bytes: usize) {
        subtract_metric(&self.proxy_dns_udp_queued_current, 1);
        subtract_metric(&self.proxy_dns_udp_queued_bytes_current, bytes as u64);
    }

    pub(super) fn proxy_dns_udp_pending_added(&self, bytes: usize) {
        self.proxy_dns_udp_pending_current
            .fetch_add(1, Ordering::Relaxed);
        self.proxy_dns_udp_pending_bytes_current
            .fetch_add(bytes as u64, Ordering::Relaxed);
        self.dns_udp_pending_added();
    }

    pub(super) fn proxy_dns_udp_pending_removed(&self, bytes: usize) {
        subtract_metric(&self.proxy_dns_udp_pending_current, 1);
        subtract_metric(&self.proxy_dns_udp_pending_bytes_current, bytes as u64);
        self.dns_udp_pending_removed(1);
    }

    pub(super) fn proxy_dns_udp_abandoned(&self, bytes: usize) {
        self.proxy_dns_udp_abandoned.fetch_add(1, Ordering::Relaxed);
        self.proxy_dns_udp_abandoned_bytes
            .fetch_add(bytes as u64, Ordering::Relaxed);
    }

    pub(super) fn proxy_dns_udp_expired(&self, bytes: usize) {
        self.proxy_dns_udp_expired.fetch_add(1, Ordering::Relaxed);
        self.proxy_dns_udp_expired_bytes
            .fetch_add(bytes as u64, Ordering::Relaxed);
    }

    pub(super) fn udp_response_validated(&self) {
        self.udp_response_validated.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn udp_response_compatibility_unverified(&self) {
        self.udp_response_compatibility_unverified
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn udp_response_dropped(&self, bytes: usize) {
        self.udp_response_dropped.fetch_add(1, Ordering::Relaxed);
        self.udp_response_dropped_bytes
            .fetch_add(bytes as u64, Ordering::Relaxed);
    }

    pub(super) fn dns_fast_path_queued(&self) {
        self.dns_fast_path_queued.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn dns_fast_path_queue_full(&self) {
        self.dns_fast_path_queue_full
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn dns_fast_path_started(&self) {
        let active = self
            .dns_fast_path_active
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        self.dns_fast_path_maximum_active
            .fetch_max(active, Ordering::Relaxed);
    }

    pub(super) fn dns_fast_path_finished(&self, failed: bool) {
        self.dns_fast_path_released();
        if failed {
            self.dns_fast_path_failed.fetch_add(1, Ordering::Relaxed);
        }
        self.dns_fast_path_completed.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn dns_fast_path_rejected(&self) {
        self.dns_fast_path_queue_full();
        self.dns_fast_path_failed.fetch_add(1, Ordering::Relaxed);
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

    pub(super) fn dns_fast_path_cancelled(&self) {
        self.dns_fast_path_released();
        self.dns_fast_path_failed.fetch_add(1, Ordering::Relaxed);
        self.dns_fast_path_cancelled.fetch_add(1, Ordering::Relaxed);
    }

    fn dns_fast_path_released(&self) {
        let _ = self.dns_fast_path_active.fetch_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |active| Some(active.saturating_sub(1)),
        );
    }

    pub(super) fn udp_reply_socket_recreated(&self) {
        self.udp_reply_socket_recreated
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn udp_reply_socket_idle_evicted(&self, count: usize) {
        self.udp_reply_socket_idle_evicted
            .fetch_add(count as u64, Ordering::Relaxed);
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
            "udpSessionDispatchQueued": self.udp_session_dispatch_queued.load(Ordering::Relaxed),
            "udpSessionDispatchQueueFull": self.udp_session_dispatch_queue_full.load(Ordering::Relaxed),
            "udpSessionCreated": self.udp_session_created.load(Ordering::Relaxed),
            "udpSessionReused": self.udp_session_reused.load(Ordering::Relaxed),
            "udpSessionAdmissionRejected": self.udp_session_admission_rejected.load(Ordering::Relaxed),
            "udpSessionQueueFull": self.udp_session_queue_full.load(Ordering::Relaxed),
            "udpSessionStaleRecreated": self.udp_session_stale_recreated.load(Ordering::Relaxed),
            "udpSessionActorPanicked": self.udp_session_actor_panicked.load(Ordering::Relaxed),
            "udpSessionCleanupNotificationFailed": self.udp_session_cleanup_notification_failed.load(Ordering::Relaxed),
            "udpSessionShutdownDeadlineHits": self.udp_session_shutdown_deadline_hits.load(Ordering::Relaxed),
            "udpIngressPackets": self.udp_ingress_packets.load(Ordering::Relaxed),
            "udpIngressDrainBatches": self.udp_ingress_drain_batches.load(Ordering::Relaxed),
            "udpIngressDrainBudgetHits": self.udp_ingress_drain_budget_hits.load(Ordering::Relaxed),
            "udpIngressTruncated": self.udp_ingress_truncated.load(Ordering::Relaxed),
            "dnsFastPathActive": self.dns_fast_path_active.load(Ordering::Relaxed),
            "dnsFastPathMaximumActive": self.dns_fast_path_maximum_active.load(Ordering::Relaxed),
            "dnsFastPathQueued": self.dns_fast_path_queued.load(Ordering::Relaxed),
            "dnsFastPathQueueFull": self.dns_fast_path_queue_full.load(Ordering::Relaxed),
            "dnsFastPathCompleted": self.dns_fast_path_completed.load(Ordering::Relaxed),
            "dnsFastPathFailed": self.dns_fast_path_failed.load(Ordering::Relaxed),
            "dnsFastPathCancelled": self.dns_fast_path_cancelled.load(Ordering::Relaxed),
            "dnsUdpActorsOpened": self.dns_udp_actors_opened.load(Ordering::Relaxed),
            "dnsUdpActorsClosed": self.dns_udp_actors_closed.load(Ordering::Relaxed),
            "dnsUdpActorFatalExits": self.dns_udp_actor_fatal_exits.load(Ordering::Relaxed),
            "dnsUdpForwarderRecreated": self.dns_udp_forwarder_recreated.load(Ordering::Relaxed),
            "dnsUdpQueueWaitTimeouts": self.dns_udp_queue_wait_timeouts.load(Ordering::Relaxed),
            "dnsUdpPendingCurrent": self.dns_udp_pending_current.load(Ordering::Relaxed),
            "dnsUdpPendingMaximum": self.dns_udp_pending_maximum.load(Ordering::Relaxed),
            "dnsUdpPendingRejected": self.dns_udp_pending_rejected.load(Ordering::Relaxed),
            "dnsUdpIdExhausted": self.dns_udp_id_exhausted.load(Ordering::Relaxed),
            "dnsUdpRetries": self.dns_udp_retries.load(Ordering::Relaxed),
            "dnsUdpShutdownRequestsFailed": self.dns_udp_shutdown_requests_failed.load(Ordering::Relaxed),
            "proxyDnsUdpExecutorsOpened": self.proxy_dns_udp_executors_opened.load(Ordering::Relaxed),
            "proxyDnsUdpExecutorsReused": self.proxy_dns_udp_executors_reused.load(Ordering::Relaxed),
            "proxyDnsUdpExecutorsReset": self.proxy_dns_udp_executors_reset.load(Ordering::Relaxed),
            "proxyDnsUdpQueuedCurrent": self.proxy_dns_udp_queued_current.load(Ordering::Relaxed),
            "proxyDnsUdpQueuedBytesCurrent": self.proxy_dns_udp_queued_bytes_current.load(Ordering::Relaxed),
            "proxyDnsUdpPendingCurrent": self.proxy_dns_udp_pending_current.load(Ordering::Relaxed),
            "proxyDnsUdpPendingBytesCurrent": self.proxy_dns_udp_pending_bytes_current.load(Ordering::Relaxed),
            "proxyDnsUdpAbandoned": self.proxy_dns_udp_abandoned.load(Ordering::Relaxed),
            "proxyDnsUdpAbandonedBytes": self.proxy_dns_udp_abandoned_bytes.load(Ordering::Relaxed),
            "proxyDnsUdpExpired": self.proxy_dns_udp_expired.load(Ordering::Relaxed),
            "proxyDnsUdpExpiredBytes": self.proxy_dns_udp_expired_bytes.load(Ordering::Relaxed),
            "udpResponseValidated": self.udp_response_validated.load(Ordering::Relaxed),
            "udpResponseCompatibilityUnverified": self.udp_response_compatibility_unverified.load(Ordering::Relaxed),
            "udpResponseDropped": self.udp_response_dropped.load(Ordering::Relaxed),
            "udpResponseDroppedBytes": self.udp_response_dropped_bytes.load(Ordering::Relaxed),
            "udpReplyQueued": self.udp_reply_queued.load(Ordering::Relaxed),
            "udpReplyQueueFull": self.udp_reply_queue_full.load(Ordering::Relaxed),
            "udpReplySent": self.udp_reply_sent.load(Ordering::Relaxed),
            "udpReplySendWouldBlock": self.udp_reply_send_would_block.load(Ordering::Relaxed),
            "udpReplySocketRecreated": self.udp_reply_socket_recreated.load(Ordering::Relaxed),
            "udpReplySocketIdleEvicted": self.udp_reply_socket_idle_evicted.load(Ordering::Relaxed),
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

    #[test]
    fn udp_response_validation_metrics_keep_drops_and_compatibility_visible() {
        let metrics = ResidentDataplaneMetrics::default();
        metrics.udp_response_validated();
        metrics.udp_response_compatibility_unverified();
        metrics.udp_response_dropped(512);
        let snapshot = metrics.snapshot();
        assert_eq!(snapshot["udpResponseValidated"], 1);
        assert_eq!(snapshot["udpResponseCompatibilityUnverified"], 1);
        assert_eq!(snapshot["udpResponseDropped"], 1);
        assert_eq!(snapshot["udpResponseDroppedBytes"], 512);
    }
}
