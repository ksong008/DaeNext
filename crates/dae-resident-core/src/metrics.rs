use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use dae_core_types::Ss2022UdpReplayMetricsSnapshot;
use serde_json::{Value, json};

#[path = "metrics/proxied_doh3.rs"]
mod proxied_doh3;
#[path = "metrics/traffic.rs"]
mod traffic;

pub use self::proxied_doh3::ProxiedDoh3CleanupMetricObservation;
use self::proxied_doh3::ProxiedDoh3CleanupMetrics;
pub use self::traffic::ResidentTrafficCounters;

#[derive(Debug, Default)]
pub struct ResidentDataplaneMetrics {
    upload_total: AtomicU64,
    download_total: AtomicU64,
    active_tcp_connections: AtomicU64,
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
    active_udp_sessions: AtomicU64,
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
    udp_generation_pin_unavailable: AtomicU64,
    udp_ingress_packets: AtomicU64,
    udp_ingress_drain_batches: AtomicU64,
    udp_ingress_drain_budget_hits: AtomicU64,
    udp_ingress_syscalls: AtomicU64,
    udp_ingress_datagrams: AtomicU64,
    udp_ingress_syscall_batches: AtomicU64,
    udp_ingress_batch_datagrams_total: AtomicU64,
    udp_ingress_batch_max: AtomicU64,
    udp_ingress_would_block: AtomicU64,
    udp_ingress_truncated: AtomicU64,
    udp_ingress_control_truncated: AtomicU64,
    udp_ingress_invalid: AtomicU64,
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
    dns_udp_send_syscalls: AtomicU64,
    dns_udp_send_datagrams: AtomicU64,
    dns_udp_send_batches: AtomicU64,
    dns_udp_send_batch_datagrams_total: AtomicU64,
    dns_udp_send_batch_max: AtomicU64,
    dns_udp_recv_syscalls: AtomicU64,
    dns_udp_recv_datagrams: AtomicU64,
    proxy_dns_udp_executors_opened: AtomicU64,
    proxy_dns_udp_executors_reused: AtomicU64,
    proxy_dns_udp_executors_reset: AtomicU64,
    proxy_dns_health_forwarders_current: AtomicU64,
    proxy_dns_health_leases_current: AtomicU64,
    proxy_dns_udp_queued_current: AtomicU64,
    proxy_dns_udp_queued_bytes_current: AtomicU64,
    proxy_dns_udp_pending_current: AtomicU64,
    proxy_dns_udp_pending_bytes_current: AtomicU64,
    proxy_dns_udp_pending_metadata_bytes_current: AtomicU64,
    proxy_dns_udp_pending_metadata_bytes_maximum: AtomicU64,
    proxy_dns_udp_response_bytes_current: AtomicU64,
    proxy_dns_udp_response_bytes_maximum: AtomicU64,
    proxy_dns_udp_abandoned: AtomicU64,
    proxy_dns_udp_abandoned_bytes: AtomicU64,
    proxy_dns_udp_expired: AtomicU64,
    proxy_dns_udp_expired_bytes: AtomicU64,
    dns_transport_owners_current: AtomicU64,
    dns_transport_owners_maximum: AtomicU64,
    dns_transport_owners_evicted_current: AtomicU64,
    dns_transport_owners_evicted_maximum: AtomicU64,
    dns_transport_owner_bytes_current: AtomicU64,
    dns_transport_owner_bytes_maximum: AtomicU64,
    proxied_doh3_cleanup: ProxiedDoh3CleanupMetrics,
    udp_response_validated: AtomicU64,
    udp_response_compatibility_unverified: AtomicU64,
    udp_response_dropped: AtomicU64,
    udp_response_dropped_bytes: AtomicU64,
    ss2022_replay_active_windows_current: AtomicU64,
    ss2022_replay_quarantined_sessions_current: AtomicU64,
    ss2022_replay_retained_sessions_current: AtomicU64,
    ss2022_replay_retained_sessions_maximum: AtomicU64,
    ss2022_replay_estimated_bytes_current: AtomicU64,
    ss2022_replay_estimated_bytes_maximum: AtomicU64,
    ss2022_replay_rejections: AtomicU64,
    ss2022_replay_lru_evictions: AtomicU64,
    ss2022_replay_ttl_expirations: AtomicU64,
    ss2022_replay_saturation_rejections: AtomicU64,
    udp_reply_queued: AtomicU64,
    udp_reply_queue_full: AtomicU64,
    udp_reply_sent: AtomicU64,
    udp_reply_syscalls: AtomicU64,
    udp_reply_datagrams: AtomicU64,
    udp_reply_batches: AtomicU64,
    udp_reply_batch_datagrams_total: AtomicU64,
    udp_reply_batch_max: AtomicU64,
    udp_reply_partial_failures: AtomicU64,
    udp_reply_send_would_block: AtomicU64,
    udp_reply_socket_recreated: AtomicU64,
    udp_reply_socket_idle_evicted: AtomicU64,
    udp_reply_failed: AtomicU64,
}

pub struct UdpIngressMetricObservation {
    pub packets: usize,
    pub truncated: usize,
    pub control_truncated: usize,
    pub invalid: usize,
    pub budget_hit: bool,
    pub syscalls: usize,
    pub syscall_batches: usize,
    pub batch_datagrams: usize,
    pub batch_max: usize,
    pub would_block: usize,
}

fn subtract_metric(metric: &AtomicU64, value: u64) {
    let updated = metric.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
        current.checked_sub(value)
    });
    debug_assert!(updated.is_ok(), "resident dataplane metric underflow");
}

impl ResidentDataplaneMetrics {
    pub fn observe_ss2022_replay(
        &self,
        previous: Ss2022UdpReplayMetricsSnapshot,
        current: Ss2022UdpReplayMetricsSnapshot,
    ) {
        adjust_current_metric(
            &self.ss2022_replay_active_windows_current,
            previous.active_windows,
            current.active_windows,
        );
        adjust_current_metric(
            &self.ss2022_replay_quarantined_sessions_current,
            previous.quarantined_sessions,
            current.quarantined_sessions,
        );
        let retained = adjust_current_metric(
            &self.ss2022_replay_retained_sessions_current,
            previous.retained_sessions,
            current.retained_sessions,
        );
        self.ss2022_replay_retained_sessions_maximum
            .fetch_max(retained, Ordering::Relaxed);
        let bytes = adjust_current_metric(
            &self.ss2022_replay_estimated_bytes_current,
            previous.estimated_bytes,
            current.estimated_bytes,
        );
        self.ss2022_replay_estimated_bytes_maximum
            .fetch_max(bytes, Ordering::Relaxed);
        self.ss2022_replay_rejections.fetch_add(
            current
                .replay_rejections
                .saturating_sub(previous.replay_rejections),
            Ordering::Relaxed,
        );
        self.ss2022_replay_lru_evictions.fetch_add(
            current.lru_evictions.saturating_sub(previous.lru_evictions),
            Ordering::Relaxed,
        );
        self.ss2022_replay_ttl_expirations.fetch_add(
            current
                .ttl_expirations
                .saturating_sub(previous.ttl_expirations),
            Ordering::Relaxed,
        );
        self.ss2022_replay_saturation_rejections.fetch_add(
            current
                .saturation_rejections
                .saturating_sub(previous.saturation_rejections),
            Ordering::Relaxed,
        );
    }

    pub fn dns_transport_owner_opened(&self, charged_bytes: usize) {
        let current = self
            .dns_transport_owners_current
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        self.dns_transport_owners_maximum
            .fetch_max(current, Ordering::Relaxed);
        let bytes = charged_bytes as u64;
        let current_bytes = self
            .dns_transport_owner_bytes_current
            .fetch_add(bytes, Ordering::Relaxed)
            .saturating_add(bytes);
        self.dns_transport_owner_bytes_maximum
            .fetch_max(current_bytes, Ordering::Relaxed);
    }

    pub fn dns_transport_owner_evicted(&self) {
        let current = self
            .dns_transport_owners_evicted_current
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        self.dns_transport_owners_evicted_maximum
            .fetch_max(current, Ordering::Relaxed);
    }

    pub fn dns_transport_owner_released(&self, charged_bytes: usize, evicted: bool) {
        subtract_metric(&self.dns_transport_owners_current, 1);
        subtract_metric(
            &self.dns_transport_owner_bytes_current,
            charged_bytes as u64,
        );
        if evicted {
            subtract_metric(&self.dns_transport_owners_evicted_current, 1);
        }
    }

    pub fn tcp_opened(&self) {
        self.active_tcp_connections.fetch_add(1, Ordering::Relaxed);
    }

    pub fn tcp_closed(&self) {
        self.active_tcp_connections.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn tcp_admitted(&self) {
        let active = self
            .tcp_admission_active
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        self.tcp_admission_maximum_active
            .fetch_max(active, Ordering::Relaxed);
        self.tcp_admission_accepted_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn tcp_admission_released(&self) {
        let _ = self.tcp_admission_active.fetch_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |active| Some(active.saturating_sub(1)),
        );
    }

    pub fn tcp_admission_waited(&self) {
        self.tcp_admission_wait_cycles
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn health_round_started(&self) {
        let active = self
            .health_rounds_active
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        self.health_rounds_maximum_active
            .fetch_max(active, Ordering::Relaxed);
        self.health_rounds_started_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn health_round_finished(&self, cancelled: bool) {
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

    pub fn health_resuscitation_queued(&self) {
        self.health_resuscitation_queued
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn health_resuscitation_queue_full(&self) {
        self.health_resuscitation_queue_full
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn health_resuscitation_disconnected(&self) {
        self.health_resuscitation_disconnected
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn udp_opened(&self) {
        self.active_udp_sessions.fetch_add(1, Ordering::Relaxed);
    }

    pub fn udp_session_dispatch_queued(&self) {
        self.udp_session_dispatch_queued
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn udp_session_dispatch_queue_full(&self) {
        self.udp_session_dispatch_queue_full
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn udp_session_created(&self) {
        self.udp_session_created.fetch_add(1, Ordering::Relaxed);
    }

    pub fn udp_session_reused(&self) {
        self.udp_session_reused.fetch_add(1, Ordering::Relaxed);
    }

    pub fn udp_session_admission_rejected(&self) {
        self.udp_session_admission_rejected
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn udp_session_queue_full(&self) {
        self.udp_session_queue_full.fetch_add(1, Ordering::Relaxed);
    }

    pub fn udp_session_stale_recreated(&self) {
        self.udp_session_stale_recreated
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn udp_session_actor_panicked(&self) {
        self.udp_session_actor_panicked
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn udp_session_cleanup_notification_failed(&self) {
        self.udp_session_cleanup_notification_failed
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn udp_session_shutdown_deadline_hit(&self) {
        self.udp_session_shutdown_deadline_hits
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn udp_generation_pin_unavailable(&self) {
        self.udp_generation_pin_unavailable
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn udp_closed(&self) {
        self.active_udp_sessions.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn add_upload(&self, bytes: usize) {
        self.upload_total.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    pub fn add_download(&self, bytes: usize) {
        self.download_total
            .fetch_add(bytes as u64, Ordering::Relaxed);
    }

    pub fn record_udp_ingress_batch(&self, observation: UdpIngressMetricObservation) {
        let UdpIngressMetricObservation {
            packets,
            truncated,
            control_truncated,
            invalid,
            budget_hit,
            syscalls,
            syscall_batches,
            batch_datagrams,
            batch_max,
            would_block,
        } = observation;
        self.udp_ingress_packets
            .fetch_add(packets as u64, Ordering::Relaxed);
        self.udp_ingress_truncated
            .fetch_add(truncated as u64, Ordering::Relaxed);
        self.udp_ingress_control_truncated
            .fetch_add(control_truncated as u64, Ordering::Relaxed);
        self.udp_ingress_invalid
            .fetch_add(invalid as u64, Ordering::Relaxed);
        self.udp_ingress_datagrams.fetch_add(
            packets
                .saturating_add(truncated)
                .saturating_add(control_truncated)
                .saturating_add(invalid) as u64,
            Ordering::Relaxed,
        );
        self.udp_ingress_syscalls
            .fetch_add(syscalls as u64, Ordering::Relaxed);
        self.udp_ingress_syscall_batches
            .fetch_add(syscall_batches as u64, Ordering::Relaxed);
        self.udp_ingress_batch_datagrams_total
            .fetch_add(batch_datagrams as u64, Ordering::Relaxed);
        self.udp_ingress_batch_max
            .fetch_max(batch_max as u64, Ordering::Relaxed);
        self.udp_ingress_would_block
            .fetch_add(would_block as u64, Ordering::Relaxed);
        self.udp_ingress_drain_batches
            .fetch_add(1, Ordering::Relaxed);
        if budget_hit {
            self.udp_ingress_drain_budget_hits
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn udp_reply_queued(&self) {
        self.udp_reply_queued.fetch_add(1, Ordering::Relaxed);
    }

    pub fn dns_udp_actor_opened(&self) {
        self.dns_udp_actors_opened.fetch_add(1, Ordering::Relaxed);
    }

    pub fn dns_udp_actor_closed(&self, fatal: bool) {
        self.dns_udp_actors_closed.fetch_add(1, Ordering::Relaxed);
        if fatal {
            self.dns_udp_actor_fatal_exits
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn dns_udp_forwarder_recreated(&self) {
        self.dns_udp_forwarder_recreated
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn dns_udp_queue_wait_timeout(&self) {
        self.dns_udp_queue_wait_timeouts
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn dns_udp_pending_added(&self) {
        let current = self
            .dns_udp_pending_current
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        self.dns_udp_pending_maximum
            .fetch_max(current, Ordering::Relaxed);
    }

    pub fn dns_udp_pending_removed(&self, count: usize) {
        let count = count as u64;
        let _ = self.dns_udp_pending_current.fetch_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |current| Some(current.saturating_sub(count)),
        );
    }

    pub fn dns_udp_pending_rejected(&self) {
        self.dns_udp_pending_rejected
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn dns_udp_id_exhausted(&self) {
        self.dns_udp_id_exhausted.fetch_add(1, Ordering::Relaxed);
    }

    pub fn dns_udp_retry(&self) {
        self.dns_udp_retries.fetch_add(1, Ordering::Relaxed);
    }

    pub fn dns_udp_shutdown_failed_requests(&self, count: usize) {
        self.dns_udp_shutdown_requests_failed
            .fetch_add(count as u64, Ordering::Relaxed);
    }

    pub fn dns_udp_send_syscall(&self, batch_size: usize) {
        self.dns_udp_send_syscalls.fetch_add(1, Ordering::Relaxed);
        if batch_size > 1 {
            self.dns_udp_send_batches.fetch_add(1, Ordering::Relaxed);
            self.dns_udp_send_batch_datagrams_total
                .fetch_add(batch_size as u64, Ordering::Relaxed);
            self.dns_udp_send_batch_max
                .fetch_max(batch_size as u64, Ordering::Relaxed);
        }
    }

    pub fn dns_udp_datagrams_sent(&self, count: usize) {
        self.dns_udp_send_datagrams
            .fetch_add(count as u64, Ordering::Relaxed);
    }

    pub fn dns_udp_recv_syscall(&self) {
        self.dns_udp_recv_syscalls.fetch_add(1, Ordering::Relaxed);
    }

    pub fn dns_udp_datagram_received(&self) {
        self.dns_udp_recv_datagrams.fetch_add(1, Ordering::Relaxed);
    }

    pub fn proxy_dns_udp_executor_opened(&self) {
        self.proxy_dns_udp_executors_opened
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn proxy_dns_udp_executor_reused(&self) {
        self.proxy_dns_udp_executors_reused
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn proxy_dns_udp_executor_reset(&self) {
        self.proxy_dns_udp_executors_reset
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn proxy_dns_health_forwarder_opened(&self) {
        self.proxy_dns_health_forwarders_current
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn proxy_dns_health_forwarder_closed(&self) {
        subtract_metric(&self.proxy_dns_health_forwarders_current, 1);
    }

    pub fn proxy_dns_health_lease_acquired(&self) {
        self.proxy_dns_health_leases_current
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn proxy_dns_health_lease_released(&self) {
        subtract_metric(&self.proxy_dns_health_leases_current, 1);
    }

    pub fn proxy_dns_udp_queued_added(&self, bytes: usize) {
        self.proxy_dns_udp_queued_current
            .fetch_add(1, Ordering::Relaxed);
        self.proxy_dns_udp_queued_bytes_current
            .fetch_add(bytes as u64, Ordering::Relaxed);
    }

    pub fn proxy_dns_udp_queued_removed(&self, bytes: usize) {
        subtract_metric(&self.proxy_dns_udp_queued_current, 1);
        subtract_metric(&self.proxy_dns_udp_queued_bytes_current, bytes as u64);
    }

    pub fn proxy_dns_udp_pending_added(&self, bytes: usize) {
        self.proxy_dns_udp_pending_current
            .fetch_add(1, Ordering::Relaxed);
        self.proxy_dns_udp_pending_bytes_current
            .fetch_add(bytes as u64, Ordering::Relaxed);
        self.dns_udp_pending_added();
    }

    pub fn proxy_dns_udp_pending_removed(&self, bytes: usize) {
        subtract_metric(&self.proxy_dns_udp_pending_current, 1);
        subtract_metric(&self.proxy_dns_udp_pending_bytes_current, bytes as u64);
        self.dns_udp_pending_removed(1);
    }

    pub fn proxy_dns_udp_pending_metadata_added(&self, bytes: usize) {
        let bytes = bytes as u64;
        let current = self
            .proxy_dns_udp_pending_metadata_bytes_current
            .fetch_add(bytes, Ordering::Relaxed)
            .saturating_add(bytes);
        self.proxy_dns_udp_pending_metadata_bytes_maximum
            .fetch_max(current, Ordering::Relaxed);
    }

    pub fn proxy_dns_udp_pending_metadata_removed(&self, bytes: usize) {
        subtract_metric(
            &self.proxy_dns_udp_pending_metadata_bytes_current,
            bytes as u64,
        );
    }

    pub fn proxy_dns_udp_response_added(&self, bytes: usize) {
        let bytes = bytes as u64;
        let current = self
            .proxy_dns_udp_response_bytes_current
            .fetch_add(bytes, Ordering::Relaxed)
            .saturating_add(bytes);
        self.proxy_dns_udp_response_bytes_maximum
            .fetch_max(current, Ordering::Relaxed);
    }

    pub fn proxy_dns_udp_response_removed(&self, bytes: usize) {
        subtract_metric(&self.proxy_dns_udp_response_bytes_current, bytes as u64);
    }

    pub fn proxy_dns_udp_abandoned(&self, bytes: usize) {
        self.proxy_dns_udp_abandoned.fetch_add(1, Ordering::Relaxed);
        self.proxy_dns_udp_abandoned_bytes
            .fetch_add(bytes as u64, Ordering::Relaxed);
    }

    pub fn proxy_dns_udp_expired(&self, bytes: usize) {
        self.proxy_dns_udp_expired.fetch_add(1, Ordering::Relaxed);
        self.proxy_dns_udp_expired_bytes
            .fetch_add(bytes as u64, Ordering::Relaxed);
    }

    pub fn udp_response_validated(&self) {
        self.udp_response_validated.fetch_add(1, Ordering::Relaxed);
    }

    pub fn udp_response_compatibility_unverified(&self) {
        self.udp_response_compatibility_unverified
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn udp_response_dropped(&self, bytes: usize) {
        self.udp_response_dropped.fetch_add(1, Ordering::Relaxed);
        self.udp_response_dropped_bytes
            .fetch_add(bytes as u64, Ordering::Relaxed);
    }

    pub fn dns_fast_path_queued(&self) {
        self.dns_fast_path_queued.fetch_add(1, Ordering::Relaxed);
    }

    pub fn dns_fast_path_queue_full(&self) {
        self.dns_fast_path_queue_full
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn dns_fast_path_started(&self) {
        let active = self
            .dns_fast_path_active
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        self.dns_fast_path_maximum_active
            .fetch_max(active, Ordering::Relaxed);
    }

    pub fn dns_fast_path_finished(&self, failed: bool) {
        self.dns_fast_path_released();
        if failed {
            self.dns_fast_path_failed.fetch_add(1, Ordering::Relaxed);
        }
        self.dns_fast_path_completed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn dns_fast_path_rejected(&self) {
        self.dns_fast_path_queue_full();
        self.dns_fast_path_failed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn udp_reply_queue_full(&self) {
        self.udp_reply_queue_full.fetch_add(1, Ordering::Relaxed);
    }

    pub fn udp_reply_sent(&self) {
        self.udp_reply_sent.fetch_add(1, Ordering::Relaxed);
        self.udp_reply_datagrams.fetch_add(1, Ordering::Relaxed);
    }

    pub fn udp_reply_sent_count(&self, count: usize) {
        self.udp_reply_sent
            .fetch_add(count as u64, Ordering::Relaxed);
        self.udp_reply_datagrams
            .fetch_add(count as u64, Ordering::Relaxed);
    }

    pub fn udp_reply_send_syscall(&self, batch_size: usize) {
        self.udp_reply_syscalls.fetch_add(1, Ordering::Relaxed);
        if batch_size > 1 {
            self.udp_reply_batches.fetch_add(1, Ordering::Relaxed);
            self.udp_reply_batch_datagrams_total
                .fetch_add(batch_size as u64, Ordering::Relaxed);
            self.udp_reply_batch_max
                .fetch_max(batch_size as u64, Ordering::Relaxed);
        }
    }

    pub fn udp_reply_partial_failure(&self) {
        self.udp_reply_partial_failures
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn udp_reply_send_would_block(&self) {
        self.udp_reply_send_would_block
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn dns_fast_path_cancelled(&self) {
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

    pub fn udp_reply_socket_recreated(&self) {
        self.udp_reply_socket_recreated
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn udp_reply_socket_idle_evicted(&self, count: usize) {
        self.udp_reply_socket_idle_evicted
            .fetch_add(count as u64, Ordering::Relaxed);
    }

    pub fn udp_reply_failed(&self) {
        self.udp_reply_failed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> Value {
        let traffic = self.traffic_counters();
        let mut snapshot = json!({
            "uploadTotal": traffic.upload_total,
            "downloadTotal": traffic.download_total,
            "activeTcpConnections": traffic.active_tcp_connections,
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
            "activeUdpSessions": traffic.active_udp_sessions,
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
            "udpGenerationPinUnavailable": self.udp_generation_pin_unavailable.load(Ordering::Relaxed),
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
            "proxyDnsHealthForwardersCurrent": self.proxy_dns_health_forwarders_current.load(Ordering::Relaxed),
            "proxyDnsHealthLeasesCurrent": self.proxy_dns_health_leases_current.load(Ordering::Relaxed),
            "proxyDnsUdpQueuedCurrent": self.proxy_dns_udp_queued_current.load(Ordering::Relaxed),
            "proxyDnsUdpQueuedBytesCurrent": self.proxy_dns_udp_queued_bytes_current.load(Ordering::Relaxed),
            "proxyDnsUdpPendingCurrent": self.proxy_dns_udp_pending_current.load(Ordering::Relaxed),
            "proxyDnsUdpPendingBytesCurrent": self.proxy_dns_udp_pending_bytes_current.load(Ordering::Relaxed),
            "proxyDnsUdpPendingMetadataBytesCurrent": self.proxy_dns_udp_pending_metadata_bytes_current.load(Ordering::Relaxed),
            "proxyDnsUdpPendingMetadataBytesMaximum": self.proxy_dns_udp_pending_metadata_bytes_maximum.load(Ordering::Relaxed),
            "proxyDnsUdpResponseBytesCurrent": self.proxy_dns_udp_response_bytes_current.load(Ordering::Relaxed),
            "proxyDnsUdpResponseBytesMaximum": self.proxy_dns_udp_response_bytes_maximum.load(Ordering::Relaxed),
            "proxyDnsUdpAbandoned": self.proxy_dns_udp_abandoned.load(Ordering::Relaxed),
            "proxyDnsUdpAbandonedBytes": self.proxy_dns_udp_abandoned_bytes.load(Ordering::Relaxed),
            "proxyDnsUdpExpired": self.proxy_dns_udp_expired.load(Ordering::Relaxed),
            "proxyDnsUdpExpiredBytes": self.proxy_dns_udp_expired_bytes.load(Ordering::Relaxed),
            "dnsTransportOwnersCurrent": self.dns_transport_owners_current.load(Ordering::Relaxed),
            "dnsTransportOwnersMaximum": self.dns_transport_owners_maximum.load(Ordering::Relaxed),
            "dnsTransportOwnersEvictedCurrent": self.dns_transport_owners_evicted_current.load(Ordering::Relaxed),
            "dnsTransportOwnersEvictedMaximum": self.dns_transport_owners_evicted_maximum.load(Ordering::Relaxed),
            "dnsTransportOwnerBytesCurrent": self.dns_transport_owner_bytes_current.load(Ordering::Relaxed),
            "dnsTransportOwnerBytesMaximum": self.dns_transport_owner_bytes_maximum.load(Ordering::Relaxed),
            "proxiedDoh3Cleanup": self.proxied_doh3_cleanup.snapshot(),
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
        });
        snapshot["udpIngressSyscalls"] = json!(self.udp_ingress_syscalls.load(Ordering::Relaxed));
        snapshot["udpIngressDatagrams"] = json!(self.udp_ingress_datagrams.load(Ordering::Relaxed));
        snapshot["udpIngressBatches"] =
            json!(self.udp_ingress_syscall_batches.load(Ordering::Relaxed));
        snapshot["udpIngressBatchDatagramsTotal"] = json!(
            self.udp_ingress_batch_datagrams_total
                .load(Ordering::Relaxed)
        );
        snapshot["udpIngressBatchMax"] = json!(self.udp_ingress_batch_max.load(Ordering::Relaxed));
        snapshot["udpIngressWouldBlock"] =
            json!(self.udp_ingress_would_block.load(Ordering::Relaxed));
        snapshot["udpIngressControlTruncated"] =
            json!(self.udp_ingress_control_truncated.load(Ordering::Relaxed));
        snapshot["udpIngressInvalid"] = json!(self.udp_ingress_invalid.load(Ordering::Relaxed));
        snapshot["udpReplySyscalls"] = json!(self.udp_reply_syscalls.load(Ordering::Relaxed));
        snapshot["udpReplyDatagrams"] = json!(self.udp_reply_datagrams.load(Ordering::Relaxed));
        snapshot["udpReplyBatches"] = json!(self.udp_reply_batches.load(Ordering::Relaxed));
        snapshot["udpReplyBatchDatagramsTotal"] =
            json!(self.udp_reply_batch_datagrams_total.load(Ordering::Relaxed));
        snapshot["udpReplyBatchMax"] = json!(self.udp_reply_batch_max.load(Ordering::Relaxed));
        snapshot["udpReplyPartialFailures"] =
            json!(self.udp_reply_partial_failures.load(Ordering::Relaxed));
        snapshot["dnsUdpSendSyscalls"] = json!(self.dns_udp_send_syscalls.load(Ordering::Relaxed));
        snapshot["dnsUdpSendDatagrams"] =
            json!(self.dns_udp_send_datagrams.load(Ordering::Relaxed));
        snapshot["dnsUdpSendBatches"] = json!(self.dns_udp_send_batches.load(Ordering::Relaxed));
        snapshot["dnsUdpSendBatchDatagramsTotal"] = json!(
            self.dns_udp_send_batch_datagrams_total
                .load(Ordering::Relaxed)
        );
        snapshot["dnsUdpSendBatchMax"] = json!(self.dns_udp_send_batch_max.load(Ordering::Relaxed));
        snapshot["dnsUdpRecvSyscalls"] = json!(self.dns_udp_recv_syscalls.load(Ordering::Relaxed));
        snapshot["dnsUdpRecvDatagrams"] =
            json!(self.dns_udp_recv_datagrams.load(Ordering::Relaxed));
        snapshot["ss2022Replay"] = json!({
            "activeWindowsCurrent": self.ss2022_replay_active_windows_current.load(Ordering::Relaxed),
            "quarantinedSessionsCurrent": self.ss2022_replay_quarantined_sessions_current.load(Ordering::Relaxed),
            "retainedSessionsCurrent": self.ss2022_replay_retained_sessions_current.load(Ordering::Relaxed),
            "retainedSessionsMaximum": self.ss2022_replay_retained_sessions_maximum.load(Ordering::Relaxed),
            "estimatedBytesCurrent": self.ss2022_replay_estimated_bytes_current.load(Ordering::Relaxed),
            "estimatedBytesMaximum": self.ss2022_replay_estimated_bytes_maximum.load(Ordering::Relaxed),
            "replayRejections": self.ss2022_replay_rejections.load(Ordering::Relaxed),
            "lruEvictions": self.ss2022_replay_lru_evictions.load(Ordering::Relaxed),
            "ttlExpirations": self.ss2022_replay_ttl_expirations.load(Ordering::Relaxed),
            "saturationRejections": self.ss2022_replay_saturation_rejections.load(Ordering::Relaxed),
        });
        snapshot
    }
}

fn adjust_current_metric(metric: &AtomicU64, previous: usize, current: usize) -> u64 {
    if current >= previous {
        let increase = current.saturating_sub(previous) as u64;
        metric
            .fetch_add(increase, Ordering::Relaxed)
            .saturating_add(increase)
    } else {
        let decrease = previous.saturating_sub(current) as u64;
        let prior = metric
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |aggregate| {
                aggregate.checked_sub(decrease)
            })
            .expect("SS2022 replay current metric cannot underflow");
        prior - decrease
    }
}

pub struct ResidentTcpConnectionGuard {
    metrics: Arc<ResidentDataplaneMetrics>,
}

pub struct ResidentUdpActivityGuard {
    metrics: Arc<ResidentDataplaneMetrics>,
}

impl ResidentUdpActivityGuard {
    pub fn new(metrics: Arc<ResidentDataplaneMetrics>) -> Self {
        metrics.udp_opened();
        Self { metrics }
    }
}

impl Drop for ResidentUdpActivityGuard {
    fn drop(&mut self) {
        self.metrics.udp_closed();
    }
}

impl ResidentTcpConnectionGuard {
    pub fn new(metrics: Arc<ResidentDataplaneMetrics>) -> Self {
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
    fn udp_activity_guard_closes_on_drop() {
        let metrics = Arc::new(ResidentDataplaneMetrics::default());
        {
            let _guard = ResidentUdpActivityGuard::new(Arc::clone(&metrics));
            assert_eq!(metrics.active_udp_sessions.load(Ordering::Relaxed), 1);
        }
        assert_eq!(metrics.active_udp_sessions.load(Ordering::Relaxed), 0);
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

    #[test]
    fn unavailable_udp_generation_pins_are_visible_without_dynamic_labels() {
        let metrics = ResidentDataplaneMetrics::default();
        metrics.udp_generation_pin_unavailable();
        metrics.udp_generation_pin_unavailable();

        assert_eq!(metrics.snapshot()["udpGenerationPinUnavailable"], 2);
    }

    #[test]
    fn ss2022_replay_metrics_aggregate_sessions_and_release_current_state() {
        let metrics = ResidentDataplaneMetrics::default();
        let first = Ss2022UdpReplayMetricsSnapshot {
            active_windows: 2,
            retained_sessions: 2,
            estimated_bytes: 1200,
            high_water_retained_sessions: 2,
            high_water_estimated_bytes: 1200,
            replay_rejections: 1,
            ..Ss2022UdpReplayMetricsSnapshot::default()
        };
        let second = Ss2022UdpReplayMetricsSnapshot {
            active_windows: 1,
            quarantined_sessions: 1,
            retained_sessions: 2,
            estimated_bytes: 800,
            high_water_retained_sessions: 2,
            high_water_estimated_bytes: 1200,
            replay_rejections: 2,
            lru_evictions: 1,
            ..Ss2022UdpReplayMetricsSnapshot::default()
        };
        metrics.observe_ss2022_replay(Ss2022UdpReplayMetricsSnapshot::default(), first);
        metrics.observe_ss2022_replay(first, second);
        let live = metrics.snapshot();
        assert_eq!(live["ss2022Replay"]["activeWindowsCurrent"], 1);
        assert_eq!(live["ss2022Replay"]["quarantinedSessionsCurrent"], 1);
        assert_eq!(live["ss2022Replay"]["retainedSessionsCurrent"], 2);
        assert_eq!(live["ss2022Replay"]["retainedSessionsMaximum"], 2);
        assert_eq!(live["ss2022Replay"]["estimatedBytesCurrent"], 800);
        assert_eq!(live["ss2022Replay"]["estimatedBytesMaximum"], 1200);
        assert_eq!(live["ss2022Replay"]["replayRejections"], 2);
        assert_eq!(live["ss2022Replay"]["lruEvictions"], 1);

        metrics.observe_ss2022_replay(second, Ss2022UdpReplayMetricsSnapshot::default());
        let closed = metrics.snapshot();
        assert_eq!(closed["ss2022Replay"]["activeWindowsCurrent"], 0);
        assert_eq!(closed["ss2022Replay"]["quarantinedSessionsCurrent"], 0);
        assert_eq!(closed["ss2022Replay"]["retainedSessionsCurrent"], 0);
        assert_eq!(closed["ss2022Replay"]["estimatedBytesCurrent"], 0);
        assert_eq!(closed["ss2022Replay"]["retainedSessionsMaximum"], 2);
        assert_eq!(closed["ss2022Replay"]["replayRejections"], 2);
    }
}
