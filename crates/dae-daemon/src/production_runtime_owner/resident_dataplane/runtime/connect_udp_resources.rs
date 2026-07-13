use super::*;
use dae_outbound::shared_transport::MasqueCapsuleLimits;

const CONNECT_UDP_MAX_DATAGRAM_PAYLOAD_BYTES: usize = 64 * 1_024;
const CONNECT_UDP_MAX_CAPSULE_PAYLOAD_BYTES: usize = CONNECT_UDP_MAX_DATAGRAM_PAYLOAD_BYTES + 8;
const CONNECT_UDP_MAX_CAPSULE_BUFFERED_BYTES: usize = CONNECT_UDP_MAX_CAPSULE_PAYLOAD_BYTES + 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ResidentConnectUdpRuntimePlan {
    pub(crate) generation: u64,
    pub(crate) profile: &'static str,
    pub(crate) h2_pool_connections: usize,
    pub(crate) h3_pool_connections: usize,
    pub(crate) sessions_per_connection: usize,
    pub(crate) h3_command_queue_depth: usize,
    pub(crate) h3_session_queue_depth: usize,
    pub(crate) h3_datagram_buffer_bytes: usize,
    pub(crate) h3_keep_alive_interval: Duration,
    pub(crate) h3_idle_timeout: Duration,
    pub(crate) capsule_limits: MasqueCapsuleLimits,
}

impl ResidentConnectUdpRuntimePlan {
    pub(crate) fn from_profile(generation: u64, profile: ResidentRuntimeProfile) -> Self {
        Self {
            generation,
            profile: profile.name(),
            h2_pool_connections: profile.connect_udp_h2_pool_connections_default(),
            h3_pool_connections: profile.connect_udp_h3_pool_connections_default(),
            sessions_per_connection: profile.connect_udp_sessions_per_connection_default(),
            h3_command_queue_depth: profile.connect_udp_h3_command_queue_depth_default(),
            h3_session_queue_depth: profile.connect_udp_h3_session_queue_depth_default(),
            h3_datagram_buffer_bytes: profile.connect_udp_h3_datagram_buffer_bytes_default(),
            h3_keep_alive_interval: Duration::from_secs(
                profile.connect_udp_h3_keep_alive_seconds_default(),
            ),
            h3_idle_timeout: Duration::from_secs(
                profile.connect_udp_h3_idle_timeout_seconds_default(),
            ),
            capsule_limits: MasqueCapsuleLimits {
                max_buffered_bytes: CONNECT_UDP_MAX_CAPSULE_BUFFERED_BYTES,
                max_capsule_payload_bytes: CONNECT_UDP_MAX_CAPSULE_PAYLOAD_BYTES,
                max_datagram_payload_bytes: CONNECT_UDP_MAX_DATAGRAM_PAYLOAD_BYTES,
            },
        }
    }

    pub(crate) fn standalone() -> Self {
        let selection = ResidentRuntimeProfileSelection::selected();
        Self::from_profile(0, selection.profile)
    }

    pub(crate) fn to_value(self) -> Value {
        json!({
            "generation": self.generation,
            "profile": self.profile,
            "h2PoolConnections": self.h2_pool_connections,
            "h3PoolConnections": self.h3_pool_connections,
            "sessionsPerConnection": self.sessions_per_connection,
            "h3CommandQueueDepth": self.h3_command_queue_depth,
            "h3SessionQueueDepth": self.h3_session_queue_depth,
            "h3DatagramBufferBytes": self.h3_datagram_buffer_bytes,
            "h3KeepAliveMs": self.h3_keep_alive_interval.as_millis(),
            "h3IdleTimeoutMs": self.h3_idle_timeout.as_millis(),
            "capsuleBufferedBytes": self.capsule_limits.max_buffered_bytes,
            "capsulePayloadBytes": self.capsule_limits.max_capsule_payload_bytes,
            "datagramPayloadBytes": self.capsule_limits.max_datagram_payload_bytes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profiles_bound_connect_udp_resources_monotonically() {
        let low = ResidentConnectUdpRuntimePlan::from_profile(7, ResidentRuntimeProfile::LowMemory);
        let balanced =
            ResidentConnectUdpRuntimePlan::from_profile(7, ResidentRuntimeProfile::Balanced);
        let high =
            ResidentConnectUdpRuntimePlan::from_profile(7, ResidentRuntimeProfile::HighPerformance);
        assert!(low.h2_pool_connections <= balanced.h2_pool_connections);
        assert!(balanced.h2_pool_connections <= high.h2_pool_connections);
        assert!(low.sessions_per_connection <= balanced.sessions_per_connection);
        assert!(balanced.sessions_per_connection <= high.sessions_per_connection);
        assert!(low.h3_session_queue_depth <= balanced.h3_session_queue_depth);
        assert!(balanced.h3_session_queue_depth <= high.h3_session_queue_depth);
        assert!(low.h3_datagram_buffer_bytes <= balanced.h3_datagram_buffer_bytes);
        assert!(balanced.h3_datagram_buffer_bytes <= high.h3_datagram_buffer_bytes);
        assert_eq!(low.generation, 7);
        assert_eq!(low.capsule_limits, high.capsule_limits);
    }
}
