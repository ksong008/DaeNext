use super::*;

#[path = "resource_profile/auto.rs"]
mod auto;
use self::auto::*;

pub(crate) const RESIDENT_RUNTIME_PROFILE_ENV: &str = "RESIDENT_RUNTIME_PROFILE";
const RESIDENT_RUNTIME_PROFILE_LOW_MEMORY: &str = "low-memory";
const RESIDENT_RUNTIME_PROFILE_BALANCED: &str = "balanced";
const RESIDENT_RUNTIME_PROFILE_HIGH_PERFORMANCE: &str = "high-performance";

const LOW_MEMORY_TCP_RUNTIME_WORKERS_MAX: usize = 2;
const BALANCED_TCP_RUNTIME_WORKERS_MAX: usize = 4;
const HIGH_PERFORMANCE_TCP_RUNTIME_WORKERS_MAX: usize = 8;
const LOW_MEMORY_TCP_CONNECTION_LIMIT: usize = 256;
const BALANCED_TCP_CONNECTION_LIMIT: usize = 1_024;
const HIGH_PERFORMANCE_TCP_CONNECTION_LIMIT: usize = 4_096;
const LOW_MEMORY_UDP_SESSION_LIMIT: usize = 128;
const BALANCED_UDP_SESSION_LIMIT: usize = 512;
const HIGH_PERFORMANCE_UDP_SESSION_LIMIT: usize = 1_024;
const LOW_MEMORY_UDP_SESSION_QUEUE_DEPTH: usize = 32;
const BALANCED_UDP_SESSION_QUEUE_DEPTH: usize = 128;
const HIGH_PERFORMANCE_UDP_SESSION_QUEUE_DEPTH: usize = 256;
const LOW_MEMORY_UDP_RUNTIME_SHARDS_MAX: usize = 1;
const BALANCED_UDP_RUNTIME_SHARDS_MAX: usize = 4;
const HIGH_PERFORMANCE_UDP_RUNTIME_SHARDS_MAX: usize = 8;
const LOW_MEMORY_UDP_DISPATCH_QUEUE_DEPTH: usize = 128;
const BALANCED_UDP_DISPATCH_QUEUE_DEPTH: usize = 512;
const HIGH_PERFORMANCE_UDP_DISPATCH_QUEUE_DEPTH: usize = 2_048;
const LOW_MEMORY_UDP_REPLY_SOCKET_IDLE_SECONDS: u64 = 60;
const BALANCED_UDP_REPLY_SOCKET_IDLE_SECONDS: u64 = 180;
const HIGH_PERFORMANCE_UDP_REPLY_SOCKET_IDLE_SECONDS: u64 = 300;
const LOW_MEMORY_UDP_DIRECT_RESPONSE_BUFFER_IDLE_SECONDS: u64 = 15;
const BALANCED_UDP_DIRECT_RESPONSE_BUFFER_IDLE_SECONDS: u64 = 30;
const HIGH_PERFORMANCE_UDP_DIRECT_RESPONSE_BUFFER_IDLE_SECONDS: u64 = 60;
const LOW_MEMORY_UDP_QUEUED_PAYLOAD_BYTES: usize = 8 * 1024 * 1024;
const BALANCED_UDP_QUEUED_PAYLOAD_BYTES: usize = 32 * 1024 * 1024;
const HIGH_PERFORMANCE_UDP_QUEUED_PAYLOAD_BYTES: usize = 128 * 1024 * 1024;
const LOW_MEMORY_QUIC_ENDPOINT_LIMIT: usize = 8;
const BALANCED_QUIC_ENDPOINT_LIMIT: usize = 32;
const HIGH_PERFORMANCE_QUIC_ENDPOINT_LIMIT: usize = 128;
const LOW_MEMORY_QUIC_ENDPOINT_CHARGED_BYTES: usize = 16 * 1024 * 1024;
const BALANCED_QUIC_ENDPOINT_CHARGED_BYTES: usize = 64 * 1024 * 1024;
const HIGH_PERFORMANCE_QUIC_ENDPOINT_CHARGED_BYTES: usize = 256 * 1024 * 1024;
const LOW_MEMORY_QUIC_UDP_FRAGMENT_PENDING_PACKETS: usize = 16;
const BALANCED_QUIC_UDP_FRAGMENT_PENDING_PACKETS: usize = 64;
const HIGH_PERFORMANCE_QUIC_UDP_FRAGMENT_PENDING_PACKETS: usize = 256;
const LOW_MEMORY_QUIC_UDP_FRAGMENT_PENDING_BYTES: usize = 128 * 1024;
const BALANCED_QUIC_UDP_FRAGMENT_PENDING_BYTES: usize = 512 * 1024;
const HIGH_PERFORMANCE_QUIC_UDP_FRAGMENT_PENDING_BYTES: usize = 2 * 1024 * 1024;
const LOW_MEMORY_QUIC_UDP_PACKET_ID_LEASES: usize = 256;
const BALANCED_QUIC_UDP_PACKET_ID_LEASES: usize = 1_024;
const HIGH_PERFORMANCE_QUIC_UDP_PACKET_ID_LEASES: usize = 4_096;
const LOW_MEMORY_QUIC_UDP_PMTU_RETRIES: usize = 2;
const BALANCED_QUIC_UDP_PMTU_RETRIES: usize = 3;
const HIGH_PERFORMANCE_QUIC_UDP_PMTU_RETRIES: usize = 4;
const QUIC_UDP_FRAGMENT_TTL_SECONDS: u64 = 10;
const QUIC_UDP_PACKET_ID_LEASE_TTL_SECONDS: u64 = 10;
const QUIC_UDP_FRAGMENT_QUARANTINE_TTL_SECONDS: u64 = 10;
const LOW_MEMORY_HYSTERIA2_OWNER_LIMIT: usize = 8;
const BALANCED_HYSTERIA2_OWNER_LIMIT: usize = 32;
const HIGH_PERFORMANCE_HYSTERIA2_OWNER_LIMIT: usize = 128;
const LOW_MEMORY_HYSTERIA2_OWNER_COMMAND_QUEUE_DEPTH: usize = 64;
const BALANCED_HYSTERIA2_OWNER_COMMAND_QUEUE_DEPTH: usize = 256;
const HIGH_PERFORMANCE_HYSTERIA2_OWNER_COMMAND_QUEUE_DEPTH: usize = 1_024;
const LOW_MEMORY_HYSTERIA2_LOGICAL_LEASE_LIMIT: usize = 128;
const BALANCED_HYSTERIA2_LOGICAL_LEASE_LIMIT: usize = 1_024;
const HIGH_PERFORMANCE_HYSTERIA2_LOGICAL_LEASE_LIMIT: usize = 4_096;
const LOW_MEMORY_HYSTERIA2_UDP_SESSION_LIMIT: usize = 32;
const BALANCED_HYSTERIA2_UDP_SESSION_LIMIT: usize = 256;
const HIGH_PERFORMANCE_HYSTERIA2_UDP_SESSION_LIMIT: usize = 1_024;
const LOW_MEMORY_HYSTERIA2_UDP_SESSION_QUEUE_DEPTH: usize = 32;
const BALANCED_HYSTERIA2_UDP_SESSION_QUEUE_DEPTH: usize = 128;
const HIGH_PERFORMANCE_HYSTERIA2_UDP_SESSION_QUEUE_DEPTH: usize = 256;
const LOW_MEMORY_HYSTERIA2_UDP_SESSION_QUEUE_BYTES: usize = 128 * 1024;
const BALANCED_HYSTERIA2_UDP_SESSION_QUEUE_BYTES: usize = 256 * 1024;
const HIGH_PERFORMANCE_HYSTERIA2_UDP_SESSION_QUEUE_BYTES: usize = 512 * 1024;
const LOW_MEMORY_HYSTERIA2_UDP_OWNER_QUEUE_BYTES: usize = 2 * 1024 * 1024;
const BALANCED_HYSTERIA2_UDP_OWNER_QUEUE_BYTES: usize = 16 * 1024 * 1024;
const HIGH_PERFORMANCE_HYSTERIA2_UDP_OWNER_QUEUE_BYTES: usize = 64 * 1024 * 1024;
const LOW_MEMORY_HYSTERIA2_UDP_SESSION_QUARANTINE_LIMIT: usize = 128;
const BALANCED_HYSTERIA2_UDP_SESSION_QUARANTINE_LIMIT: usize = 1_024;
const HIGH_PERFORMANCE_HYSTERIA2_UDP_SESSION_QUARANTINE_LIMIT: usize = 4_096;
const HYSTERIA2_UDP_SESSION_QUARANTINE_TTL_SECONDS: u64 = 10;
const LOW_MEMORY_HYSTERIA2_RETRY_COOLDOWN_SECONDS: u64 = 5;
const BALANCED_HYSTERIA2_RETRY_COOLDOWN_SECONDS: u64 = 3;
const HIGH_PERFORMANCE_HYSTERIA2_RETRY_COOLDOWN_SECONDS: u64 = 1;
const LOW_MEMORY_HYSTERIA2_PORT_HOP_RESOLVED_CANDIDATE_LIMIT: usize = 8_192;
const BALANCED_HYSTERIA2_PORT_HOP_RESOLVED_CANDIDATE_LIMIT: usize = 32_768;
const HIGH_PERFORMANCE_HYSTERIA2_PORT_HOP_RESOLVED_CANDIDATE_LIMIT: usize = 131_072;
const HYSTERIA2_PORT_HOP_TRANSITION_SOCKET_LIMIT: usize = 3;
const LOW_MEMORY_TUIC_OWNER_LIMIT: usize = 8;
const BALANCED_TUIC_OWNER_LIMIT: usize = 32;
const HIGH_PERFORMANCE_TUIC_OWNER_LIMIT: usize = 128;
const LOW_MEMORY_JUICITY_OWNER_LIMIT: usize = 8;
const BALANCED_JUICITY_OWNER_LIMIT: usize = 32;
const HIGH_PERFORMANCE_JUICITY_OWNER_LIMIT: usize = 128;
const LOW_MEMORY_JUICITY_CONNECTIONS_PER_POOL: usize = 2;
const BALANCED_JUICITY_CONNECTIONS_PER_POOL: usize = 4;
const HIGH_PERFORMANCE_JUICITY_CONNECTIONS_PER_POOL: usize = 8;
const LOW_MEMORY_JUICITY_LOGICAL_STREAMS_PER_CONNECTION: usize = 24;
const BALANCED_JUICITY_LOGICAL_STREAMS_PER_CONNECTION: usize = 64;
const HIGH_PERFORMANCE_JUICITY_LOGICAL_STREAMS_PER_CONNECTION: usize = 128;
const LOW_MEMORY_JUICITY_RESERVED_STREAMS_PER_CONNECTION: usize = 1;
const BALANCED_JUICITY_RESERVED_STREAMS_PER_CONNECTION: usize = 3;
const HIGH_PERFORMANCE_JUICITY_RESERVED_STREAMS_PER_CONNECTION: usize = 5;
const LOW_MEMORY_JUICITY_OWNER_COMMAND_QUEUE_DEPTH: usize = 32;
const BALANCED_JUICITY_OWNER_COMMAND_QUEUE_DEPTH: usize = 128;
const HIGH_PERFORMANCE_JUICITY_OWNER_COMMAND_QUEUE_DEPTH: usize = 512;
const LOW_MEMORY_JUICITY_RETRY_COOLDOWN_SECONDS: u64 = 5;
const BALANCED_JUICITY_RETRY_COOLDOWN_SECONDS: u64 = 3;
const HIGH_PERFORMANCE_JUICITY_RETRY_COOLDOWN_SECONDS: u64 = 1;
const LOW_MEMORY_ANYTLS_OWNER_LIMIT: usize = 8;
const BALANCED_ANYTLS_OWNER_LIMIT: usize = 32;
const HIGH_PERFORMANCE_ANYTLS_OWNER_LIMIT: usize = 128;
const LOW_MEMORY_ANYTLS_COMMAND_QUEUE_DEPTH: usize = 64;
const BALANCED_ANYTLS_COMMAND_QUEUE_DEPTH: usize = 256;
const HIGH_PERFORMANCE_ANYTLS_COMMAND_QUEUE_DEPTH: usize = 1_024;
const ANYTLS_PHYSICAL_CONTROL_QUEUE_DEPTH: usize = 1;
const LOW_MEMORY_ANYTLS_LOGICAL_BUFFER_BYTES: usize = 64 * 1024;
const BALANCED_ANYTLS_LOGICAL_BUFFER_BYTES: usize = 128 * 1024;
const HIGH_PERFORMANCE_ANYTLS_LOGICAL_BUFFER_BYTES: usize = 256 * 1024;
const LOW_MEMORY_ANYTLS_SID_QUARANTINE_LIMIT: usize = 128;
const BALANCED_ANYTLS_SID_QUARANTINE_LIMIT: usize = 1_024;
const HIGH_PERFORMANCE_ANYTLS_SID_QUARANTINE_LIMIT: usize = 4_096;
const ANYTLS_IDLE_SESSION_LIMIT: usize = 1;
const ANYTLS_IDLE_SESSION_TIMEOUT_SECONDS: u64 = 30;
const ANYTLS_IDLE_SESSION_PROBE_THRESHOLD_SECONDS: u64 = 3;
const ANYTLS_IDLE_SESSION_PROBE_TIMEOUT_SECONDS: u64 = 2;
const ANYTLS_SID_QUARANTINE_TTL_SECONDS: u64 = 10;
const LOW_MEMORY_TUIC_OWNER_COMMAND_QUEUE_DEPTH: usize = 64;
const BALANCED_TUIC_OWNER_COMMAND_QUEUE_DEPTH: usize = 256;
const HIGH_PERFORMANCE_TUIC_OWNER_COMMAND_QUEUE_DEPTH: usize = 1_024;
const LOW_MEMORY_TUIC_LOGICAL_LEASE_LIMIT: usize = 128;
const BALANCED_TUIC_LOGICAL_LEASE_LIMIT: usize = 1_024;
const HIGH_PERFORMANCE_TUIC_LOGICAL_LEASE_LIMIT: usize = 4_096;
const LOW_MEMORY_TUIC_UDP_ASSOCIATION_LIMIT: usize = 32;
const BALANCED_TUIC_UDP_ASSOCIATION_LIMIT: usize = 256;
const HIGH_PERFORMANCE_TUIC_UDP_ASSOCIATION_LIMIT: usize = 1_024;
const LOW_MEMORY_TUIC_UDP_ASSOCIATION_QUEUE_DEPTH: usize = 32;
const BALANCED_TUIC_UDP_ASSOCIATION_QUEUE_DEPTH: usize = 128;
const HIGH_PERFORMANCE_TUIC_UDP_ASSOCIATION_QUEUE_DEPTH: usize = 256;
const LOW_MEMORY_TUIC_UDP_ASSOCIATION_QUEUE_BYTES: usize = 128 * 1024;
const BALANCED_TUIC_UDP_ASSOCIATION_QUEUE_BYTES: usize = 256 * 1024;
const HIGH_PERFORMANCE_TUIC_UDP_ASSOCIATION_QUEUE_BYTES: usize = 512 * 1024;
const LOW_MEMORY_TUIC_UDP_OWNER_QUEUE_BYTES: usize = 2 * 1024 * 1024;
const BALANCED_TUIC_UDP_OWNER_QUEUE_BYTES: usize = 16 * 1024 * 1024;
const HIGH_PERFORMANCE_TUIC_UDP_OWNER_QUEUE_BYTES: usize = 64 * 1024 * 1024;
const LOW_MEMORY_TUIC_ASSOCIATION_QUARANTINE_LIMIT: usize = 128;
const BALANCED_TUIC_ASSOCIATION_QUARANTINE_LIMIT: usize = 1_024;
const HIGH_PERFORMANCE_TUIC_ASSOCIATION_QUARANTINE_LIMIT: usize = 4_096;
const TUIC_ASSOCIATION_QUARANTINE_TTL_SECONDS: u64 = 10;
const LOW_MEMORY_TUIC_RETRY_COOLDOWN_SECONDS: u64 = 5;
const BALANCED_TUIC_RETRY_COOLDOWN_SECONDS: u64 = 3;
const HIGH_PERFORMANCE_TUIC_RETRY_COOLDOWN_SECONDS: u64 = 1;
const LOW_MEMORY_DNS_FAST_PATH_CONCURRENCY: usize = 64;
const BALANCED_DNS_FAST_PATH_CONCURRENCY: usize = 512;
const HIGH_PERFORMANCE_DNS_FAST_PATH_CONCURRENCY: usize = 1_024;
const LOW_MEMORY_DNS_FAST_PATH_QUEUE_DEPTH: usize = 128;
const BALANCED_DNS_FAST_PATH_QUEUE_DEPTH: usize = 1_024;
const HIGH_PERFORMANCE_DNS_FAST_PATH_QUEUE_DEPTH: usize = 4_096;
const LOW_MEMORY_DNS_UDP_FORWARDER_QUEUE_DEPTH: usize = 256;
const BALANCED_DNS_UDP_FORWARDER_QUEUE_DEPTH: usize = 1_024;
const HIGH_PERFORMANCE_DNS_UDP_FORWARDER_QUEUE_DEPTH: usize = 4_096;
const LOW_MEMORY_DNS_UDP_FORWARDER_PENDING_LIMIT: usize = 256;
const BALANCED_DNS_UDP_FORWARDER_PENDING_LIMIT: usize = 1_024;
const HIGH_PERFORMANCE_DNS_UDP_FORWARDER_PENDING_LIMIT: usize = 4_096;
const LOW_MEMORY_DNS_UDP_FORWARDER_ATTEMPTS: usize = 2;
const BALANCED_DNS_UDP_FORWARDER_ATTEMPTS: usize = 3;
const HIGH_PERFORMANCE_DNS_UDP_FORWARDER_ATTEMPTS: usize = 3;
const LOW_MEMORY_DNS_PROXY_UDP_ACTORS: usize = 2;
const BALANCED_DNS_PROXY_UDP_ACTORS: usize = 8;
const HIGH_PERFORMANCE_DNS_PROXY_UDP_ACTORS: usize = 16;
const LOW_MEMORY_DATAPATH_POSTFLIGHT_INTERVAL_SECONDS: u64 = 60;
const BALANCED_DATAPATH_POSTFLIGHT_INTERVAL_SECONDS: u64 = 30;
const HIGH_PERFORMANCE_DATAPATH_POSTFLIGHT_INTERVAL_SECONDS: u64 = 15;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ResidentRuntimeProfile {
    LowMemory,
    Balanced,
    HighPerformance,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResidentRuntimeProfileSelection {
    pub(crate) profile: ResidentRuntimeProfile,
    source: &'static str,
    capacity_source: Option<&'static str>,
    effective_memory_bytes: Option<u64>,
    host_memory_bytes: Option<u64>,
    cgroup_limit_bytes: Option<u64>,
    invalid_value: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct QuicUdpDatagramResourceProfile {
    pending_fragment_packets: usize,
    pending_fragment_bytes: usize,
    packet_id_leases: usize,
    pmtu_retries: usize,
    fragment_ttl: Duration,
    packet_id_lease_ttl: Duration,
    fragment_quarantine_ttl: Duration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Hysteria2OwnerResourceProfile {
    owner_limit: usize,
    command_queue_depth: usize,
    logical_lease_limit: usize,
    udp_session_limit: usize,
    udp_session_queue_depth: usize,
    udp_session_queue_bytes: usize,
    udp_owner_queue_bytes: usize,
    udp_session_quarantine_limit: usize,
    udp_session_quarantine_ttl: Duration,
    retry_cooldown: Duration,
    port_hop_resolved_candidate_limit: usize,
    port_hop_transition_socket_limit: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TuicOwnerResourceProfile {
    owner_limit: usize,
    command_queue_depth: usize,
    logical_lease_limit: usize,
    udp_association_limit: usize,
    udp_association_queue_depth: usize,
    udp_association_queue_bytes: usize,
    udp_owner_queue_bytes: usize,
    association_quarantine_limit: usize,
    association_quarantine_ttl: Duration,
    retry_cooldown: Duration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct JuicityOwnerResourceProfile {
    owner_limit: usize,
    connections_per_pool: usize,
    logical_streams_per_connection: usize,
    reserved_streams_per_connection: usize,
    command_queue_depth: usize,
    retry_cooldown: Duration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AnyTlsOwnerResourceProfile {
    owner_limit: usize,
    physical_session_limit: usize,
    physical_sessions_per_owner: usize,
    command_queue_depth: usize,
    logical_buffer_bytes: usize,
    idle_session_limit: usize,
    idle_session_timeout: Duration,
    idle_probe_threshold: Duration,
    idle_probe_timeout: Duration,
    sid_quarantine_limit: usize,
    sid_quarantine_ttl: Duration,
}

impl AnyTlsOwnerResourceProfile {
    pub(crate) const fn from_runtime_profile(profile: ResidentRuntimeProfile) -> Self {
        match profile {
            ResidentRuntimeProfile::LowMemory => Self::new(
                LOW_MEMORY_ANYTLS_OWNER_LIMIT,
                LOW_MEMORY_TCP_CONNECTION_LIMIT + LOW_MEMORY_UDP_SESSION_LIMIT,
                LOW_MEMORY_ANYTLS_COMMAND_QUEUE_DEPTH,
                LOW_MEMORY_ANYTLS_LOGICAL_BUFFER_BYTES,
                LOW_MEMORY_ANYTLS_SID_QUARANTINE_LIMIT,
            ),
            ResidentRuntimeProfile::Balanced => Self::new(
                BALANCED_ANYTLS_OWNER_LIMIT,
                BALANCED_TCP_CONNECTION_LIMIT + BALANCED_UDP_SESSION_LIMIT,
                BALANCED_ANYTLS_COMMAND_QUEUE_DEPTH,
                BALANCED_ANYTLS_LOGICAL_BUFFER_BYTES,
                BALANCED_ANYTLS_SID_QUARANTINE_LIMIT,
            ),
            ResidentRuntimeProfile::HighPerformance => Self::new(
                HIGH_PERFORMANCE_ANYTLS_OWNER_LIMIT,
                HIGH_PERFORMANCE_TCP_CONNECTION_LIMIT + HIGH_PERFORMANCE_UDP_SESSION_LIMIT,
                HIGH_PERFORMANCE_ANYTLS_COMMAND_QUEUE_DEPTH,
                HIGH_PERFORMANCE_ANYTLS_LOGICAL_BUFFER_BYTES,
                HIGH_PERFORMANCE_ANYTLS_SID_QUARANTINE_LIMIT,
            ),
        }
    }

    const fn new(
        owner_limit: usize,
        physical_session_limit: usize,
        command_queue_depth: usize,
        logical_buffer_bytes: usize,
        sid_quarantine_limit: usize,
    ) -> Self {
        Self {
            owner_limit,
            physical_session_limit,
            physical_sessions_per_owner: physical_session_limit,
            command_queue_depth,
            logical_buffer_bytes,
            idle_session_limit: ANYTLS_IDLE_SESSION_LIMIT,
            idle_session_timeout: Duration::from_secs(ANYTLS_IDLE_SESSION_TIMEOUT_SECONDS),
            idle_probe_threshold: Duration::from_secs(ANYTLS_IDLE_SESSION_PROBE_THRESHOLD_SECONDS),
            idle_probe_timeout: Duration::from_secs(ANYTLS_IDLE_SESSION_PROBE_TIMEOUT_SECONDS),
            sid_quarantine_limit,
            sid_quarantine_ttl: Duration::from_secs(ANYTLS_SID_QUARANTINE_TTL_SECONDS),
        }
    }

    pub(crate) fn selected() -> Self {
        static SELECTED: std::sync::OnceLock<AnyTlsOwnerResourceProfile> =
            std::sync::OnceLock::new();
        *SELECTED.get_or_init(|| {
            Self::from_runtime_profile(ResidentRuntimeProfileSelection::selected().profile)
        })
    }

    pub(crate) const fn owner_limit(self) -> usize {
        self.owner_limit
    }
    pub(crate) const fn physical_session_limit(self) -> usize {
        self.physical_session_limit
    }
    pub(crate) const fn physical_sessions_per_owner(self) -> usize {
        self.physical_sessions_per_owner
    }
    pub(crate) const fn command_queue_depth(self) -> usize {
        self.command_queue_depth
    }
    pub(crate) const fn physical_control_queue_depth(self) -> usize {
        ANYTLS_PHYSICAL_CONTROL_QUEUE_DEPTH
    }
    pub(crate) const fn logical_buffer_bytes(self) -> usize {
        self.logical_buffer_bytes
    }
    pub(crate) const fn idle_session_limit(self) -> usize {
        self.idle_session_limit
    }
    pub(crate) const fn idle_session_timeout(self) -> Duration {
        self.idle_session_timeout
    }
    pub(crate) const fn idle_probe_threshold(self) -> Duration {
        self.idle_probe_threshold
    }
    pub(crate) const fn idle_probe_timeout(self) -> Duration {
        self.idle_probe_timeout
    }
    pub(crate) const fn sid_quarantine_limit(self) -> usize {
        self.sid_quarantine_limit
    }
    pub(crate) const fn sid_quarantine_ttl(self) -> Duration {
        self.sid_quarantine_ttl
    }

    #[cfg(test)]
    pub(crate) fn with_idle_policy_for_test(
        mut self,
        idle_session_timeout: Duration,
        idle_probe_threshold: Duration,
        idle_probe_timeout: Duration,
    ) -> Self {
        self.idle_session_timeout = idle_session_timeout;
        self.idle_probe_threshold = idle_probe_threshold;
        self.idle_probe_timeout = idle_probe_timeout;
        self
    }
}

impl JuicityOwnerResourceProfile {
    pub(crate) const fn from_runtime_profile(profile: ResidentRuntimeProfile) -> Self {
        match profile {
            ResidentRuntimeProfile::LowMemory => Self {
                owner_limit: LOW_MEMORY_JUICITY_OWNER_LIMIT,
                connections_per_pool: LOW_MEMORY_JUICITY_CONNECTIONS_PER_POOL,
                logical_streams_per_connection: LOW_MEMORY_JUICITY_LOGICAL_STREAMS_PER_CONNECTION,
                reserved_streams_per_connection: LOW_MEMORY_JUICITY_RESERVED_STREAMS_PER_CONNECTION,
                command_queue_depth: LOW_MEMORY_JUICITY_OWNER_COMMAND_QUEUE_DEPTH,
                retry_cooldown: Duration::from_secs(LOW_MEMORY_JUICITY_RETRY_COOLDOWN_SECONDS),
            },
            ResidentRuntimeProfile::Balanced => Self {
                owner_limit: BALANCED_JUICITY_OWNER_LIMIT,
                connections_per_pool: BALANCED_JUICITY_CONNECTIONS_PER_POOL,
                logical_streams_per_connection: BALANCED_JUICITY_LOGICAL_STREAMS_PER_CONNECTION,
                reserved_streams_per_connection: BALANCED_JUICITY_RESERVED_STREAMS_PER_CONNECTION,
                command_queue_depth: BALANCED_JUICITY_OWNER_COMMAND_QUEUE_DEPTH,
                retry_cooldown: Duration::from_secs(BALANCED_JUICITY_RETRY_COOLDOWN_SECONDS),
            },
            ResidentRuntimeProfile::HighPerformance => Self {
                owner_limit: HIGH_PERFORMANCE_JUICITY_OWNER_LIMIT,
                connections_per_pool: HIGH_PERFORMANCE_JUICITY_CONNECTIONS_PER_POOL,
                logical_streams_per_connection:
                    HIGH_PERFORMANCE_JUICITY_LOGICAL_STREAMS_PER_CONNECTION,
                reserved_streams_per_connection:
                    HIGH_PERFORMANCE_JUICITY_RESERVED_STREAMS_PER_CONNECTION,
                command_queue_depth: HIGH_PERFORMANCE_JUICITY_OWNER_COMMAND_QUEUE_DEPTH,
                retry_cooldown: Duration::from_secs(
                    HIGH_PERFORMANCE_JUICITY_RETRY_COOLDOWN_SECONDS,
                ),
            },
        }
    }

    pub(crate) fn selected() -> Self {
        static SELECTED: std::sync::OnceLock<JuicityOwnerResourceProfile> =
            std::sync::OnceLock::new();
        *SELECTED.get_or_init(|| {
            Self::from_runtime_profile(ResidentRuntimeProfileSelection::selected().profile)
        })
    }

    pub(crate) const fn owner_limit(self) -> usize {
        self.owner_limit
    }

    #[cfg(test)]
    pub(crate) const fn with_owner_limit(mut self, owner_limit: usize) -> Self {
        self.owner_limit = owner_limit;
        self
    }

    #[cfg(test)]
    pub(crate) const fn with_pool_shape(
        mut self,
        connections_per_pool: usize,
        logical_streams_per_connection: usize,
        reserved_streams_per_connection: usize,
    ) -> Self {
        self.connections_per_pool = connections_per_pool;
        self.logical_streams_per_connection = logical_streams_per_connection;
        self.reserved_streams_per_connection = reserved_streams_per_connection;
        self
    }

    pub(crate) const fn connections_per_pool(self) -> usize {
        self.connections_per_pool
    }

    pub(crate) const fn logical_streams_per_connection(self) -> usize {
        self.logical_streams_per_connection
    }

    pub(crate) const fn reserved_streams_per_connection(self) -> usize {
        self.reserved_streams_per_connection
    }

    pub(crate) const fn usable_streams_per_connection(self) -> usize {
        self.logical_streams_per_connection
            .saturating_sub(self.reserved_streams_per_connection)
    }

    pub(crate) const fn command_queue_depth(self) -> usize {
        self.command_queue_depth
    }

    pub(crate) const fn retry_cooldown(self) -> Duration {
        self.retry_cooldown
    }
}

impl TuicOwnerResourceProfile {
    pub(crate) const fn from_runtime_profile(profile: ResidentRuntimeProfile) -> Self {
        match profile {
            ResidentRuntimeProfile::LowMemory => Self {
                owner_limit: LOW_MEMORY_TUIC_OWNER_LIMIT,
                command_queue_depth: LOW_MEMORY_TUIC_OWNER_COMMAND_QUEUE_DEPTH,
                logical_lease_limit: LOW_MEMORY_TUIC_LOGICAL_LEASE_LIMIT,
                udp_association_limit: LOW_MEMORY_TUIC_UDP_ASSOCIATION_LIMIT,
                udp_association_queue_depth: LOW_MEMORY_TUIC_UDP_ASSOCIATION_QUEUE_DEPTH,
                udp_association_queue_bytes: LOW_MEMORY_TUIC_UDP_ASSOCIATION_QUEUE_BYTES,
                udp_owner_queue_bytes: LOW_MEMORY_TUIC_UDP_OWNER_QUEUE_BYTES,
                association_quarantine_limit: LOW_MEMORY_TUIC_ASSOCIATION_QUARANTINE_LIMIT,
                association_quarantine_ttl: Duration::from_secs(
                    TUIC_ASSOCIATION_QUARANTINE_TTL_SECONDS,
                ),
                retry_cooldown: Duration::from_secs(LOW_MEMORY_TUIC_RETRY_COOLDOWN_SECONDS),
            },
            ResidentRuntimeProfile::Balanced => Self {
                owner_limit: BALANCED_TUIC_OWNER_LIMIT,
                command_queue_depth: BALANCED_TUIC_OWNER_COMMAND_QUEUE_DEPTH,
                logical_lease_limit: BALANCED_TUIC_LOGICAL_LEASE_LIMIT,
                udp_association_limit: BALANCED_TUIC_UDP_ASSOCIATION_LIMIT,
                udp_association_queue_depth: BALANCED_TUIC_UDP_ASSOCIATION_QUEUE_DEPTH,
                udp_association_queue_bytes: BALANCED_TUIC_UDP_ASSOCIATION_QUEUE_BYTES,
                udp_owner_queue_bytes: BALANCED_TUIC_UDP_OWNER_QUEUE_BYTES,
                association_quarantine_limit: BALANCED_TUIC_ASSOCIATION_QUARANTINE_LIMIT,
                association_quarantine_ttl: Duration::from_secs(
                    TUIC_ASSOCIATION_QUARANTINE_TTL_SECONDS,
                ),
                retry_cooldown: Duration::from_secs(BALANCED_TUIC_RETRY_COOLDOWN_SECONDS),
            },
            ResidentRuntimeProfile::HighPerformance => Self {
                owner_limit: HIGH_PERFORMANCE_TUIC_OWNER_LIMIT,
                command_queue_depth: HIGH_PERFORMANCE_TUIC_OWNER_COMMAND_QUEUE_DEPTH,
                logical_lease_limit: HIGH_PERFORMANCE_TUIC_LOGICAL_LEASE_LIMIT,
                udp_association_limit: HIGH_PERFORMANCE_TUIC_UDP_ASSOCIATION_LIMIT,
                udp_association_queue_depth: HIGH_PERFORMANCE_TUIC_UDP_ASSOCIATION_QUEUE_DEPTH,
                udp_association_queue_bytes: HIGH_PERFORMANCE_TUIC_UDP_ASSOCIATION_QUEUE_BYTES,
                udp_owner_queue_bytes: HIGH_PERFORMANCE_TUIC_UDP_OWNER_QUEUE_BYTES,
                association_quarantine_limit: HIGH_PERFORMANCE_TUIC_ASSOCIATION_QUARANTINE_LIMIT,
                association_quarantine_ttl: Duration::from_secs(
                    TUIC_ASSOCIATION_QUARANTINE_TTL_SECONDS,
                ),
                retry_cooldown: Duration::from_secs(HIGH_PERFORMANCE_TUIC_RETRY_COOLDOWN_SECONDS),
            },
        }
    }

    pub(crate) fn selected() -> Self {
        static SELECTED: std::sync::OnceLock<TuicOwnerResourceProfile> = std::sync::OnceLock::new();
        *SELECTED.get_or_init(|| {
            Self::from_runtime_profile(ResidentRuntimeProfileSelection::selected().profile)
        })
    }

    pub(crate) const fn owner_limit(self) -> usize {
        self.owner_limit
    }

    #[cfg(test)]
    pub(crate) const fn with_owner_limit(mut self, owner_limit: usize) -> Self {
        self.owner_limit = owner_limit;
        self
    }

    pub(crate) const fn command_queue_depth(self) -> usize {
        self.command_queue_depth
    }

    pub(crate) const fn logical_lease_limit(self) -> usize {
        self.logical_lease_limit
    }

    pub(crate) const fn udp_association_limit(self) -> usize {
        self.udp_association_limit
    }

    pub(crate) const fn udp_association_queue_depth(self) -> usize {
        self.udp_association_queue_depth
    }

    pub(crate) const fn udp_association_queue_bytes(self) -> usize {
        self.udp_association_queue_bytes
    }

    pub(crate) const fn udp_owner_queue_bytes(self) -> usize {
        self.udp_owner_queue_bytes
    }

    pub(crate) const fn association_quarantine_limit(self) -> usize {
        self.association_quarantine_limit
    }

    pub(crate) const fn association_quarantine_ttl(self) -> Duration {
        self.association_quarantine_ttl
    }

    pub(crate) const fn retry_cooldown(self) -> Duration {
        self.retry_cooldown
    }
}

impl Hysteria2OwnerResourceProfile {
    pub(crate) const fn from_runtime_profile(profile: ResidentRuntimeProfile) -> Self {
        match profile {
            ResidentRuntimeProfile::LowMemory => Self {
                owner_limit: LOW_MEMORY_HYSTERIA2_OWNER_LIMIT,
                command_queue_depth: LOW_MEMORY_HYSTERIA2_OWNER_COMMAND_QUEUE_DEPTH,
                logical_lease_limit: LOW_MEMORY_HYSTERIA2_LOGICAL_LEASE_LIMIT,
                udp_session_limit: LOW_MEMORY_HYSTERIA2_UDP_SESSION_LIMIT,
                udp_session_queue_depth: LOW_MEMORY_HYSTERIA2_UDP_SESSION_QUEUE_DEPTH,
                udp_session_queue_bytes: LOW_MEMORY_HYSTERIA2_UDP_SESSION_QUEUE_BYTES,
                udp_owner_queue_bytes: LOW_MEMORY_HYSTERIA2_UDP_OWNER_QUEUE_BYTES,
                udp_session_quarantine_limit: LOW_MEMORY_HYSTERIA2_UDP_SESSION_QUARANTINE_LIMIT,
                udp_session_quarantine_ttl: Duration::from_secs(
                    HYSTERIA2_UDP_SESSION_QUARANTINE_TTL_SECONDS,
                ),
                retry_cooldown: Duration::from_secs(LOW_MEMORY_HYSTERIA2_RETRY_COOLDOWN_SECONDS),
                port_hop_resolved_candidate_limit:
                    LOW_MEMORY_HYSTERIA2_PORT_HOP_RESOLVED_CANDIDATE_LIMIT,
                port_hop_transition_socket_limit: HYSTERIA2_PORT_HOP_TRANSITION_SOCKET_LIMIT,
            },
            ResidentRuntimeProfile::Balanced => Self {
                owner_limit: BALANCED_HYSTERIA2_OWNER_LIMIT,
                command_queue_depth: BALANCED_HYSTERIA2_OWNER_COMMAND_QUEUE_DEPTH,
                logical_lease_limit: BALANCED_HYSTERIA2_LOGICAL_LEASE_LIMIT,
                udp_session_limit: BALANCED_HYSTERIA2_UDP_SESSION_LIMIT,
                udp_session_queue_depth: BALANCED_HYSTERIA2_UDP_SESSION_QUEUE_DEPTH,
                udp_session_queue_bytes: BALANCED_HYSTERIA2_UDP_SESSION_QUEUE_BYTES,
                udp_owner_queue_bytes: BALANCED_HYSTERIA2_UDP_OWNER_QUEUE_BYTES,
                udp_session_quarantine_limit: BALANCED_HYSTERIA2_UDP_SESSION_QUARANTINE_LIMIT,
                udp_session_quarantine_ttl: Duration::from_secs(
                    HYSTERIA2_UDP_SESSION_QUARANTINE_TTL_SECONDS,
                ),
                retry_cooldown: Duration::from_secs(BALANCED_HYSTERIA2_RETRY_COOLDOWN_SECONDS),
                port_hop_resolved_candidate_limit:
                    BALANCED_HYSTERIA2_PORT_HOP_RESOLVED_CANDIDATE_LIMIT,
                port_hop_transition_socket_limit: HYSTERIA2_PORT_HOP_TRANSITION_SOCKET_LIMIT,
            },
            ResidentRuntimeProfile::HighPerformance => Self {
                owner_limit: HIGH_PERFORMANCE_HYSTERIA2_OWNER_LIMIT,
                command_queue_depth: HIGH_PERFORMANCE_HYSTERIA2_OWNER_COMMAND_QUEUE_DEPTH,
                logical_lease_limit: HIGH_PERFORMANCE_HYSTERIA2_LOGICAL_LEASE_LIMIT,
                udp_session_limit: HIGH_PERFORMANCE_HYSTERIA2_UDP_SESSION_LIMIT,
                udp_session_queue_depth: HIGH_PERFORMANCE_HYSTERIA2_UDP_SESSION_QUEUE_DEPTH,
                udp_session_queue_bytes: HIGH_PERFORMANCE_HYSTERIA2_UDP_SESSION_QUEUE_BYTES,
                udp_owner_queue_bytes: HIGH_PERFORMANCE_HYSTERIA2_UDP_OWNER_QUEUE_BYTES,
                udp_session_quarantine_limit:
                    HIGH_PERFORMANCE_HYSTERIA2_UDP_SESSION_QUARANTINE_LIMIT,
                udp_session_quarantine_ttl: Duration::from_secs(
                    HYSTERIA2_UDP_SESSION_QUARANTINE_TTL_SECONDS,
                ),
                retry_cooldown: Duration::from_secs(
                    HIGH_PERFORMANCE_HYSTERIA2_RETRY_COOLDOWN_SECONDS,
                ),
                port_hop_resolved_candidate_limit:
                    HIGH_PERFORMANCE_HYSTERIA2_PORT_HOP_RESOLVED_CANDIDATE_LIMIT,
                port_hop_transition_socket_limit: HYSTERIA2_PORT_HOP_TRANSITION_SOCKET_LIMIT,
            },
        }
    }

    pub(crate) fn selected() -> Self {
        static SELECTED: std::sync::OnceLock<Hysteria2OwnerResourceProfile> =
            std::sync::OnceLock::new();
        *SELECTED.get_or_init(|| {
            Self::from_runtime_profile(ResidentRuntimeProfileSelection::selected().profile)
        })
    }

    pub(crate) const fn owner_limit(self) -> usize {
        self.owner_limit
    }

    pub(crate) const fn command_queue_depth(self) -> usize {
        self.command_queue_depth
    }

    pub(crate) const fn logical_lease_limit(self) -> usize {
        self.logical_lease_limit
    }

    pub(crate) const fn udp_session_limit(self) -> usize {
        self.udp_session_limit
    }

    pub(crate) const fn udp_session_queue_depth(self) -> usize {
        self.udp_session_queue_depth
    }

    pub(crate) const fn udp_session_queue_bytes(self) -> usize {
        self.udp_session_queue_bytes
    }

    pub(crate) const fn udp_owner_queue_bytes(self) -> usize {
        self.udp_owner_queue_bytes
    }

    pub(crate) const fn udp_session_quarantine_limit(self) -> usize {
        self.udp_session_quarantine_limit
    }

    pub(crate) const fn udp_session_quarantine_ttl(self) -> Duration {
        self.udp_session_quarantine_ttl
    }

    pub(crate) const fn retry_cooldown(self) -> Duration {
        self.retry_cooldown
    }

    pub(crate) const fn port_hop_resolved_candidate_limit(self) -> usize {
        self.port_hop_resolved_candidate_limit
    }

    pub(crate) const fn port_hop_transition_socket_limit(self) -> usize {
        self.port_hop_transition_socket_limit
    }

    #[cfg(test)]
    pub(crate) fn with_udp_session_limits_for_test(
        session_limit: usize,
        queue_depth: usize,
    ) -> Self {
        let mut resources = Self::from_runtime_profile(ResidentRuntimeProfile::LowMemory);
        resources.udp_session_limit = session_limit;
        resources.udp_session_queue_depth = queue_depth;
        resources.udp_session_queue_bytes = 4_096;
        resources.udp_owner_queue_bytes = 4_096;
        resources.udp_session_quarantine_limit = session_limit.saturating_mul(2).max(1);
        resources.udp_session_quarantine_ttl = Duration::from_secs(10);
        resources
    }
}

impl QuicUdpDatagramResourceProfile {
    pub(crate) fn selected() -> Self {
        static SELECTED: std::sync::OnceLock<QuicUdpDatagramResourceProfile> =
            std::sync::OnceLock::new();
        *SELECTED.get_or_init(|| {
            Self::from_runtime_profile(ResidentRuntimeProfileSelection::selected().profile)
        })
    }

    pub(crate) const fn from_runtime_profile(profile: ResidentRuntimeProfile) -> Self {
        let (pending_fragment_packets, pending_fragment_bytes, packet_id_leases, pmtu_retries) =
            match profile {
                ResidentRuntimeProfile::LowMemory => (
                    LOW_MEMORY_QUIC_UDP_FRAGMENT_PENDING_PACKETS,
                    LOW_MEMORY_QUIC_UDP_FRAGMENT_PENDING_BYTES,
                    LOW_MEMORY_QUIC_UDP_PACKET_ID_LEASES,
                    LOW_MEMORY_QUIC_UDP_PMTU_RETRIES,
                ),
                ResidentRuntimeProfile::Balanced => (
                    BALANCED_QUIC_UDP_FRAGMENT_PENDING_PACKETS,
                    BALANCED_QUIC_UDP_FRAGMENT_PENDING_BYTES,
                    BALANCED_QUIC_UDP_PACKET_ID_LEASES,
                    BALANCED_QUIC_UDP_PMTU_RETRIES,
                ),
                ResidentRuntimeProfile::HighPerformance => (
                    HIGH_PERFORMANCE_QUIC_UDP_FRAGMENT_PENDING_PACKETS,
                    HIGH_PERFORMANCE_QUIC_UDP_FRAGMENT_PENDING_BYTES,
                    HIGH_PERFORMANCE_QUIC_UDP_PACKET_ID_LEASES,
                    HIGH_PERFORMANCE_QUIC_UDP_PMTU_RETRIES,
                ),
            };
        Self {
            pending_fragment_packets,
            pending_fragment_bytes,
            packet_id_leases,
            pmtu_retries,
            fragment_ttl: Duration::from_secs(QUIC_UDP_FRAGMENT_TTL_SECONDS),
            packet_id_lease_ttl: Duration::from_secs(QUIC_UDP_PACKET_ID_LEASE_TTL_SECONDS),
            fragment_quarantine_ttl: Duration::from_secs(QUIC_UDP_FRAGMENT_QUARANTINE_TTL_SECONDS),
        }
    }

    pub(crate) const fn pending_fragment_packets(self) -> usize {
        self.pending_fragment_packets
    }

    pub(crate) const fn pending_fragment_bytes(self) -> usize {
        self.pending_fragment_bytes
    }

    pub(crate) const fn packet_id_leases(self) -> usize {
        self.packet_id_leases
    }

    pub(crate) const fn pmtu_retries(self) -> usize {
        self.pmtu_retries
    }

    pub(crate) const fn fragment_ttl(self) -> Duration {
        self.fragment_ttl
    }

    pub(crate) const fn packet_id_lease_ttl(self) -> Duration {
        self.packet_id_lease_ttl
    }

    pub(crate) const fn fragment_quarantine_ttl(self) -> Duration {
        self.fragment_quarantine_ttl
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct EffectiveProcessMemoryCapacity {
    bytes: u64,
    source: &'static str,
}

impl EffectiveProcessMemoryCapacity {
    pub(crate) const fn new(bytes: u64, source: &'static str) -> Self {
        Self { bytes, source }
    }

    pub(crate) const fn bytes(self) -> u64 {
        self.bytes
    }

    pub(crate) const fn source(self) -> &'static str {
        self.source
    }
}

impl ResidentRuntimeProfile {
    fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "low" | "low_memory" | RESIDENT_RUNTIME_PROFILE_LOW_MEMORY => Some(Self::LowMemory),
            "standard" | RESIDENT_RUNTIME_PROFILE_BALANCED => Some(Self::Balanced),
            "high" | "high_performance" | RESIDENT_RUNTIME_PROFILE_HIGH_PERFORMANCE => {
                Some(Self::HighPerformance)
            }
            _ => None,
        }
    }

    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::LowMemory => RESIDENT_RUNTIME_PROFILE_LOW_MEMORY,
            Self::Balanced => RESIDENT_RUNTIME_PROFILE_BALANCED,
            Self::HighPerformance => RESIDENT_RUNTIME_PROFILE_HIGH_PERFORMANCE,
        }
    }

    pub(crate) fn tcp_runtime_workers_default(self, available_parallelism: usize) -> usize {
        let profile_max = match self {
            Self::LowMemory => LOW_MEMORY_TCP_RUNTIME_WORKERS_MAX,
            Self::Balanced => BALANCED_TCP_RUNTIME_WORKERS_MAX,
            Self::HighPerformance => HIGH_PERFORMANCE_TCP_RUNTIME_WORKERS_MAX,
        };
        available_parallelism.max(1).min(profile_max)
    }

    pub(crate) fn tcp_connection_limit_default(self) -> usize {
        match self {
            Self::LowMemory => LOW_MEMORY_TCP_CONNECTION_LIMIT,
            Self::Balanced => BALANCED_TCP_CONNECTION_LIMIT,
            Self::HighPerformance => HIGH_PERFORMANCE_TCP_CONNECTION_LIMIT,
        }
    }

    pub(crate) fn udp_session_limit_default(self) -> usize {
        match self {
            Self::LowMemory => LOW_MEMORY_UDP_SESSION_LIMIT,
            Self::Balanced => BALANCED_UDP_SESSION_LIMIT,
            Self::HighPerformance => HIGH_PERFORMANCE_UDP_SESSION_LIMIT,
        }
    }

    pub(crate) fn udp_session_queue_depth_default(self) -> usize {
        match self {
            Self::LowMemory => LOW_MEMORY_UDP_SESSION_QUEUE_DEPTH,
            Self::Balanced => BALANCED_UDP_SESSION_QUEUE_DEPTH,
            Self::HighPerformance => HIGH_PERFORMANCE_UDP_SESSION_QUEUE_DEPTH,
        }
    }

    pub(crate) fn udp_runtime_shards_default(self, available_parallelism: usize) -> usize {
        let maximum = match self {
            Self::LowMemory => LOW_MEMORY_UDP_RUNTIME_SHARDS_MAX,
            Self::Balanced => BALANCED_UDP_RUNTIME_SHARDS_MAX,
            Self::HighPerformance => HIGH_PERFORMANCE_UDP_RUNTIME_SHARDS_MAX,
        };
        available_parallelism.max(1).min(maximum)
    }

    pub(crate) fn udp_dispatch_queue_depth_default(self) -> usize {
        match self {
            Self::LowMemory => LOW_MEMORY_UDP_DISPATCH_QUEUE_DEPTH,
            Self::Balanced => BALANCED_UDP_DISPATCH_QUEUE_DEPTH,
            Self::HighPerformance => HIGH_PERFORMANCE_UDP_DISPATCH_QUEUE_DEPTH,
        }
    }

    pub(crate) fn udp_reply_socket_idle_timeout(self) -> Duration {
        Duration::from_secs(match self {
            Self::LowMemory => LOW_MEMORY_UDP_REPLY_SOCKET_IDLE_SECONDS,
            Self::Balanced => BALANCED_UDP_REPLY_SOCKET_IDLE_SECONDS,
            Self::HighPerformance => HIGH_PERFORMANCE_UDP_REPLY_SOCKET_IDLE_SECONDS,
        })
    }

    pub(crate) fn udp_direct_response_buffer_idle_timeout(self) -> Duration {
        Duration::from_secs(match self {
            Self::LowMemory => LOW_MEMORY_UDP_DIRECT_RESPONSE_BUFFER_IDLE_SECONDS,
            Self::Balanced => BALANCED_UDP_DIRECT_RESPONSE_BUFFER_IDLE_SECONDS,
            Self::HighPerformance => HIGH_PERFORMANCE_UDP_DIRECT_RESPONSE_BUFFER_IDLE_SECONDS,
        })
    }

    pub(crate) fn udp_queued_payload_bytes_default(self) -> usize {
        match self {
            Self::LowMemory => LOW_MEMORY_UDP_QUEUED_PAYLOAD_BYTES,
            Self::Balanced => BALANCED_UDP_QUEUED_PAYLOAD_BYTES,
            Self::HighPerformance => HIGH_PERFORMANCE_UDP_QUEUED_PAYLOAD_BYTES,
        }
    }

    pub(crate) fn quic_endpoint_limit_default(self) -> usize {
        match self {
            Self::LowMemory => LOW_MEMORY_QUIC_ENDPOINT_LIMIT,
            Self::Balanced => BALANCED_QUIC_ENDPOINT_LIMIT,
            Self::HighPerformance => HIGH_PERFORMANCE_QUIC_ENDPOINT_LIMIT,
        }
    }

    pub(crate) fn quic_endpoint_charged_bytes_default(self) -> usize {
        match self {
            Self::LowMemory => LOW_MEMORY_QUIC_ENDPOINT_CHARGED_BYTES,
            Self::Balanced => BALANCED_QUIC_ENDPOINT_CHARGED_BYTES,
            Self::HighPerformance => HIGH_PERFORMANCE_QUIC_ENDPOINT_CHARGED_BYTES,
        }
    }

    pub(crate) fn dns_fast_path_concurrency_default(self) -> usize {
        match self {
            Self::LowMemory => LOW_MEMORY_DNS_FAST_PATH_CONCURRENCY,
            Self::Balanced => BALANCED_DNS_FAST_PATH_CONCURRENCY,
            Self::HighPerformance => HIGH_PERFORMANCE_DNS_FAST_PATH_CONCURRENCY,
        }
    }

    pub(crate) fn dns_fast_path_queue_depth_default(self) -> usize {
        match self {
            Self::LowMemory => LOW_MEMORY_DNS_FAST_PATH_QUEUE_DEPTH,
            Self::Balanced => BALANCED_DNS_FAST_PATH_QUEUE_DEPTH,
            Self::HighPerformance => HIGH_PERFORMANCE_DNS_FAST_PATH_QUEUE_DEPTH,
        }
    }

    pub(crate) fn dns_udp_forwarder_queue_depth_default(self) -> usize {
        match self {
            Self::LowMemory => LOW_MEMORY_DNS_UDP_FORWARDER_QUEUE_DEPTH,
            Self::Balanced => BALANCED_DNS_UDP_FORWARDER_QUEUE_DEPTH,
            Self::HighPerformance => HIGH_PERFORMANCE_DNS_UDP_FORWARDER_QUEUE_DEPTH,
        }
    }

    pub(crate) fn dns_udp_forwarder_pending_limit_default(self) -> usize {
        match self {
            Self::LowMemory => LOW_MEMORY_DNS_UDP_FORWARDER_PENDING_LIMIT,
            Self::Balanced => BALANCED_DNS_UDP_FORWARDER_PENDING_LIMIT,
            Self::HighPerformance => HIGH_PERFORMANCE_DNS_UDP_FORWARDER_PENDING_LIMIT,
        }
    }

    pub(crate) fn dns_udp_forwarder_attempts_default(self) -> usize {
        match self {
            Self::LowMemory => LOW_MEMORY_DNS_UDP_FORWARDER_ATTEMPTS,
            Self::Balanced => BALANCED_DNS_UDP_FORWARDER_ATTEMPTS,
            Self::HighPerformance => HIGH_PERFORMANCE_DNS_UDP_FORWARDER_ATTEMPTS,
        }
    }

    pub(crate) fn dns_proxy_udp_actors_default(self) -> usize {
        match self {
            Self::LowMemory => LOW_MEMORY_DNS_PROXY_UDP_ACTORS,
            Self::Balanced => BALANCED_DNS_PROXY_UDP_ACTORS,
            Self::HighPerformance => HIGH_PERFORMANCE_DNS_PROXY_UDP_ACTORS,
        }
    }

    pub(crate) fn datapath_postflight_interval_seconds_default(self) -> u64 {
        match self {
            Self::LowMemory => LOW_MEMORY_DATAPATH_POSTFLIGHT_INTERVAL_SECONDS,
            Self::Balanced => BALANCED_DATAPATH_POSTFLIGHT_INTERVAL_SECONDS,
            Self::HighPerformance => HIGH_PERFORMANCE_DATAPATH_POSTFLIGHT_INTERVAL_SECONDS,
        }
    }
}

impl ResidentRuntimeProfileSelection {
    pub(crate) fn selected() -> Self {
        if let Ok(value) = std::env::var(RESIDENT_RUNTIME_PROFILE_ENV) {
            return select_resident_runtime_profile(Some(&value));
        }
        select_resident_runtime_profile(None)
    }

    pub(crate) fn json(&self) -> Value {
        json!({
            "name": self.profile.name(),
            "source": self.source,
            "capacitySource": self.capacity_source,
            "effectiveMemoryBytes": self.effective_memory_bytes.map(|value| value.to_string()),
            "hostMemoryBytes": self.host_memory_bytes.map(|value| value.to_string()),
            "cgroupLimitBytes": self.cgroup_limit_bytes.map(|value| value.to_string()),
            "env": RESIDENT_RUNTIME_PROFILE_ENV,
            "invalidValue": self.invalid_value,
        })
    }
}

pub(crate) fn selected_resident_runtime_profile_name() -> &'static str {
    ResidentRuntimeProfileSelection::selected().profile.name()
}

pub(crate) fn effective_process_memory_capacity() -> Option<EffectiveProcessMemoryCapacity> {
    automatic_memory_capacity()
        .map(|(bytes, source)| EffectiveProcessMemoryCapacity::new(bytes, source))
}

pub(crate) fn resident_runtime_profile_contract() -> Value {
    json!({
        "env": RESIDENT_RUNTIME_PROFILE_ENV,
        "default": RESIDENT_RUNTIME_PROFILE_AUTO,
        "supported": [
            RESIDENT_RUNTIME_PROFILE_AUTO,
            RESIDENT_RUNTIME_PROFILE_LOW_MEMORY,
            RESIDENT_RUNTIME_PROFILE_BALANCED,
            RESIDENT_RUNTIME_PROFILE_HIGH_PERFORMANCE,
        ],
        "automaticSelection": {
            "capacityPolicy": "minimum finite cgroup memory limit and host MemTotal",
            "lowMemoryAtOrBelowBytes": AUTO_LOW_MEMORY_MAX_BYTES.to_string(),
            "balancedAboveBytes": AUTO_LOW_MEMORY_MAX_BYTES.to_string(),
            "highPerformanceFromBytes": AUTO_HIGH_PERFORMANCE_LOWER_BOUND_BYTES.to_string(),
            "fallback": RESIDENT_RUNTIME_PROFILE_BALANCED,
            "stableForProcessLifetime": true,
        },
        "profiles": [
            {
                "name": RESIDENT_RUNTIME_PROFILE_LOW_MEMORY,
                "tcpRuntimeWorkersMax": LOW_MEMORY_TCP_RUNTIME_WORKERS_MAX,
                "tcpConnectionDefault": LOW_MEMORY_TCP_CONNECTION_LIMIT,
                "udpSessionDefault": LOW_MEMORY_UDP_SESSION_LIMIT,
                "udpSessionQueueDepthDefault": LOW_MEMORY_UDP_SESSION_QUEUE_DEPTH,
                "udpRuntimeShardsMax": LOW_MEMORY_UDP_RUNTIME_SHARDS_MAX,
                "udpDispatchQueueDepthDefault": LOW_MEMORY_UDP_DISPATCH_QUEUE_DEPTH,
                "quicEndpointDefault": LOW_MEMORY_QUIC_ENDPOINT_LIMIT,
                "quicEndpointChargedBytesDefault": LOW_MEMORY_QUIC_ENDPOINT_CHARGED_BYTES,
                "quicUdpFragmentPendingPackets": LOW_MEMORY_QUIC_UDP_FRAGMENT_PENDING_PACKETS,
                "quicUdpFragmentPendingBytes": LOW_MEMORY_QUIC_UDP_FRAGMENT_PENDING_BYTES,
                "quicUdpPacketIdLeases": LOW_MEMORY_QUIC_UDP_PACKET_ID_LEASES,
                "quicUdpPmtuRetries": LOW_MEMORY_QUIC_UDP_PMTU_RETRIES,
                "hysteria2OwnerLimit": LOW_MEMORY_HYSTERIA2_OWNER_LIMIT,
                "hysteria2OwnerCommandQueueDepth": LOW_MEMORY_HYSTERIA2_OWNER_COMMAND_QUEUE_DEPTH,
                "hysteria2LogicalLeaseLimit": LOW_MEMORY_HYSTERIA2_LOGICAL_LEASE_LIMIT,
                "hysteria2UdpSessionLimit": LOW_MEMORY_HYSTERIA2_UDP_SESSION_LIMIT,
                "hysteria2UdpSessionQueueDepth": LOW_MEMORY_HYSTERIA2_UDP_SESSION_QUEUE_DEPTH,
                "hysteria2UdpSessionQueueBytes": LOW_MEMORY_HYSTERIA2_UDP_SESSION_QUEUE_BYTES,
                "hysteria2UdpOwnerQueueBytes": LOW_MEMORY_HYSTERIA2_UDP_OWNER_QUEUE_BYTES,
                "hysteria2UdpSessionQuarantineLimit": LOW_MEMORY_HYSTERIA2_UDP_SESSION_QUARANTINE_LIMIT,
                "hysteria2UdpSessionQuarantineTtlSeconds": HYSTERIA2_UDP_SESSION_QUARANTINE_TTL_SECONDS,
                "hysteria2RetryCooldownSeconds": LOW_MEMORY_HYSTERIA2_RETRY_COOLDOWN_SECONDS,
                "hysteria2PortHopResolvedCandidateLimit": LOW_MEMORY_HYSTERIA2_PORT_HOP_RESOLVED_CANDIDATE_LIMIT,
                "hysteria2PortHopTransitionSocketLimit": HYSTERIA2_PORT_HOP_TRANSITION_SOCKET_LIMIT,
                "dnsFastPathConcurrencyDefault": LOW_MEMORY_DNS_FAST_PATH_CONCURRENCY,
                "dnsFastPathQueueDepthDefault": LOW_MEMORY_DNS_FAST_PATH_QUEUE_DEPTH,
                "dnsUdpForwarderQueueDepthDefault": LOW_MEMORY_DNS_UDP_FORWARDER_QUEUE_DEPTH,
                "dnsUdpForwarderPendingDefault": LOW_MEMORY_DNS_UDP_FORWARDER_PENDING_LIMIT,
                "dnsUdpForwarderAttemptsDefault": LOW_MEMORY_DNS_UDP_FORWARDER_ATTEMPTS,
                "dnsProxyUdpActorsDefault": LOW_MEMORY_DNS_PROXY_UDP_ACTORS,
                "datapathPostflightIntervalSecondsDefault": LOW_MEMORY_DATAPATH_POSTFLIGHT_INTERVAL_SECONDS,
            },
            {
                "name": RESIDENT_RUNTIME_PROFILE_BALANCED,
                "tcpRuntimeWorkersMax": BALANCED_TCP_RUNTIME_WORKERS_MAX,
                "tcpConnectionDefault": BALANCED_TCP_CONNECTION_LIMIT,
                "udpSessionDefault": BALANCED_UDP_SESSION_LIMIT,
                "udpSessionQueueDepthDefault": BALANCED_UDP_SESSION_QUEUE_DEPTH,
                "udpRuntimeShardsMax": BALANCED_UDP_RUNTIME_SHARDS_MAX,
                "udpDispatchQueueDepthDefault": BALANCED_UDP_DISPATCH_QUEUE_DEPTH,
                "quicEndpointDefault": BALANCED_QUIC_ENDPOINT_LIMIT,
                "quicEndpointChargedBytesDefault": BALANCED_QUIC_ENDPOINT_CHARGED_BYTES,
                "quicUdpFragmentPendingPackets": BALANCED_QUIC_UDP_FRAGMENT_PENDING_PACKETS,
                "quicUdpFragmentPendingBytes": BALANCED_QUIC_UDP_FRAGMENT_PENDING_BYTES,
                "quicUdpPacketIdLeases": BALANCED_QUIC_UDP_PACKET_ID_LEASES,
                "quicUdpPmtuRetries": BALANCED_QUIC_UDP_PMTU_RETRIES,
                "hysteria2OwnerLimit": BALANCED_HYSTERIA2_OWNER_LIMIT,
                "hysteria2OwnerCommandQueueDepth": BALANCED_HYSTERIA2_OWNER_COMMAND_QUEUE_DEPTH,
                "hysteria2LogicalLeaseLimit": BALANCED_HYSTERIA2_LOGICAL_LEASE_LIMIT,
                "hysteria2UdpSessionLimit": BALANCED_HYSTERIA2_UDP_SESSION_LIMIT,
                "hysteria2UdpSessionQueueDepth": BALANCED_HYSTERIA2_UDP_SESSION_QUEUE_DEPTH,
                "hysteria2UdpSessionQueueBytes": BALANCED_HYSTERIA2_UDP_SESSION_QUEUE_BYTES,
                "hysteria2UdpOwnerQueueBytes": BALANCED_HYSTERIA2_UDP_OWNER_QUEUE_BYTES,
                "hysteria2UdpSessionQuarantineLimit": BALANCED_HYSTERIA2_UDP_SESSION_QUARANTINE_LIMIT,
                "hysteria2UdpSessionQuarantineTtlSeconds": HYSTERIA2_UDP_SESSION_QUARANTINE_TTL_SECONDS,
                "hysteria2RetryCooldownSeconds": BALANCED_HYSTERIA2_RETRY_COOLDOWN_SECONDS,
                "hysteria2PortHopResolvedCandidateLimit": BALANCED_HYSTERIA2_PORT_HOP_RESOLVED_CANDIDATE_LIMIT,
                "hysteria2PortHopTransitionSocketLimit": HYSTERIA2_PORT_HOP_TRANSITION_SOCKET_LIMIT,
                "dnsFastPathConcurrencyDefault": BALANCED_DNS_FAST_PATH_CONCURRENCY,
                "dnsFastPathQueueDepthDefault": BALANCED_DNS_FAST_PATH_QUEUE_DEPTH,
                "dnsUdpForwarderQueueDepthDefault": BALANCED_DNS_UDP_FORWARDER_QUEUE_DEPTH,
                "dnsUdpForwarderPendingDefault": BALANCED_DNS_UDP_FORWARDER_PENDING_LIMIT,
                "dnsUdpForwarderAttemptsDefault": BALANCED_DNS_UDP_FORWARDER_ATTEMPTS,
                "dnsProxyUdpActorsDefault": BALANCED_DNS_PROXY_UDP_ACTORS,
                "datapathPostflightIntervalSecondsDefault": BALANCED_DATAPATH_POSTFLIGHT_INTERVAL_SECONDS,
            },
            {
                "name": RESIDENT_RUNTIME_PROFILE_HIGH_PERFORMANCE,
                "tcpRuntimeWorkersMax": HIGH_PERFORMANCE_TCP_RUNTIME_WORKERS_MAX,
                "tcpConnectionDefault": HIGH_PERFORMANCE_TCP_CONNECTION_LIMIT,
                "udpSessionDefault": HIGH_PERFORMANCE_UDP_SESSION_LIMIT,
                "udpSessionQueueDepthDefault": HIGH_PERFORMANCE_UDP_SESSION_QUEUE_DEPTH,
                "udpRuntimeShardsMax": HIGH_PERFORMANCE_UDP_RUNTIME_SHARDS_MAX,
                "udpDispatchQueueDepthDefault": HIGH_PERFORMANCE_UDP_DISPATCH_QUEUE_DEPTH,
                "quicEndpointDefault": HIGH_PERFORMANCE_QUIC_ENDPOINT_LIMIT,
                "quicEndpointChargedBytesDefault": HIGH_PERFORMANCE_QUIC_ENDPOINT_CHARGED_BYTES,
                "quicUdpFragmentPendingPackets": HIGH_PERFORMANCE_QUIC_UDP_FRAGMENT_PENDING_PACKETS,
                "quicUdpFragmentPendingBytes": HIGH_PERFORMANCE_QUIC_UDP_FRAGMENT_PENDING_BYTES,
                "quicUdpPacketIdLeases": HIGH_PERFORMANCE_QUIC_UDP_PACKET_ID_LEASES,
                "quicUdpPmtuRetries": HIGH_PERFORMANCE_QUIC_UDP_PMTU_RETRIES,
                "hysteria2OwnerLimit": HIGH_PERFORMANCE_HYSTERIA2_OWNER_LIMIT,
                "hysteria2OwnerCommandQueueDepth": HIGH_PERFORMANCE_HYSTERIA2_OWNER_COMMAND_QUEUE_DEPTH,
                "hysteria2LogicalLeaseLimit": HIGH_PERFORMANCE_HYSTERIA2_LOGICAL_LEASE_LIMIT,
                "hysteria2UdpSessionLimit": HIGH_PERFORMANCE_HYSTERIA2_UDP_SESSION_LIMIT,
                "hysteria2UdpSessionQueueDepth": HIGH_PERFORMANCE_HYSTERIA2_UDP_SESSION_QUEUE_DEPTH,
                "hysteria2UdpSessionQueueBytes": HIGH_PERFORMANCE_HYSTERIA2_UDP_SESSION_QUEUE_BYTES,
                "hysteria2UdpOwnerQueueBytes": HIGH_PERFORMANCE_HYSTERIA2_UDP_OWNER_QUEUE_BYTES,
                "hysteria2UdpSessionQuarantineLimit": HIGH_PERFORMANCE_HYSTERIA2_UDP_SESSION_QUARANTINE_LIMIT,
                "hysteria2UdpSessionQuarantineTtlSeconds": HYSTERIA2_UDP_SESSION_QUARANTINE_TTL_SECONDS,
                "hysteria2RetryCooldownSeconds": HIGH_PERFORMANCE_HYSTERIA2_RETRY_COOLDOWN_SECONDS,
                "hysteria2PortHopResolvedCandidateLimit": HIGH_PERFORMANCE_HYSTERIA2_PORT_HOP_RESOLVED_CANDIDATE_LIMIT,
                "hysteria2PortHopTransitionSocketLimit": HYSTERIA2_PORT_HOP_TRANSITION_SOCKET_LIMIT,
                "dnsFastPathConcurrencyDefault": HIGH_PERFORMANCE_DNS_FAST_PATH_CONCURRENCY,
                "dnsFastPathQueueDepthDefault": HIGH_PERFORMANCE_DNS_FAST_PATH_QUEUE_DEPTH,
                "dnsUdpForwarderQueueDepthDefault": HIGH_PERFORMANCE_DNS_UDP_FORWARDER_QUEUE_DEPTH,
                "dnsUdpForwarderPendingDefault": HIGH_PERFORMANCE_DNS_UDP_FORWARDER_PENDING_LIMIT,
                "dnsUdpForwarderAttemptsDefault": HIGH_PERFORMANCE_DNS_UDP_FORWARDER_ATTEMPTS,
                "dnsProxyUdpActorsDefault": HIGH_PERFORMANCE_DNS_PROXY_UDP_ACTORS,
                "datapathPostflightIntervalSecondsDefault": HIGH_PERFORMANCE_DATAPATH_POSTFLIGHT_INTERVAL_SECONDS,
            },
        ],
    })
}

pub(in crate::production_runtime_owner) fn resident_datapath_postflight_interval_seconds_default()
-> u64 {
    ResidentRuntimeProfileSelection::selected()
        .profile
        .datapath_postflight_interval_seconds_default()
}

fn select_resident_runtime_profile(configured: Option<&str>) -> ResidentRuntimeProfileSelection {
    select_resident_runtime_profile_with_auto(configured, automatic_profile_decision())
}

fn select_resident_runtime_profile_with_auto(
    configured: Option<&str>,
    automatic: AutomaticProfileDecision,
) -> ResidentRuntimeProfileSelection {
    let Some(value) = configured else {
        return automatic.into_selection(None);
    };
    parsed_profile_selection(value, "env", automatic)
}

fn parsed_profile_selection(
    value: &str,
    source: &'static str,
    automatic: AutomaticProfileDecision,
) -> ResidentRuntimeProfileSelection {
    if matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "" | RESIDENT_RUNTIME_PROFILE_AUTO
    ) {
        return automatic.into_selection(None);
    }
    match ResidentRuntimeProfile::parse(value) {
        Some(profile) => ResidentRuntimeProfileSelection {
            profile,
            source,
            capacity_source: None,
            effective_memory_bytes: None,
            host_memory_bytes: None,
            cgroup_limit_bytes: None,
            invalid_value: None,
        },
        None => ResidentRuntimeProfileSelection {
            profile: ResidentRuntimeProfile::Balanced,
            source: "invalid-env-fallback",
            capacity_source: None,
            effective_memory_bytes: None,
            host_memory_bytes: None,
            cgroup_limit_bytes: None,
            invalid_value: Some(value.to_owned()),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resident_runtime_profiles_bound_tcp_and_udp_resources() {
        assert_eq!(
            ResidentRuntimeProfile::LowMemory.tcp_runtime_workers_default(64),
            LOW_MEMORY_TCP_RUNTIME_WORKERS_MAX
        );
        assert_eq!(
            ResidentRuntimeProfile::Balanced.tcp_runtime_workers_default(64),
            BALANCED_TCP_RUNTIME_WORKERS_MAX
        );
        assert_eq!(
            ResidentRuntimeProfile::HighPerformance.tcp_runtime_workers_default(64),
            HIGH_PERFORMANCE_TCP_RUNTIME_WORKERS_MAX
        );
        assert_eq!(
            ResidentRuntimeProfile::Balanced.tcp_runtime_workers_default(1),
            1
        );
        assert!(
            ResidentRuntimeProfile::LowMemory.tcp_connection_limit_default()
                < ResidentRuntimeProfile::Balanced.tcp_connection_limit_default()
        );
        assert!(
            ResidentRuntimeProfile::Balanced.tcp_connection_limit_default()
                < ResidentRuntimeProfile::HighPerformance.tcp_connection_limit_default()
        );
        assert!(
            ResidentRuntimeProfile::LowMemory.quic_endpoint_limit_default()
                < ResidentRuntimeProfile::Balanced.quic_endpoint_limit_default()
        );
        assert!(
            ResidentRuntimeProfile::Balanced.quic_endpoint_limit_default()
                < ResidentRuntimeProfile::HighPerformance.quic_endpoint_limit_default()
        );
        assert!(
            ResidentRuntimeProfile::LowMemory.quic_endpoint_charged_bytes_default()
                < ResidentRuntimeProfile::Balanced.quic_endpoint_charged_bytes_default()
        );
        assert!(
            ResidentRuntimeProfile::Balanced.quic_endpoint_charged_bytes_default()
                < ResidentRuntimeProfile::HighPerformance.quic_endpoint_charged_bytes_default()
        );
        let low_quic_udp =
            QuicUdpDatagramResourceProfile::from_runtime_profile(ResidentRuntimeProfile::LowMemory);
        let balanced_quic_udp =
            QuicUdpDatagramResourceProfile::from_runtime_profile(ResidentRuntimeProfile::Balanced);
        let high_quic_udp = QuicUdpDatagramResourceProfile::from_runtime_profile(
            ResidentRuntimeProfile::HighPerformance,
        );
        assert!(
            low_quic_udp.pending_fragment_packets() < balanced_quic_udp.pending_fragment_packets()
        );
        assert!(
            balanced_quic_udp.pending_fragment_packets() < high_quic_udp.pending_fragment_packets()
        );
        assert!(low_quic_udp.pending_fragment_bytes() < balanced_quic_udp.pending_fragment_bytes());
        assert!(
            balanced_quic_udp.pending_fragment_bytes() < high_quic_udp.pending_fragment_bytes()
        );
        assert!(low_quic_udp.packet_id_leases() < balanced_quic_udp.packet_id_leases());
        assert!(balanced_quic_udp.packet_id_leases() < high_quic_udp.packet_id_leases());
        assert!(low_quic_udp.pmtu_retries() < balanced_quic_udp.pmtu_retries());
        assert!(balanced_quic_udp.pmtu_retries() < high_quic_udp.pmtu_retries());
        assert_eq!(low_quic_udp.fragment_ttl(), Duration::from_secs(10));
        assert_eq!(low_quic_udp.packet_id_lease_ttl(), Duration::from_secs(10));
        assert_eq!(
            low_quic_udp.fragment_quarantine_ttl(),
            Duration::from_secs(10)
        );
        let low_hysteria2 =
            Hysteria2OwnerResourceProfile::from_runtime_profile(ResidentRuntimeProfile::LowMemory);
        let balanced_hysteria2 =
            Hysteria2OwnerResourceProfile::from_runtime_profile(ResidentRuntimeProfile::Balanced);
        let high_hysteria2 = Hysteria2OwnerResourceProfile::from_runtime_profile(
            ResidentRuntimeProfile::HighPerformance,
        );
        assert!(low_hysteria2.owner_limit() < balanced_hysteria2.owner_limit());
        assert!(balanced_hysteria2.owner_limit() < high_hysteria2.owner_limit());
        assert!(low_hysteria2.command_queue_depth() < balanced_hysteria2.command_queue_depth());
        assert!(balanced_hysteria2.command_queue_depth() < high_hysteria2.command_queue_depth());
        assert!(low_hysteria2.logical_lease_limit() < balanced_hysteria2.logical_lease_limit());
        assert!(balanced_hysteria2.logical_lease_limit() < high_hysteria2.logical_lease_limit());
        assert!(low_hysteria2.udp_session_limit() < balanced_hysteria2.udp_session_limit());
        assert!(balanced_hysteria2.udp_session_limit() < high_hysteria2.udp_session_limit());
        assert!(
            low_hysteria2.udp_session_queue_depth() < balanced_hysteria2.udp_session_queue_depth()
        );
        assert!(
            balanced_hysteria2.udp_session_queue_depth() < high_hysteria2.udp_session_queue_depth()
        );
        assert!(
            low_hysteria2.udp_session_queue_bytes() < balanced_hysteria2.udp_session_queue_bytes()
        );
        assert!(
            balanced_hysteria2.udp_session_queue_bytes() < high_hysteria2.udp_session_queue_bytes()
        );
        assert!(low_hysteria2.udp_owner_queue_bytes() < balanced_hysteria2.udp_owner_queue_bytes());
        assert!(
            balanced_hysteria2.udp_owner_queue_bytes() < high_hysteria2.udp_owner_queue_bytes()
        );
        assert!(
            low_hysteria2.udp_session_quarantine_limit()
                < balanced_hysteria2.udp_session_quarantine_limit()
        );
        assert!(
            balanced_hysteria2.udp_session_quarantine_limit()
                < high_hysteria2.udp_session_quarantine_limit()
        );
        assert_eq!(
            low_hysteria2.udp_session_quarantine_ttl(),
            balanced_hysteria2.udp_session_quarantine_ttl()
        );
        assert!(low_hysteria2.retry_cooldown() > balanced_hysteria2.retry_cooldown());
        assert!(balanced_hysteria2.retry_cooldown() > high_hysteria2.retry_cooldown());
        assert!(
            low_hysteria2.port_hop_resolved_candidate_limit()
                < balanced_hysteria2.port_hop_resolved_candidate_limit()
        );
        assert!(
            balanced_hysteria2.port_hop_resolved_candidate_limit()
                < high_hysteria2.port_hop_resolved_candidate_limit()
        );
        assert_eq!(low_hysteria2.port_hop_transition_socket_limit(), 3);
        assert_eq!(
            low_hysteria2.port_hop_transition_socket_limit(),
            high_hysteria2.port_hop_transition_socket_limit()
        );
        assert_eq!(
            ResidentRuntimeProfile::LowMemory.udp_runtime_shards_default(64),
            1
        );
        assert_eq!(
            ResidentRuntimeProfile::Balanced.udp_runtime_shards_default(1),
            1
        );
        assert!(
            ResidentRuntimeProfile::LowMemory.udp_session_limit_default()
                < ResidentRuntimeProfile::Balanced.udp_session_limit_default()
        );
        assert!(
            ResidentRuntimeProfile::Balanced.udp_session_limit_default()
                < ResidentRuntimeProfile::HighPerformance.udp_session_limit_default()
        );
    }

    #[test]
    fn resident_runtime_profile_reports_invalid_values() {
        let automatic = automatic_profile_decision_for_capacities(
            Some(16 * GIBIBYTE),
            Some((512 * MEBIBYTE, "cgroup-v2-memory.max")),
        );
        let selected = select_resident_runtime_profile_with_auto(Some("high"), automatic.clone());
        assert_eq!(selected.profile, ResidentRuntimeProfile::HighPerformance);
        assert_eq!(selected.source, "env");

        let invalid = select_resident_runtime_profile_with_auto(Some("unknown"), automatic);
        assert_eq!(invalid.profile, ResidentRuntimeProfile::Balanced);
        assert_eq!(invalid.source, "invalid-env-fallback");
        assert_eq!(invalid.invalid_value.as_deref(), Some("unknown"));
    }
}
