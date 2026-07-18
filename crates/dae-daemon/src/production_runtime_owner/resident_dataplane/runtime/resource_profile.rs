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
