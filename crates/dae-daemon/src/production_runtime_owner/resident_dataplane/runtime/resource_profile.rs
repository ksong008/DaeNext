use super::*;

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
const LOW_MEMORY_CONNECT_UDP_H2_POOL_CONNECTIONS: usize = 1;
const BALANCED_CONNECT_UDP_H2_POOL_CONNECTIONS: usize = 2;
const HIGH_PERFORMANCE_CONNECT_UDP_H2_POOL_CONNECTIONS: usize = 4;
const LOW_MEMORY_CONNECT_UDP_H3_POOL_CONNECTIONS: usize = 1;
const BALANCED_CONNECT_UDP_H3_POOL_CONNECTIONS: usize = 2;
const HIGH_PERFORMANCE_CONNECT_UDP_H3_POOL_CONNECTIONS: usize = 4;
const LOW_MEMORY_CONNECT_UDP_SESSIONS_PER_CONNECTION: usize = 64;
const BALANCED_CONNECT_UDP_SESSIONS_PER_CONNECTION: usize = 256;
const HIGH_PERFORMANCE_CONNECT_UDP_SESSIONS_PER_CONNECTION: usize = 1_024;
const LOW_MEMORY_CONNECT_UDP_H3_COMMAND_QUEUE_DEPTH: usize = 64;
const BALANCED_CONNECT_UDP_H3_COMMAND_QUEUE_DEPTH: usize = 256;
const HIGH_PERFORMANCE_CONNECT_UDP_H3_COMMAND_QUEUE_DEPTH: usize = 1_024;
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
    invalid_value: Option<String>,
}

impl ResidentRuntimeProfile {
    fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "low" | "low_memory" | RESIDENT_RUNTIME_PROFILE_LOW_MEMORY => Some(Self::LowMemory),
            "" | "standard" | RESIDENT_RUNTIME_PROFILE_BALANCED => Some(Self::Balanced),
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

    pub(crate) fn connect_udp_h2_pool_connections_default(self) -> usize {
        match self {
            Self::LowMemory => LOW_MEMORY_CONNECT_UDP_H2_POOL_CONNECTIONS,
            Self::Balanced => BALANCED_CONNECT_UDP_H2_POOL_CONNECTIONS,
            Self::HighPerformance => HIGH_PERFORMANCE_CONNECT_UDP_H2_POOL_CONNECTIONS,
        }
    }

    pub(crate) fn connect_udp_h3_pool_connections_default(self) -> usize {
        match self {
            Self::LowMemory => LOW_MEMORY_CONNECT_UDP_H3_POOL_CONNECTIONS,
            Self::Balanced => BALANCED_CONNECT_UDP_H3_POOL_CONNECTIONS,
            Self::HighPerformance => HIGH_PERFORMANCE_CONNECT_UDP_H3_POOL_CONNECTIONS,
        }
    }

    pub(crate) fn connect_udp_sessions_per_connection_default(self) -> usize {
        match self {
            Self::LowMemory => LOW_MEMORY_CONNECT_UDP_SESSIONS_PER_CONNECTION,
            Self::Balanced => BALANCED_CONNECT_UDP_SESSIONS_PER_CONNECTION,
            Self::HighPerformance => HIGH_PERFORMANCE_CONNECT_UDP_SESSIONS_PER_CONNECTION,
        }
    }

    pub(crate) fn connect_udp_h3_command_queue_depth_default(self) -> usize {
        match self {
            Self::LowMemory => LOW_MEMORY_CONNECT_UDP_H3_COMMAND_QUEUE_DEPTH,
            Self::Balanced => BALANCED_CONNECT_UDP_H3_COMMAND_QUEUE_DEPTH,
            Self::HighPerformance => HIGH_PERFORMANCE_CONNECT_UDP_H3_COMMAND_QUEUE_DEPTH,
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
            return parsed_profile_selection(&value, "env");
        }
        select_resident_runtime_profile(None)
    }

    pub(crate) fn json(&self) -> Value {
        json!({
            "name": self.profile.name(),
            "source": self.source,
            "env": RESIDENT_RUNTIME_PROFILE_ENV,
            "invalidValue": self.invalid_value,
        })
    }
}

pub(crate) fn resident_runtime_profile_contract() -> Value {
    json!({
        "env": RESIDENT_RUNTIME_PROFILE_ENV,
        "default": RESIDENT_RUNTIME_PROFILE_BALANCED,
        "supported": [
            RESIDENT_RUNTIME_PROFILE_LOW_MEMORY,
            RESIDENT_RUNTIME_PROFILE_BALANCED,
            RESIDENT_RUNTIME_PROFILE_HIGH_PERFORMANCE,
        ],
        "profiles": [
            {
                "name": RESIDENT_RUNTIME_PROFILE_LOW_MEMORY,
                "tcpRuntimeWorkersMax": LOW_MEMORY_TCP_RUNTIME_WORKERS_MAX,
                "tcpConnectionDefault": LOW_MEMORY_TCP_CONNECTION_LIMIT,
                "udpSessionDefault": LOW_MEMORY_UDP_SESSION_LIMIT,
                "udpSessionQueueDepthDefault": LOW_MEMORY_UDP_SESSION_QUEUE_DEPTH,
                "udpRuntimeShardsMax": LOW_MEMORY_UDP_RUNTIME_SHARDS_MAX,
                "udpDispatchQueueDepthDefault": LOW_MEMORY_UDP_DISPATCH_QUEUE_DEPTH,
                "dnsFastPathConcurrencyDefault": LOW_MEMORY_DNS_FAST_PATH_CONCURRENCY,
                "dnsFastPathQueueDepthDefault": LOW_MEMORY_DNS_FAST_PATH_QUEUE_DEPTH,
                "dnsUdpForwarderQueueDepthDefault": LOW_MEMORY_DNS_UDP_FORWARDER_QUEUE_DEPTH,
                "dnsUdpForwarderPendingDefault": LOW_MEMORY_DNS_UDP_FORWARDER_PENDING_LIMIT,
                "dnsUdpForwarderAttemptsDefault": LOW_MEMORY_DNS_UDP_FORWARDER_ATTEMPTS,
                "dnsProxyUdpActorsDefault": LOW_MEMORY_DNS_PROXY_UDP_ACTORS,
                "connectUdpH2PoolConnectionsDefault": LOW_MEMORY_CONNECT_UDP_H2_POOL_CONNECTIONS,
                "connectUdpH3PoolConnectionsDefault": LOW_MEMORY_CONNECT_UDP_H3_POOL_CONNECTIONS,
                "connectUdpSessionsPerConnectionDefault": LOW_MEMORY_CONNECT_UDP_SESSIONS_PER_CONNECTION,
                "connectUdpH3CommandQueueDepthDefault": LOW_MEMORY_CONNECT_UDP_H3_COMMAND_QUEUE_DEPTH,
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
                "dnsFastPathConcurrencyDefault": BALANCED_DNS_FAST_PATH_CONCURRENCY,
                "dnsFastPathQueueDepthDefault": BALANCED_DNS_FAST_PATH_QUEUE_DEPTH,
                "dnsUdpForwarderQueueDepthDefault": BALANCED_DNS_UDP_FORWARDER_QUEUE_DEPTH,
                "dnsUdpForwarderPendingDefault": BALANCED_DNS_UDP_FORWARDER_PENDING_LIMIT,
                "dnsUdpForwarderAttemptsDefault": BALANCED_DNS_UDP_FORWARDER_ATTEMPTS,
                "dnsProxyUdpActorsDefault": BALANCED_DNS_PROXY_UDP_ACTORS,
                "connectUdpH2PoolConnectionsDefault": BALANCED_CONNECT_UDP_H2_POOL_CONNECTIONS,
                "connectUdpH3PoolConnectionsDefault": BALANCED_CONNECT_UDP_H3_POOL_CONNECTIONS,
                "connectUdpSessionsPerConnectionDefault": BALANCED_CONNECT_UDP_SESSIONS_PER_CONNECTION,
                "connectUdpH3CommandQueueDepthDefault": BALANCED_CONNECT_UDP_H3_COMMAND_QUEUE_DEPTH,
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
                "dnsFastPathConcurrencyDefault": HIGH_PERFORMANCE_DNS_FAST_PATH_CONCURRENCY,
                "dnsFastPathQueueDepthDefault": HIGH_PERFORMANCE_DNS_FAST_PATH_QUEUE_DEPTH,
                "dnsUdpForwarderQueueDepthDefault": HIGH_PERFORMANCE_DNS_UDP_FORWARDER_QUEUE_DEPTH,
                "dnsUdpForwarderPendingDefault": HIGH_PERFORMANCE_DNS_UDP_FORWARDER_PENDING_LIMIT,
                "dnsUdpForwarderAttemptsDefault": HIGH_PERFORMANCE_DNS_UDP_FORWARDER_ATTEMPTS,
                "dnsProxyUdpActorsDefault": HIGH_PERFORMANCE_DNS_PROXY_UDP_ACTORS,
                "connectUdpH2PoolConnectionsDefault": HIGH_PERFORMANCE_CONNECT_UDP_H2_POOL_CONNECTIONS,
                "connectUdpH3PoolConnectionsDefault": HIGH_PERFORMANCE_CONNECT_UDP_H3_POOL_CONNECTIONS,
                "connectUdpSessionsPerConnectionDefault": HIGH_PERFORMANCE_CONNECT_UDP_SESSIONS_PER_CONNECTION,
                "connectUdpH3CommandQueueDepthDefault": HIGH_PERFORMANCE_CONNECT_UDP_H3_COMMAND_QUEUE_DEPTH,
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
    if let Some(value) = configured {
        return parsed_profile_selection(value, "env");
    }
    ResidentRuntimeProfileSelection {
        profile: ResidentRuntimeProfile::Balanced,
        source: "default",
        invalid_value: None,
    }
}

fn parsed_profile_selection(value: &str, source: &'static str) -> ResidentRuntimeProfileSelection {
    match ResidentRuntimeProfile::parse(value) {
        Some(profile) => ResidentRuntimeProfileSelection {
            profile,
            source,
            invalid_value: None,
        },
        None => ResidentRuntimeProfileSelection {
            profile: ResidentRuntimeProfile::Balanced,
            source: "invalid-env-fallback",
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
        let selected = select_resident_runtime_profile(Some("high"));
        assert_eq!(selected.profile, ResidentRuntimeProfile::HighPerformance);
        assert_eq!(selected.source, "env");

        let invalid = select_resident_runtime_profile(Some("unknown"));
        assert_eq!(invalid.profile, ResidentRuntimeProfile::Balanced);
        assert_eq!(invalid.source, "invalid-env-fallback");
        assert_eq!(invalid.invalid_value.as_deref(), Some("unknown"));
    }
}
