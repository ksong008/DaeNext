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
const BALANCED_TCP_CONNECTION_LIMIT: usize = 2_048;
const HIGH_PERFORMANCE_TCP_CONNECTION_LIMIT: usize = 4_096;
const LOW_MEMORY_WEBSOCKET_CONTROL_QUEUE_DEPTH: usize = 2;
const BALANCED_WEBSOCKET_CONTROL_QUEUE_DEPTH: usize = 4;
const HIGH_PERFORMANCE_WEBSOCKET_CONTROL_QUEUE_DEPTH: usize = 8;
const LOW_MEMORY_UDP_SESSION_SOFT_WATERMARK: usize = 128;
const BALANCED_UDP_SESSION_SOFT_WATERMARK: usize = 512;
const HIGH_PERFORMANCE_UDP_SESSION_SOFT_WATERMARK: usize = 1_024;
const LOW_MEMORY_UDP_SESSION_QUEUE_DEPTH: usize = 32;
const BALANCED_UDP_SESSION_QUEUE_DEPTH: usize = 128;
const HIGH_PERFORMANCE_UDP_SESSION_QUEUE_DEPTH: usize = 256;
const LOW_MEMORY_UDP_RUNTIME_SHARDS_MAX: usize = 1;
const BALANCED_UDP_RUNTIME_SHARDS_MAX: usize = 4;
const HIGH_PERFORMANCE_UDP_RUNTIME_SHARDS_MAX: usize = 8;
const LOW_MEMORY_UDP_DISPATCH_QUEUE_DEPTH: usize = 128;
const BALANCED_UDP_DISPATCH_QUEUE_DEPTH: usize = 512;
const HIGH_PERFORMANCE_UDP_DISPATCH_QUEUE_DEPTH: usize = 2_048;
const LOW_MEMORY_UDP_SESSION_IDLE_SECONDS: u64 = 60;
const BALANCED_UDP_SESSION_IDLE_SECONDS: u64 = 120;
const HIGH_PERFORMANCE_UDP_SESSION_IDLE_SECONDS: u64 = 300;
const PROXY_UDP_SESSION_IDLE_SECONDS_MIN: u64 = 120;
pub(crate) const RESIDENT_UDP_SESSION_IDLE_TIMEOUT_MAX: Duration =
    Duration::from_secs(HIGH_PERFORMANCE_UDP_SESSION_IDLE_SECONDS);
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
const QUIC_CANDIDATE_RACE_WIDTH: usize = 2;
const LOW_MEMORY_QUIC_CANDIDATE_STAGGER_MILLISECONDS: u64 = 250;
const BALANCED_QUIC_CANDIDATE_STAGGER_MILLISECONDS: u64 = 225;
const HIGH_PERFORMANCE_QUIC_CANDIDATE_STAGGER_MILLISECONDS: u64 = 200;
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
const LOW_MEMORY_HYSTERIA2_LOGICAL_LEASE_SOFT_WATERMARK: usize = 128;
const BALANCED_HYSTERIA2_LOGICAL_LEASE_SOFT_WATERMARK: usize = 1_024;
const HIGH_PERFORMANCE_HYSTERIA2_LOGICAL_LEASE_SOFT_WATERMARK: usize = 4_096;
const LOW_MEMORY_HYSTERIA2_UDP_SESSION_SOFT_WATERMARK: usize = 32;
const BALANCED_HYSTERIA2_UDP_SESSION_SOFT_WATERMARK: usize = 512;
const HIGH_PERFORMANCE_HYSTERIA2_UDP_SESSION_SOFT_WATERMARK: usize = 1_024;
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
const LOW_MEMORY_HYSTERIA2_INITIAL_CONNECT_ATTEMPT_LIMIT: usize = 2;
const BALANCED_HYSTERIA2_INITIAL_CONNECT_ATTEMPT_LIMIT: usize = 4;
const HIGH_PERFORMANCE_HYSTERIA2_INITIAL_CONNECT_ATTEMPT_LIMIT: usize = 8;
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
const LOW_MEMORY_H2_CARRIER_OWNER_LIMIT: usize = 8;
const BALANCED_H2_CARRIER_OWNER_LIMIT: usize = 32;
const HIGH_PERFORMANCE_H2_CARRIER_OWNER_LIMIT: usize = 128;
const LOW_MEMORY_H2_PENDING_OPEN_LIMIT: usize = 64;
const BALANCED_H2_PENDING_OPEN_LIMIT: usize = 256;
const HIGH_PERFORMANCE_H2_PENDING_OPEN_LIMIT: usize = 1_024;
const LOW_MEMORY_H2_STREAM_RECEIVE_WINDOW_BYTES: u32 = 256 * 1024;
const BALANCED_H2_STREAM_RECEIVE_WINDOW_BYTES: u32 = 1024 * 1024;
const HIGH_PERFORMANCE_H2_STREAM_RECEIVE_WINDOW_BYTES: u32 = 2 * 1024 * 1024;
const LOW_MEMORY_H2_CONNECTION_RECEIVE_WINDOW_BYTES: u32 = 1024 * 1024;
const BALANCED_H2_CONNECTION_RECEIVE_WINDOW_BYTES: u32 = 4 * 1024 * 1024;
const HIGH_PERFORMANCE_H2_CONNECTION_RECEIVE_WINDOW_BYTES: u32 = 16 * 1024 * 1024;
const LOW_MEMORY_MEEK_RESPONSE_HEADER_BYTES: usize = 8 * 1024;
const BALANCED_MEEK_RESPONSE_HEADER_BYTES: usize = 16 * 1024;
const HIGH_PERFORMANCE_MEEK_RESPONSE_HEADER_BYTES: usize = 32 * 1024;
const LOW_MEMORY_MEEK_RESPONSE_BODY_BYTES: usize = 256 * 1024;
const BALANCED_MEEK_RESPONSE_BODY_BYTES: usize = 1024 * 1024;
const HIGH_PERFORMANCE_MEEK_RESPONSE_BODY_BYTES: usize = 4 * 1024 * 1024;
const LOW_MEMORY_MEEK_OWNER_LIMIT: usize = 8;
const BALANCED_MEEK_OWNER_LIMIT: usize = 32;
const HIGH_PERFORMANCE_MEEK_OWNER_LIMIT: usize = 128;
const LOW_MEMORY_MEEK_IDLE_CONNECTION_LIMIT: usize = 1;
const BALANCED_MEEK_IDLE_CONNECTION_LIMIT: usize = 2;
const HIGH_PERFORMANCE_MEEK_IDLE_CONNECTION_LIMIT: usize = 4;
const LOW_MEMORY_MEEK_IDLE_CONNECTION_TIMEOUT_SECONDS: u64 = 15;
const BALANCED_MEEK_IDLE_CONNECTION_TIMEOUT_SECONDS: u64 = 30;
const HIGH_PERFORMANCE_MEEK_IDLE_CONNECTION_TIMEOUT_SECONDS: u64 = 60;
const LOW_MEMORY_VLESS_MUX_OWNER_LIMIT: usize = 8;
const BALANCED_VLESS_MUX_OWNER_LIMIT: usize = 32;
const HIGH_PERFORMANCE_VLESS_MUX_OWNER_LIMIT: usize = 128;
const LOW_MEMORY_VLESS_MUX_PHYSICALS_PER_OWNER: usize = 2;
const BALANCED_VLESS_MUX_PHYSICALS_PER_OWNER: usize = 4;
const HIGH_PERFORMANCE_VLESS_MUX_PHYSICALS_PER_OWNER: usize = 8;
const LOW_MEMORY_VLESS_MUX_LOGICALS_PER_PHYSICAL: usize = 16;
const BALANCED_VLESS_MUX_LOGICALS_PER_PHYSICAL: usize = 64;
const HIGH_PERFORMANCE_VLESS_MUX_LOGICALS_PER_PHYSICAL: usize = 128;
const LOW_MEMORY_VLESS_MUX_CUMULATIVE_LOGICALS_PER_PHYSICAL: usize = 1_024;
const BALANCED_VLESS_MUX_CUMULATIVE_LOGICALS_PER_PHYSICAL: usize = 4_096;
const HIGH_PERFORMANCE_VLESS_MUX_CUMULATIVE_LOGICALS_PER_PHYSICAL: usize = 16_384;
const LOW_MEMORY_VLESS_MUX_COMMAND_QUEUE_DEPTH: usize = 64;
const BALANCED_VLESS_MUX_COMMAND_QUEUE_DEPTH: usize = 256;
const HIGH_PERFORMANCE_VLESS_MUX_COMMAND_QUEUE_DEPTH: usize = 1_024;
const LOW_MEMORY_VLESS_MUX_LOGICAL_EVENT_QUEUE_DEPTH: usize = 8;
const BALANCED_VLESS_MUX_LOGICAL_EVENT_QUEUE_DEPTH: usize = 32;
const HIGH_PERFORMANCE_VLESS_MUX_LOGICAL_EVENT_QUEUE_DEPTH: usize = 64;
const LOW_MEMORY_VLESS_MUX_LOGICAL_BUFFER_BYTES: usize = 64 * 1024;
const BALANCED_VLESS_MUX_LOGICAL_BUFFER_BYTES: usize = 128 * 1024;
const HIGH_PERFORMANCE_VLESS_MUX_LOGICAL_BUFFER_BYTES: usize = 256 * 1024;
const LOW_MEMORY_VLESS_MUX_FRAME_BYTES: usize = 8 * 1024;
const BALANCED_VLESS_MUX_FRAME_BYTES: usize = 16 * 1024;
const HIGH_PERFORMANCE_VLESS_MUX_FRAME_BYTES: usize = 32 * 1024;
const LOW_MEMORY_VLESS_MUX_SID_QUARANTINE_LIMIT: usize = 128;
const BALANCED_VLESS_MUX_SID_QUARANTINE_LIMIT: usize = 1_024;
const HIGH_PERFORMANCE_VLESS_MUX_SID_QUARANTINE_LIMIT: usize = 4_096;
const VLESS_MUX_SID_QUARANTINE_TTL_SECONDS: u64 = 10;
const LOW_MEMORY_VLESS_MUX_IDLE_TIMEOUT_SECONDS: u64 = 15;
const BALANCED_VLESS_MUX_IDLE_TIMEOUT_SECONDS: u64 = 30;
const HIGH_PERFORMANCE_VLESS_MUX_IDLE_TIMEOUT_SECONDS: u64 = 60;
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
const LOW_MEMORY_DNS_UDP_FORWARDER_INFLIGHT_WINDOW: usize = 32;
const BALANCED_DNS_UDP_FORWARDER_INFLIGHT_WINDOW: usize = 64;
const HIGH_PERFORMANCE_DNS_UDP_FORWARDER_INFLIGHT_WINDOW: usize = 256;
const LOW_MEMORY_DNS_UDP_FORWARDER_ATTEMPTS: usize = 2;
const BALANCED_DNS_UDP_FORWARDER_ATTEMPTS: usize = 3;
const HIGH_PERFORMANCE_DNS_UDP_FORWARDER_ATTEMPTS: usize = 3;
const LOW_MEMORY_DNS_UDP_SHARD_IDLE_SECONDS: u64 = 15;
const BALANCED_DNS_UDP_SHARD_IDLE_SECONDS: u64 = 30;
const HIGH_PERFORMANCE_DNS_UDP_SHARD_IDLE_SECONDS: u64 = 60;
const LOW_MEMORY_DNS_PROXY_UDP_ACTORS: usize = 2;
const BALANCED_DNS_PROXY_UDP_ACTORS: usize = 8;
const HIGH_PERFORMANCE_DNS_PROXY_UDP_ACTORS: usize = 16;
const LOW_MEMORY_DNS_FLIGHT_ENTRY_LIMIT: usize = 1_024;
const BALANCED_DNS_FLIGHT_ENTRY_LIMIT: usize = 4_096;
const HIGH_PERFORMANCE_DNS_FLIGHT_ENTRY_LIMIT: usize = 16_384;
const LOW_MEMORY_DNS_FLIGHT_FOLLOWERS_PER_ENTRY: usize = 512;
const BALANCED_DNS_FLIGHT_FOLLOWERS_PER_ENTRY: usize = 4_096;
const HIGH_PERFORMANCE_DNS_FLIGHT_FOLLOWERS_PER_ENTRY: usize = 16_384;
const LOW_MEMORY_DNS_FLIGHT_RETAINED_BYTES: usize = 8 * 1024 * 1024;
const BALANCED_DNS_FLIGHT_RETAINED_BYTES: usize = 32 * 1024 * 1024;
const HIGH_PERFORMANCE_DNS_FLIGHT_RETAINED_BYTES: usize = 128 * 1024 * 1024;
const DNS_UPSTREAM_CANDIDATE_RACE_WIDTH: usize = 2;
const LOW_MEMORY_DNS_TCP_UDP_HEDGE_INITIAL_MILLISECONDS: u64 = 500;
const LOW_MEMORY_DNS_TCP_UDP_HEDGE_MINIMUM_MILLISECONDS: u64 = 400;
const LOW_MEMORY_DNS_TCP_UDP_HEDGE_MAXIMUM_MILLISECONDS: u64 = 500;
const BALANCED_DNS_TCP_UDP_HEDGE_INITIAL_MILLISECONDS: u64 = 400;
const BALANCED_DNS_TCP_UDP_HEDGE_MINIMUM_MILLISECONDS: u64 = 300;
const BALANCED_DNS_TCP_UDP_HEDGE_MAXIMUM_MILLISECONDS: u64 = 500;
const HIGH_PERFORMANCE_DNS_TCP_UDP_HEDGE_INITIAL_MILLISECONDS: u64 = 300;
const HIGH_PERFORMANCE_DNS_TCP_UDP_HEDGE_MINIMUM_MILLISECONDS: u64 = 300;
const HIGH_PERFORMANCE_DNS_TCP_UDP_HEDGE_MAXIMUM_MILLISECONDS: u64 = 500;
const DNS_TCP_UDP_HEDGE_LEARNING_SAMPLES: u32 = 16;
const LOW_MEMORY_DNS_TARGET_REFRESH_CONCURRENCY: usize = 1;
const BALANCED_DNS_TARGET_REFRESH_CONCURRENCY: usize = 2;
const HIGH_PERFORMANCE_DNS_TARGET_REFRESH_CONCURRENCY: usize = 4;
const LOW_MEMORY_DNS_TARGET_REFRESH_QUEUE_DEPTH: usize = 16;
const BALANCED_DNS_TARGET_REFRESH_QUEUE_DEPTH: usize = 64;
const HIGH_PERFORMANCE_DNS_TARGET_REFRESH_QUEUE_DEPTH: usize = 128;
const LOW_MEMORY_DNS_TCP_CONNECTIONS_PER_ROUTE: usize = 2;
const BALANCED_DNS_TCP_CONNECTIONS_PER_ROUTE: usize = 8;
const HIGH_PERFORMANCE_DNS_TCP_CONNECTIONS_PER_ROUTE: usize = 16;
const LOW_MEMORY_DNS_TCP_REQUESTS_PER_CONNECTION: usize = 64;
const BALANCED_DNS_TCP_REQUESTS_PER_CONNECTION: usize = 256;
const HIGH_PERFORMANCE_DNS_TCP_REQUESTS_PER_CONNECTION: usize = 512;
const LOW_MEMORY_DNS_BIND_UDP_INFLIGHT: usize = 256;
const BALANCED_DNS_BIND_UDP_INFLIGHT: usize = 1_024;
const HIGH_PERFORMANCE_DNS_BIND_UDP_INFLIGHT: usize = 4_096;
const LOW_MEMORY_DNS_BIND_TCP_CONNECTIONS: usize = 64;
const BALANCED_DNS_BIND_TCP_CONNECTIONS: usize = 512;
const HIGH_PERFORMANCE_DNS_BIND_TCP_CONNECTIONS: usize = 1_024;
const DNS_BIND_TCP_LISTEN_BACKLOG_FLOOR: usize = 128;
const LOW_MEMORY_DNS_BIND_TCP_QUERIES: usize = 512;
const BALANCED_DNS_BIND_TCP_QUERIES: usize = 4_096;
const HIGH_PERFORMANCE_DNS_BIND_TCP_QUERIES: usize = 16_384;
const LOW_MEMORY_DNS_BIND_TCP_QUERIES_PER_CONNECTION: usize = 64;
const BALANCED_DNS_BIND_TCP_QUERIES_PER_CONNECTION: usize = 256;
const HIGH_PERFORMANCE_DNS_BIND_TCP_QUERIES_PER_CONNECTION: usize = 512;
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
pub(crate) struct QuicCandidateRaceResourceProfile {
    max_in_flight: usize,
    stagger: Duration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TcpRelayResourceProfile {
    websocket_control_queue_depth: usize,
}

impl TcpRelayResourceProfile {
    pub(crate) fn selected() -> Self {
        Self::from_runtime_profile(ResidentRuntimeProfileSelection::selected().profile)
    }

    pub(crate) const fn from_runtime_profile(profile: ResidentRuntimeProfile) -> Self {
        Self {
            websocket_control_queue_depth: match profile {
                ResidentRuntimeProfile::LowMemory => LOW_MEMORY_WEBSOCKET_CONTROL_QUEUE_DEPTH,
                ResidentRuntimeProfile::Balanced => BALANCED_WEBSOCKET_CONTROL_QUEUE_DEPTH,
                ResidentRuntimeProfile::HighPerformance => {
                    HIGH_PERFORMANCE_WEBSOCKET_CONTROL_QUEUE_DEPTH
                }
            },
        }
    }

    pub(crate) const fn websocket_control_queue_depth(self) -> usize {
        self.websocket_control_queue_depth
    }
}

impl QuicCandidateRaceResourceProfile {
    pub(crate) fn selected() -> Self {
        Self::from_runtime_profile(ResidentRuntimeProfileSelection::selected().profile)
    }

    pub(crate) const fn from_runtime_profile(profile: ResidentRuntimeProfile) -> Self {
        let stagger_milliseconds = match profile {
            ResidentRuntimeProfile::LowMemory => LOW_MEMORY_QUIC_CANDIDATE_STAGGER_MILLISECONDS,
            ResidentRuntimeProfile::Balanced => BALANCED_QUIC_CANDIDATE_STAGGER_MILLISECONDS,
            ResidentRuntimeProfile::HighPerformance => {
                HIGH_PERFORMANCE_QUIC_CANDIDATE_STAGGER_MILLISECONDS
            }
        };
        Self {
            max_in_flight: QUIC_CANDIDATE_RACE_WIDTH,
            stagger: Duration::from_millis(stagger_milliseconds),
        }
    }

    pub(crate) const fn max_in_flight(self) -> usize {
        self.max_in_flight
    }

    pub(crate) const fn stagger(self) -> Duration {
        self.stagger
    }

    #[cfg(test)]
    pub(crate) const fn for_test(max_in_flight: usize, stagger: Duration) -> Self {
        Self {
            max_in_flight,
            stagger,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ResidentDnsResourceProfile {
    flight_entry_limit: usize,
    flight_followers_per_entry: usize,
    flight_retained_bytes: usize,
    upstream_candidate_race_width: usize,
    tcp_udp_hedge: ResidentDnsTcpUdpHedgeProfile,
    target_refresh_concurrency: usize,
    target_refresh_queue_depth: usize,
    tcp_connections_per_route: usize,
    tcp_requests_per_connection: usize,
    bind_udp_inflight: usize,
    bind_tcp_connections: usize,
    bind_tcp_queries: usize,
    bind_tcp_queries_per_connection: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ResidentDnsTcpUdpHedgeProfile {
    initial_delay: Duration,
    minimum_delay: Duration,
    maximum_delay: Duration,
    learning_samples: u32,
}

impl ResidentDnsTcpUdpHedgeProfile {
    const fn from_runtime_profile(profile: ResidentRuntimeProfile) -> Self {
        let (initial_milliseconds, minimum_milliseconds, maximum_milliseconds) = match profile {
            ResidentRuntimeProfile::LowMemory => (
                LOW_MEMORY_DNS_TCP_UDP_HEDGE_INITIAL_MILLISECONDS,
                LOW_MEMORY_DNS_TCP_UDP_HEDGE_MINIMUM_MILLISECONDS,
                LOW_MEMORY_DNS_TCP_UDP_HEDGE_MAXIMUM_MILLISECONDS,
            ),
            ResidentRuntimeProfile::Balanced => (
                BALANCED_DNS_TCP_UDP_HEDGE_INITIAL_MILLISECONDS,
                BALANCED_DNS_TCP_UDP_HEDGE_MINIMUM_MILLISECONDS,
                BALANCED_DNS_TCP_UDP_HEDGE_MAXIMUM_MILLISECONDS,
            ),
            ResidentRuntimeProfile::HighPerformance => (
                HIGH_PERFORMANCE_DNS_TCP_UDP_HEDGE_INITIAL_MILLISECONDS,
                HIGH_PERFORMANCE_DNS_TCP_UDP_HEDGE_MINIMUM_MILLISECONDS,
                HIGH_PERFORMANCE_DNS_TCP_UDP_HEDGE_MAXIMUM_MILLISECONDS,
            ),
        };
        Self {
            initial_delay: Duration::from_millis(initial_milliseconds),
            minimum_delay: Duration::from_millis(minimum_milliseconds),
            maximum_delay: Duration::from_millis(maximum_milliseconds),
            learning_samples: DNS_TCP_UDP_HEDGE_LEARNING_SAMPLES,
        }
    }

    pub(crate) const fn initial_delay(self) -> Duration {
        self.initial_delay
    }

    pub(crate) const fn minimum_delay(self) -> Duration {
        self.minimum_delay
    }

    pub(crate) const fn maximum_delay(self) -> Duration {
        self.maximum_delay
    }

    pub(crate) const fn learning_samples(self) -> u32 {
        self.learning_samples
    }

    fn json(self) -> Value {
        json!({
            "initialMs": self.initial_delay.as_millis(),
            "minimumMs": self.minimum_delay.as_millis(),
            "maximumMs": self.maximum_delay.as_millis(),
            "learningSamples": self.learning_samples,
        })
    }
}

impl ResidentDnsResourceProfile {
    pub(crate) fn selected() -> Self {
        Self::from_runtime_profile(ResidentRuntimeProfileSelection::selected().profile)
    }

    pub(crate) const fn from_runtime_profile(profile: ResidentRuntimeProfile) -> Self {
        match profile {
            ResidentRuntimeProfile::LowMemory => Self {
                flight_entry_limit: LOW_MEMORY_DNS_FLIGHT_ENTRY_LIMIT,
                flight_followers_per_entry: LOW_MEMORY_DNS_FLIGHT_FOLLOWERS_PER_ENTRY,
                flight_retained_bytes: LOW_MEMORY_DNS_FLIGHT_RETAINED_BYTES,
                upstream_candidate_race_width: DNS_UPSTREAM_CANDIDATE_RACE_WIDTH,
                tcp_udp_hedge: ResidentDnsTcpUdpHedgeProfile::from_runtime_profile(profile),
                target_refresh_concurrency: LOW_MEMORY_DNS_TARGET_REFRESH_CONCURRENCY,
                target_refresh_queue_depth: LOW_MEMORY_DNS_TARGET_REFRESH_QUEUE_DEPTH,
                tcp_connections_per_route: LOW_MEMORY_DNS_TCP_CONNECTIONS_PER_ROUTE,
                tcp_requests_per_connection: LOW_MEMORY_DNS_TCP_REQUESTS_PER_CONNECTION,
                bind_udp_inflight: LOW_MEMORY_DNS_BIND_UDP_INFLIGHT,
                bind_tcp_connections: LOW_MEMORY_DNS_BIND_TCP_CONNECTIONS,
                bind_tcp_queries: LOW_MEMORY_DNS_BIND_TCP_QUERIES,
                bind_tcp_queries_per_connection: LOW_MEMORY_DNS_BIND_TCP_QUERIES_PER_CONNECTION,
            },
            ResidentRuntimeProfile::Balanced => Self {
                flight_entry_limit: BALANCED_DNS_FLIGHT_ENTRY_LIMIT,
                flight_followers_per_entry: BALANCED_DNS_FLIGHT_FOLLOWERS_PER_ENTRY,
                flight_retained_bytes: BALANCED_DNS_FLIGHT_RETAINED_BYTES,
                upstream_candidate_race_width: DNS_UPSTREAM_CANDIDATE_RACE_WIDTH,
                tcp_udp_hedge: ResidentDnsTcpUdpHedgeProfile::from_runtime_profile(profile),
                target_refresh_concurrency: BALANCED_DNS_TARGET_REFRESH_CONCURRENCY,
                target_refresh_queue_depth: BALANCED_DNS_TARGET_REFRESH_QUEUE_DEPTH,
                tcp_connections_per_route: BALANCED_DNS_TCP_CONNECTIONS_PER_ROUTE,
                tcp_requests_per_connection: BALANCED_DNS_TCP_REQUESTS_PER_CONNECTION,
                bind_udp_inflight: BALANCED_DNS_BIND_UDP_INFLIGHT,
                bind_tcp_connections: BALANCED_DNS_BIND_TCP_CONNECTIONS,
                bind_tcp_queries: BALANCED_DNS_BIND_TCP_QUERIES,
                bind_tcp_queries_per_connection: BALANCED_DNS_BIND_TCP_QUERIES_PER_CONNECTION,
            },
            ResidentRuntimeProfile::HighPerformance => Self {
                flight_entry_limit: HIGH_PERFORMANCE_DNS_FLIGHT_ENTRY_LIMIT,
                flight_followers_per_entry: HIGH_PERFORMANCE_DNS_FLIGHT_FOLLOWERS_PER_ENTRY,
                flight_retained_bytes: HIGH_PERFORMANCE_DNS_FLIGHT_RETAINED_BYTES,
                upstream_candidate_race_width: DNS_UPSTREAM_CANDIDATE_RACE_WIDTH,
                tcp_udp_hedge: ResidentDnsTcpUdpHedgeProfile::from_runtime_profile(profile),
                target_refresh_concurrency: HIGH_PERFORMANCE_DNS_TARGET_REFRESH_CONCURRENCY,
                target_refresh_queue_depth: HIGH_PERFORMANCE_DNS_TARGET_REFRESH_QUEUE_DEPTH,
                tcp_connections_per_route: HIGH_PERFORMANCE_DNS_TCP_CONNECTIONS_PER_ROUTE,
                tcp_requests_per_connection: HIGH_PERFORMANCE_DNS_TCP_REQUESTS_PER_CONNECTION,
                bind_udp_inflight: HIGH_PERFORMANCE_DNS_BIND_UDP_INFLIGHT,
                bind_tcp_connections: HIGH_PERFORMANCE_DNS_BIND_TCP_CONNECTIONS,
                bind_tcp_queries: HIGH_PERFORMANCE_DNS_BIND_TCP_QUERIES,
                bind_tcp_queries_per_connection:
                    HIGH_PERFORMANCE_DNS_BIND_TCP_QUERIES_PER_CONNECTION,
            },
        }
    }

    pub(crate) const fn flight_entry_limit(self) -> usize {
        self.flight_entry_limit
    }

    pub(crate) const fn flight_followers_per_entry(self) -> usize {
        self.flight_followers_per_entry
    }

    pub(crate) const fn flight_retained_bytes(self) -> usize {
        self.flight_retained_bytes
    }

    pub(crate) const fn upstream_candidate_race_width(self) -> usize {
        self.upstream_candidate_race_width
    }

    pub(crate) const fn tcp_udp_hedge(self) -> ResidentDnsTcpUdpHedgeProfile {
        self.tcp_udp_hedge
    }

    pub(crate) const fn target_refresh_concurrency(self) -> usize {
        self.target_refresh_concurrency
    }

    pub(crate) const fn target_refresh_queue_depth(self) -> usize {
        self.target_refresh_queue_depth
    }

    pub(crate) const fn tcp_connections_per_route(self) -> usize {
        self.tcp_connections_per_route
    }

    pub(crate) const fn tcp_requests_per_connection(self) -> usize {
        self.tcp_requests_per_connection
    }

    pub(crate) const fn bind_udp_inflight(self) -> usize {
        self.bind_udp_inflight
    }

    pub(crate) const fn bind_tcp_connections(self) -> usize {
        self.bind_tcp_connections
    }

    pub(crate) const fn bind_tcp_listen_backlog(self) -> usize {
        if self.bind_tcp_connections < DNS_BIND_TCP_LISTEN_BACKLOG_FLOOR {
            DNS_BIND_TCP_LISTEN_BACKLOG_FLOOR
        } else {
            self.bind_tcp_connections
        }
    }

    pub(crate) const fn bind_tcp_queries(self) -> usize {
        self.bind_tcp_queries
    }

    pub(crate) const fn bind_tcp_queries_per_connection(self) -> usize {
        self.bind_tcp_queries_per_connection
    }

    pub(crate) fn json(self) -> Value {
        json!({
            "flightEntryLimit": self.flight_entry_limit,
            "flightFollowersPerEntry": self.flight_followers_per_entry,
            "flightRetainedBytes": self.flight_retained_bytes,
            "upstreamCandidateRaceWidth": self.upstream_candidate_race_width,
            "tcpUdpHedge": self.tcp_udp_hedge.json(),
            "targetRefreshConcurrency": self.target_refresh_concurrency,
            "targetRefreshQueueDepth": self.target_refresh_queue_depth,
            "tcpConnectionsPerRoute": self.tcp_connections_per_route,
            "tcpRequestsPerConnection": self.tcp_requests_per_connection,
            "bindUdpInflight": self.bind_udp_inflight,
            "bindTcpConnections": self.bind_tcp_connections,
            "bindTcpListenBacklog": self.bind_tcp_listen_backlog(),
            "bindTcpQueries": self.bind_tcp_queries,
            "bindTcpQueriesPerConnection": self.bind_tcp_queries_per_connection,
        })
    }
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
    logical_lease_limit: Option<usize>,
    logical_lease_soft_watermark: usize,
    udp_session_limit: Option<usize>,
    udp_session_soft_watermark: usize,
    udp_session_queue_depth: usize,
    udp_session_queue_bytes: usize,
    udp_owner_queue_bytes: usize,
    udp_session_quarantine_limit: usize,
    udp_session_quarantine_ttl: Duration,
    retry_cooldown: Duration,
    initial_connect_attempt_limit: usize,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct H2CarrierOwnerResourceProfile {
    owner_limit: usize,
    pending_open_limit: usize,
    stream_receive_window_bytes: u32,
    connection_receive_window_bytes: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct MeekTransportResourceProfile {
    response_header_bytes: usize,
    response_body_bytes: usize,
    owner_limit: usize,
    physical_connection_limit: usize,
    idle_connection_limit: usize,
    idle_connection_timeout: Duration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct VlessMuxOwnerResourceProfile {
    owner_limit: usize,
    physical_connections_per_owner: usize,
    logical_streams_per_physical: usize,
    cumulative_logical_streams_per_physical: usize,
    command_queue_depth: usize,
    logical_event_queue_depth: usize,
    logical_buffer_bytes: usize,
    frame_bytes: usize,
    sid_quarantine_limit: usize,
    sid_quarantine_ttl: Duration,
    idle_timeout: Duration,
}

impl VlessMuxOwnerResourceProfile {
    pub(crate) const fn from_runtime_profile(profile: ResidentRuntimeProfile) -> Self {
        match profile {
            ResidentRuntimeProfile::LowMemory => Self {
                owner_limit: LOW_MEMORY_VLESS_MUX_OWNER_LIMIT,
                physical_connections_per_owner: LOW_MEMORY_VLESS_MUX_PHYSICALS_PER_OWNER,
                logical_streams_per_physical: LOW_MEMORY_VLESS_MUX_LOGICALS_PER_PHYSICAL,
                cumulative_logical_streams_per_physical:
                    LOW_MEMORY_VLESS_MUX_CUMULATIVE_LOGICALS_PER_PHYSICAL,
                command_queue_depth: LOW_MEMORY_VLESS_MUX_COMMAND_QUEUE_DEPTH,
                logical_event_queue_depth: LOW_MEMORY_VLESS_MUX_LOGICAL_EVENT_QUEUE_DEPTH,
                logical_buffer_bytes: LOW_MEMORY_VLESS_MUX_LOGICAL_BUFFER_BYTES,
                frame_bytes: LOW_MEMORY_VLESS_MUX_FRAME_BYTES,
                sid_quarantine_limit: LOW_MEMORY_VLESS_MUX_SID_QUARANTINE_LIMIT,
                sid_quarantine_ttl: Duration::from_secs(VLESS_MUX_SID_QUARANTINE_TTL_SECONDS),
                idle_timeout: Duration::from_secs(LOW_MEMORY_VLESS_MUX_IDLE_TIMEOUT_SECONDS),
            },
            ResidentRuntimeProfile::Balanced => Self {
                owner_limit: BALANCED_VLESS_MUX_OWNER_LIMIT,
                physical_connections_per_owner: BALANCED_VLESS_MUX_PHYSICALS_PER_OWNER,
                logical_streams_per_physical: BALANCED_VLESS_MUX_LOGICALS_PER_PHYSICAL,
                cumulative_logical_streams_per_physical:
                    BALANCED_VLESS_MUX_CUMULATIVE_LOGICALS_PER_PHYSICAL,
                command_queue_depth: BALANCED_VLESS_MUX_COMMAND_QUEUE_DEPTH,
                logical_event_queue_depth: BALANCED_VLESS_MUX_LOGICAL_EVENT_QUEUE_DEPTH,
                logical_buffer_bytes: BALANCED_VLESS_MUX_LOGICAL_BUFFER_BYTES,
                frame_bytes: BALANCED_VLESS_MUX_FRAME_BYTES,
                sid_quarantine_limit: BALANCED_VLESS_MUX_SID_QUARANTINE_LIMIT,
                sid_quarantine_ttl: Duration::from_secs(VLESS_MUX_SID_QUARANTINE_TTL_SECONDS),
                idle_timeout: Duration::from_secs(BALANCED_VLESS_MUX_IDLE_TIMEOUT_SECONDS),
            },
            ResidentRuntimeProfile::HighPerformance => Self {
                owner_limit: HIGH_PERFORMANCE_VLESS_MUX_OWNER_LIMIT,
                physical_connections_per_owner: HIGH_PERFORMANCE_VLESS_MUX_PHYSICALS_PER_OWNER,
                logical_streams_per_physical: HIGH_PERFORMANCE_VLESS_MUX_LOGICALS_PER_PHYSICAL,
                cumulative_logical_streams_per_physical:
                    HIGH_PERFORMANCE_VLESS_MUX_CUMULATIVE_LOGICALS_PER_PHYSICAL,
                command_queue_depth: HIGH_PERFORMANCE_VLESS_MUX_COMMAND_QUEUE_DEPTH,
                logical_event_queue_depth: HIGH_PERFORMANCE_VLESS_MUX_LOGICAL_EVENT_QUEUE_DEPTH,
                logical_buffer_bytes: HIGH_PERFORMANCE_VLESS_MUX_LOGICAL_BUFFER_BYTES,
                frame_bytes: HIGH_PERFORMANCE_VLESS_MUX_FRAME_BYTES,
                sid_quarantine_limit: HIGH_PERFORMANCE_VLESS_MUX_SID_QUARANTINE_LIMIT,
                sid_quarantine_ttl: Duration::from_secs(VLESS_MUX_SID_QUARANTINE_TTL_SECONDS),
                idle_timeout: Duration::from_secs(HIGH_PERFORMANCE_VLESS_MUX_IDLE_TIMEOUT_SECONDS),
            },
        }
    }

    pub(crate) fn selected() -> Self {
        static SELECTED: std::sync::OnceLock<VlessMuxOwnerResourceProfile> =
            std::sync::OnceLock::new();
        *SELECTED.get_or_init(|| {
            Self::from_runtime_profile(ResidentRuntimeProfileSelection::selected().profile)
        })
    }

    pub(crate) const fn owner_limit(self) -> usize {
        self.owner_limit
    }

    pub(crate) const fn physical_connection_limit(self) -> usize {
        self.owner_limit
            .saturating_mul(self.physical_connections_per_owner)
    }

    pub(crate) const fn physical_connections_per_owner(self) -> usize {
        self.physical_connections_per_owner
    }

    pub(crate) const fn logical_streams_per_physical(self) -> usize {
        self.logical_streams_per_physical
    }

    pub(crate) const fn cumulative_logical_streams_per_physical(self) -> usize {
        self.cumulative_logical_streams_per_physical
    }

    pub(crate) const fn command_queue_depth(self) -> usize {
        self.command_queue_depth
    }

    pub(crate) const fn logical_event_queue_depth(self) -> usize {
        self.logical_event_queue_depth
    }

    pub(crate) const fn logical_buffer_bytes(self) -> usize {
        self.logical_buffer_bytes
    }

    pub(crate) const fn frame_bytes(self) -> usize {
        self.frame_bytes
    }

    pub(crate) const fn sid_quarantine_limit(self) -> usize {
        self.sid_quarantine_limit
    }

    pub(crate) const fn sid_quarantine_ttl(self) -> Duration {
        self.sid_quarantine_ttl
    }

    pub(crate) const fn idle_timeout(self) -> Duration {
        self.idle_timeout
    }

    pub(crate) fn idle_janitor_interval(self) -> Duration {
        self.idle_timeout / 2
    }

    #[cfg(test)]
    pub(crate) const fn with_limits_for_test(
        mut self,
        owner_limit: usize,
        physical_connections_per_owner: usize,
        logical_streams_per_physical: usize,
        cumulative_logical_streams_per_physical: usize,
        idle_timeout: Duration,
    ) -> Self {
        self.owner_limit = owner_limit;
        self.physical_connections_per_owner = physical_connections_per_owner;
        self.logical_streams_per_physical = logical_streams_per_physical;
        self.cumulative_logical_streams_per_physical = cumulative_logical_streams_per_physical;
        self.idle_timeout = idle_timeout;
        self
    }
}

impl MeekTransportResourceProfile {
    pub(crate) const fn from_runtime_profile(profile: ResidentRuntimeProfile) -> Self {
        match profile {
            ResidentRuntimeProfile::LowMemory => Self {
                response_header_bytes: LOW_MEMORY_MEEK_RESPONSE_HEADER_BYTES,
                response_body_bytes: LOW_MEMORY_MEEK_RESPONSE_BODY_BYTES,
                owner_limit: LOW_MEMORY_MEEK_OWNER_LIMIT,
                physical_connection_limit: LOW_MEMORY_TCP_CONNECTION_LIMIT,
                idle_connection_limit: LOW_MEMORY_MEEK_IDLE_CONNECTION_LIMIT,
                idle_connection_timeout: Duration::from_secs(
                    LOW_MEMORY_MEEK_IDLE_CONNECTION_TIMEOUT_SECONDS,
                ),
            },
            ResidentRuntimeProfile::Balanced => Self {
                response_header_bytes: BALANCED_MEEK_RESPONSE_HEADER_BYTES,
                response_body_bytes: BALANCED_MEEK_RESPONSE_BODY_BYTES,
                owner_limit: BALANCED_MEEK_OWNER_LIMIT,
                physical_connection_limit: BALANCED_TCP_CONNECTION_LIMIT,
                idle_connection_limit: BALANCED_MEEK_IDLE_CONNECTION_LIMIT,
                idle_connection_timeout: Duration::from_secs(
                    BALANCED_MEEK_IDLE_CONNECTION_TIMEOUT_SECONDS,
                ),
            },
            ResidentRuntimeProfile::HighPerformance => Self {
                response_header_bytes: HIGH_PERFORMANCE_MEEK_RESPONSE_HEADER_BYTES,
                response_body_bytes: HIGH_PERFORMANCE_MEEK_RESPONSE_BODY_BYTES,
                owner_limit: HIGH_PERFORMANCE_MEEK_OWNER_LIMIT,
                physical_connection_limit: HIGH_PERFORMANCE_TCP_CONNECTION_LIMIT,
                idle_connection_limit: HIGH_PERFORMANCE_MEEK_IDLE_CONNECTION_LIMIT,
                idle_connection_timeout: Duration::from_secs(
                    HIGH_PERFORMANCE_MEEK_IDLE_CONNECTION_TIMEOUT_SECONDS,
                ),
            },
        }
    }

    pub(crate) fn selected() -> Self {
        static SELECTED: std::sync::OnceLock<MeekTransportResourceProfile> =
            std::sync::OnceLock::new();
        *SELECTED.get_or_init(|| {
            Self::from_runtime_profile(ResidentRuntimeProfileSelection::selected().profile)
        })
    }

    pub(crate) const fn response_header_bytes(self) -> usize {
        self.response_header_bytes
    }

    pub(crate) const fn response_body_bytes(self) -> usize {
        self.response_body_bytes
    }

    pub(crate) const fn response_wire_bytes(self) -> usize {
        self.response_header_bytes
            .saturating_add(self.response_body_bytes)
    }

    pub(crate) const fn owner_limit(self) -> usize {
        self.owner_limit
    }

    pub(crate) const fn physical_connection_limit(self) -> usize {
        self.physical_connection_limit
    }

    pub(crate) const fn physical_connections_per_owner(self) -> usize {
        self.physical_connection_limit / self.owner_limit
    }

    pub(crate) const fn idle_connection_limit(self) -> usize {
        self.idle_connection_limit
    }

    pub(crate) const fn idle_connection_timeout(self) -> Duration {
        self.idle_connection_timeout
    }

    pub(crate) fn idle_janitor_interval(self) -> Duration {
        self.idle_connection_timeout / 2
    }

    #[cfg(test)]
    pub(crate) fn with_transport_limits_for_test(
        mut self,
        owner_limit: usize,
        physical_connection_limit: usize,
        idle_connection_limit: usize,
        idle_connection_timeout: Duration,
    ) -> Self {
        self.owner_limit = owner_limit.max(1);
        self.physical_connection_limit = physical_connection_limit.max(self.owner_limit);
        self.idle_connection_limit = idle_connection_limit;
        self.idle_connection_timeout = idle_connection_timeout;
        self
    }
}

impl H2CarrierOwnerResourceProfile {
    pub(crate) const fn from_runtime_profile(profile: ResidentRuntimeProfile) -> Self {
        let (
            owner_limit,
            pending_open_limit,
            stream_receive_window_bytes,
            connection_receive_window_bytes,
        ) = match profile {
            ResidentRuntimeProfile::LowMemory => (
                LOW_MEMORY_H2_CARRIER_OWNER_LIMIT,
                LOW_MEMORY_H2_PENDING_OPEN_LIMIT,
                LOW_MEMORY_H2_STREAM_RECEIVE_WINDOW_BYTES,
                LOW_MEMORY_H2_CONNECTION_RECEIVE_WINDOW_BYTES,
            ),
            ResidentRuntimeProfile::Balanced => (
                BALANCED_H2_CARRIER_OWNER_LIMIT,
                BALANCED_H2_PENDING_OPEN_LIMIT,
                BALANCED_H2_STREAM_RECEIVE_WINDOW_BYTES,
                BALANCED_H2_CONNECTION_RECEIVE_WINDOW_BYTES,
            ),
            ResidentRuntimeProfile::HighPerformance => (
                HIGH_PERFORMANCE_H2_CARRIER_OWNER_LIMIT,
                HIGH_PERFORMANCE_H2_PENDING_OPEN_LIMIT,
                HIGH_PERFORMANCE_H2_STREAM_RECEIVE_WINDOW_BYTES,
                HIGH_PERFORMANCE_H2_CONNECTION_RECEIVE_WINDOW_BYTES,
            ),
        };
        Self {
            owner_limit,
            pending_open_limit,
            stream_receive_window_bytes,
            connection_receive_window_bytes,
        }
    }

    pub(crate) fn selected() -> Self {
        static SELECTED: std::sync::OnceLock<H2CarrierOwnerResourceProfile> =
            std::sync::OnceLock::new();
        *SELECTED.get_or_init(|| {
            Self::from_runtime_profile(ResidentRuntimeProfileSelection::selected().profile)
        })
    }

    pub(crate) const fn owner_limit(self) -> usize {
        self.owner_limit
    }

    pub(crate) const fn physical_connection_limit(self) -> usize {
        self.owner_limit
    }

    pub(crate) const fn pending_open_limit(self) -> usize {
        self.pending_open_limit
    }

    pub(crate) const fn stream_receive_window_bytes(self) -> u32 {
        self.stream_receive_window_bytes
    }

    pub(crate) const fn connection_receive_window_bytes(self) -> u32 {
        self.connection_receive_window_bytes
    }

    pub(crate) fn configure_client_builder(self, builder: &mut h2::client::Builder) {
        builder
            .initial_window_size(self.stream_receive_window_bytes)
            .initial_connection_window_size(self.connection_receive_window_bytes);
    }
}

impl AnyTlsOwnerResourceProfile {
    pub(crate) const fn from_runtime_profile(profile: ResidentRuntimeProfile) -> Self {
        match profile {
            ResidentRuntimeProfile::LowMemory => Self::new(
                LOW_MEMORY_ANYTLS_OWNER_LIMIT,
                LOW_MEMORY_TCP_CONNECTION_LIMIT + LOW_MEMORY_UDP_SESSION_SOFT_WATERMARK,
                LOW_MEMORY_ANYTLS_COMMAND_QUEUE_DEPTH,
                LOW_MEMORY_ANYTLS_LOGICAL_BUFFER_BYTES,
                LOW_MEMORY_ANYTLS_SID_QUARANTINE_LIMIT,
            ),
            ResidentRuntimeProfile::Balanced => Self::new(
                BALANCED_ANYTLS_OWNER_LIMIT,
                BALANCED_TCP_CONNECTION_LIMIT + BALANCED_UDP_SESSION_SOFT_WATERMARK,
                BALANCED_ANYTLS_COMMAND_QUEUE_DEPTH,
                BALANCED_ANYTLS_LOGICAL_BUFFER_BYTES,
                BALANCED_ANYTLS_SID_QUARANTINE_LIMIT,
            ),
            ResidentRuntimeProfile::HighPerformance => Self::new(
                HIGH_PERFORMANCE_ANYTLS_OWNER_LIMIT,
                HIGH_PERFORMANCE_TCP_CONNECTION_LIMIT + HIGH_PERFORMANCE_UDP_SESSION_SOFT_WATERMARK,
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
                logical_lease_limit: None,
                logical_lease_soft_watermark: LOW_MEMORY_HYSTERIA2_LOGICAL_LEASE_SOFT_WATERMARK,
                udp_session_limit: None,
                udp_session_soft_watermark: LOW_MEMORY_HYSTERIA2_UDP_SESSION_SOFT_WATERMARK,
                udp_session_queue_depth: LOW_MEMORY_HYSTERIA2_UDP_SESSION_QUEUE_DEPTH,
                udp_session_queue_bytes: LOW_MEMORY_HYSTERIA2_UDP_SESSION_QUEUE_BYTES,
                udp_owner_queue_bytes: LOW_MEMORY_HYSTERIA2_UDP_OWNER_QUEUE_BYTES,
                udp_session_quarantine_limit: LOW_MEMORY_HYSTERIA2_UDP_SESSION_QUARANTINE_LIMIT,
                udp_session_quarantine_ttl: Duration::from_secs(
                    HYSTERIA2_UDP_SESSION_QUARANTINE_TTL_SECONDS,
                ),
                retry_cooldown: Duration::from_secs(LOW_MEMORY_HYSTERIA2_RETRY_COOLDOWN_SECONDS),
                initial_connect_attempt_limit: LOW_MEMORY_HYSTERIA2_INITIAL_CONNECT_ATTEMPT_LIMIT,
                port_hop_transition_socket_limit: HYSTERIA2_PORT_HOP_TRANSITION_SOCKET_LIMIT,
            },
            ResidentRuntimeProfile::Balanced => Self {
                owner_limit: BALANCED_HYSTERIA2_OWNER_LIMIT,
                command_queue_depth: BALANCED_HYSTERIA2_OWNER_COMMAND_QUEUE_DEPTH,
                logical_lease_limit: None,
                logical_lease_soft_watermark: BALANCED_HYSTERIA2_LOGICAL_LEASE_SOFT_WATERMARK,
                udp_session_limit: None,
                udp_session_soft_watermark: BALANCED_HYSTERIA2_UDP_SESSION_SOFT_WATERMARK,
                udp_session_queue_depth: BALANCED_HYSTERIA2_UDP_SESSION_QUEUE_DEPTH,
                udp_session_queue_bytes: BALANCED_HYSTERIA2_UDP_SESSION_QUEUE_BYTES,
                udp_owner_queue_bytes: BALANCED_HYSTERIA2_UDP_OWNER_QUEUE_BYTES,
                udp_session_quarantine_limit: BALANCED_HYSTERIA2_UDP_SESSION_QUARANTINE_LIMIT,
                udp_session_quarantine_ttl: Duration::from_secs(
                    HYSTERIA2_UDP_SESSION_QUARANTINE_TTL_SECONDS,
                ),
                retry_cooldown: Duration::from_secs(BALANCED_HYSTERIA2_RETRY_COOLDOWN_SECONDS),
                initial_connect_attempt_limit: BALANCED_HYSTERIA2_INITIAL_CONNECT_ATTEMPT_LIMIT,
                port_hop_transition_socket_limit: HYSTERIA2_PORT_HOP_TRANSITION_SOCKET_LIMIT,
            },
            ResidentRuntimeProfile::HighPerformance => Self {
                owner_limit: HIGH_PERFORMANCE_HYSTERIA2_OWNER_LIMIT,
                command_queue_depth: HIGH_PERFORMANCE_HYSTERIA2_OWNER_COMMAND_QUEUE_DEPTH,
                logical_lease_limit: None,
                logical_lease_soft_watermark:
                    HIGH_PERFORMANCE_HYSTERIA2_LOGICAL_LEASE_SOFT_WATERMARK,
                udp_session_limit: None,
                udp_session_soft_watermark: HIGH_PERFORMANCE_HYSTERIA2_UDP_SESSION_SOFT_WATERMARK,
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
                initial_connect_attempt_limit:
                    HIGH_PERFORMANCE_HYSTERIA2_INITIAL_CONNECT_ATTEMPT_LIMIT,
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

    pub(crate) const fn logical_lease_limit(self) -> Option<usize> {
        self.logical_lease_limit
    }

    pub(crate) const fn logical_lease_soft_watermark(self) -> usize {
        self.logical_lease_soft_watermark
    }

    pub(crate) const fn udp_session_limit(self) -> Option<usize> {
        self.udp_session_limit
    }

    pub(crate) const fn udp_session_soft_watermark(self) -> usize {
        self.udp_session_soft_watermark
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

    pub(crate) const fn initial_connect_attempt_limit(self) -> usize {
        self.initial_connect_attempt_limit
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
        resources.udp_session_limit = Some(session_limit.max(1));
        resources.udp_session_soft_watermark = session_limit.max(1);
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

    pub(crate) const fn udp_syscall_batch_limit(self) -> usize {
        match self {
            Self::LowMemory => 8,
            Self::Balanced => 16,
            Self::HighPerformance => 32,
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

    pub(crate) fn udp_session_soft_watermark_default(self) -> usize {
        match self {
            Self::LowMemory => LOW_MEMORY_UDP_SESSION_SOFT_WATERMARK,
            Self::Balanced => BALANCED_UDP_SESSION_SOFT_WATERMARK,
            Self::HighPerformance => HIGH_PERFORMANCE_UDP_SESSION_SOFT_WATERMARK,
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

    pub(crate) const fn udp_session_idle_timeout(self) -> Duration {
        Duration::from_secs(match self {
            Self::LowMemory => LOW_MEMORY_UDP_SESSION_IDLE_SECONDS,
            Self::Balanced => BALANCED_UDP_SESSION_IDLE_SECONDS,
            Self::HighPerformance => HIGH_PERFORMANCE_UDP_SESSION_IDLE_SECONDS,
        })
    }

    pub(crate) fn udp_proxy_session_idle_timeout(self) -> Duration {
        self.udp_session_idle_timeout()
            .max(Duration::from_secs(PROXY_UDP_SESSION_IDLE_SECONDS_MIN))
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

    pub(crate) fn dns_udp_forwarder_inflight_window_default(self) -> usize {
        match self {
            Self::LowMemory => LOW_MEMORY_DNS_UDP_FORWARDER_INFLIGHT_WINDOW,
            Self::Balanced => BALANCED_DNS_UDP_FORWARDER_INFLIGHT_WINDOW,
            Self::HighPerformance => HIGH_PERFORMANCE_DNS_UDP_FORWARDER_INFLIGHT_WINDOW,
        }
    }

    pub(crate) fn dns_udp_forwarder_attempts_default(self) -> usize {
        match self {
            Self::LowMemory => LOW_MEMORY_DNS_UDP_FORWARDER_ATTEMPTS,
            Self::Balanced => BALANCED_DNS_UDP_FORWARDER_ATTEMPTS,
            Self::HighPerformance => HIGH_PERFORMANCE_DNS_UDP_FORWARDER_ATTEMPTS,
        }
    }

    pub(crate) fn dns_udp_shard_idle_timeout(self) -> Duration {
        Duration::from_secs(match self {
            Self::LowMemory => LOW_MEMORY_DNS_UDP_SHARD_IDLE_SECONDS,
            Self::Balanced => BALANCED_DNS_UDP_SHARD_IDLE_SECONDS,
            Self::HighPerformance => HIGH_PERFORMANCE_DNS_UDP_SHARD_IDLE_SECONDS,
        })
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
                "udpSessionAdmission": {
                    "mode": "automatic",
                    "fixedLimit": Value::Null,
                    "softWatermark": LOW_MEMORY_UDP_SESSION_SOFT_WATERMARK,
                },
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
                "hysteria2LogicalLeaseAdmission": {
                    "mode": "automatic",
                    "fixedLimit": Value::Null,
                    "softWatermark": LOW_MEMORY_HYSTERIA2_LOGICAL_LEASE_SOFT_WATERMARK,
                },
                "hysteria2UdpSessionAdmission": {
                    "mode": "automatic",
                    "fixedLimit": Value::Null,
                    "softWatermark": LOW_MEMORY_HYSTERIA2_UDP_SESSION_SOFT_WATERMARK,
                },
                "hysteria2UdpSessionQueueDepth": LOW_MEMORY_HYSTERIA2_UDP_SESSION_QUEUE_DEPTH,
                "hysteria2UdpSessionQueueBytes": LOW_MEMORY_HYSTERIA2_UDP_SESSION_QUEUE_BYTES,
                "hysteria2UdpOwnerQueueBytes": LOW_MEMORY_HYSTERIA2_UDP_OWNER_QUEUE_BYTES,
                "hysteria2UdpSessionQuarantineLimit": LOW_MEMORY_HYSTERIA2_UDP_SESSION_QUARANTINE_LIMIT,
                "hysteria2UdpSessionQuarantineTtlSeconds": HYSTERIA2_UDP_SESSION_QUARANTINE_TTL_SECONDS,
                "hysteria2RetryCooldownSeconds": LOW_MEMORY_HYSTERIA2_RETRY_COOLDOWN_SECONDS,
                "hysteria2InitialConnectAttemptLimit": LOW_MEMORY_HYSTERIA2_INITIAL_CONNECT_ATTEMPT_LIMIT,
                "hysteria2PortHopTransitionSocketLimit": HYSTERIA2_PORT_HOP_TRANSITION_SOCKET_LIMIT,
                "dnsFastPathConcurrencyDefault": LOW_MEMORY_DNS_FAST_PATH_CONCURRENCY,
                "dnsFastPathQueueDepthDefault": LOW_MEMORY_DNS_FAST_PATH_QUEUE_DEPTH,
                "dnsUdpForwarderQueueDepthDefault": LOW_MEMORY_DNS_UDP_FORWARDER_QUEUE_DEPTH,
                "dnsUdpForwarderPendingDefault": LOW_MEMORY_DNS_UDP_FORWARDER_PENDING_LIMIT,
                "dnsUdpForwarderAttemptsDefault": LOW_MEMORY_DNS_UDP_FORWARDER_ATTEMPTS,
                "dnsProxyUdpActorsDefault": LOW_MEMORY_DNS_PROXY_UDP_ACTORS,
                "dnsParallelResources": ResidentDnsResourceProfile::from_runtime_profile(
                    ResidentRuntimeProfile::LowMemory,
                ).json(),
                "datapathPostflightIntervalSecondsDefault": LOW_MEMORY_DATAPATH_POSTFLIGHT_INTERVAL_SECONDS,
            },
            {
                "name": RESIDENT_RUNTIME_PROFILE_BALANCED,
                "tcpRuntimeWorkersMax": BALANCED_TCP_RUNTIME_WORKERS_MAX,
                "tcpConnectionDefault": BALANCED_TCP_CONNECTION_LIMIT,
                "udpSessionAdmission": {
                    "mode": "automatic",
                    "fixedLimit": Value::Null,
                    "softWatermark": BALANCED_UDP_SESSION_SOFT_WATERMARK,
                },
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
                "hysteria2LogicalLeaseAdmission": {
                    "mode": "automatic",
                    "fixedLimit": Value::Null,
                    "softWatermark": BALANCED_HYSTERIA2_LOGICAL_LEASE_SOFT_WATERMARK,
                },
                "hysteria2UdpSessionAdmission": {
                    "mode": "automatic",
                    "fixedLimit": Value::Null,
                    "softWatermark": BALANCED_HYSTERIA2_UDP_SESSION_SOFT_WATERMARK,
                },
                "hysteria2UdpSessionQueueDepth": BALANCED_HYSTERIA2_UDP_SESSION_QUEUE_DEPTH,
                "hysteria2UdpSessionQueueBytes": BALANCED_HYSTERIA2_UDP_SESSION_QUEUE_BYTES,
                "hysteria2UdpOwnerQueueBytes": BALANCED_HYSTERIA2_UDP_OWNER_QUEUE_BYTES,
                "hysteria2UdpSessionQuarantineLimit": BALANCED_HYSTERIA2_UDP_SESSION_QUARANTINE_LIMIT,
                "hysteria2UdpSessionQuarantineTtlSeconds": HYSTERIA2_UDP_SESSION_QUARANTINE_TTL_SECONDS,
                "hysteria2RetryCooldownSeconds": BALANCED_HYSTERIA2_RETRY_COOLDOWN_SECONDS,
                "hysteria2InitialConnectAttemptLimit": BALANCED_HYSTERIA2_INITIAL_CONNECT_ATTEMPT_LIMIT,
                "hysteria2PortHopTransitionSocketLimit": HYSTERIA2_PORT_HOP_TRANSITION_SOCKET_LIMIT,
                "dnsFastPathConcurrencyDefault": BALANCED_DNS_FAST_PATH_CONCURRENCY,
                "dnsFastPathQueueDepthDefault": BALANCED_DNS_FAST_PATH_QUEUE_DEPTH,
                "dnsUdpForwarderQueueDepthDefault": BALANCED_DNS_UDP_FORWARDER_QUEUE_DEPTH,
                "dnsUdpForwarderPendingDefault": BALANCED_DNS_UDP_FORWARDER_PENDING_LIMIT,
                "dnsUdpForwarderAttemptsDefault": BALANCED_DNS_UDP_FORWARDER_ATTEMPTS,
                "dnsProxyUdpActorsDefault": BALANCED_DNS_PROXY_UDP_ACTORS,
                "dnsParallelResources": ResidentDnsResourceProfile::from_runtime_profile(
                    ResidentRuntimeProfile::Balanced,
                ).json(),
                "datapathPostflightIntervalSecondsDefault": BALANCED_DATAPATH_POSTFLIGHT_INTERVAL_SECONDS,
            },
            {
                "name": RESIDENT_RUNTIME_PROFILE_HIGH_PERFORMANCE,
                "tcpRuntimeWorkersMax": HIGH_PERFORMANCE_TCP_RUNTIME_WORKERS_MAX,
                "tcpConnectionDefault": HIGH_PERFORMANCE_TCP_CONNECTION_LIMIT,
                "udpSessionAdmission": {
                    "mode": "automatic",
                    "fixedLimit": Value::Null,
                    "softWatermark": HIGH_PERFORMANCE_UDP_SESSION_SOFT_WATERMARK,
                },
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
                "hysteria2LogicalLeaseAdmission": {
                    "mode": "automatic",
                    "fixedLimit": Value::Null,
                    "softWatermark": HIGH_PERFORMANCE_HYSTERIA2_LOGICAL_LEASE_SOFT_WATERMARK,
                },
                "hysteria2UdpSessionAdmission": {
                    "mode": "automatic",
                    "fixedLimit": Value::Null,
                    "softWatermark": HIGH_PERFORMANCE_HYSTERIA2_UDP_SESSION_SOFT_WATERMARK,
                },
                "hysteria2UdpSessionQueueDepth": HIGH_PERFORMANCE_HYSTERIA2_UDP_SESSION_QUEUE_DEPTH,
                "hysteria2UdpSessionQueueBytes": HIGH_PERFORMANCE_HYSTERIA2_UDP_SESSION_QUEUE_BYTES,
                "hysteria2UdpOwnerQueueBytes": HIGH_PERFORMANCE_HYSTERIA2_UDP_OWNER_QUEUE_BYTES,
                "hysteria2UdpSessionQuarantineLimit": HIGH_PERFORMANCE_HYSTERIA2_UDP_SESSION_QUARANTINE_LIMIT,
                "hysteria2UdpSessionQuarantineTtlSeconds": HYSTERIA2_UDP_SESSION_QUARANTINE_TTL_SECONDS,
                "hysteria2RetryCooldownSeconds": HIGH_PERFORMANCE_HYSTERIA2_RETRY_COOLDOWN_SECONDS,
                "hysteria2InitialConnectAttemptLimit": HIGH_PERFORMANCE_HYSTERIA2_INITIAL_CONNECT_ATTEMPT_LIMIT,
                "hysteria2PortHopTransitionSocketLimit": HYSTERIA2_PORT_HOP_TRANSITION_SOCKET_LIMIT,
                "dnsFastPathConcurrencyDefault": HIGH_PERFORMANCE_DNS_FAST_PATH_CONCURRENCY,
                "dnsFastPathQueueDepthDefault": HIGH_PERFORMANCE_DNS_FAST_PATH_QUEUE_DEPTH,
                "dnsUdpForwarderQueueDepthDefault": HIGH_PERFORMANCE_DNS_UDP_FORWARDER_QUEUE_DEPTH,
                "dnsUdpForwarderPendingDefault": HIGH_PERFORMANCE_DNS_UDP_FORWARDER_PENDING_LIMIT,
                "dnsUdpForwarderAttemptsDefault": HIGH_PERFORMANCE_DNS_UDP_FORWARDER_ATTEMPTS,
                "dnsProxyUdpActorsDefault": HIGH_PERFORMANCE_DNS_PROXY_UDP_ACTORS,
                "dnsParallelResources": ResidentDnsResourceProfile::from_runtime_profile(
                    ResidentRuntimeProfile::HighPerformance,
                ).json(),
                "datapathPostflightIntervalSecondsDefault": HIGH_PERFORMANCE_DATAPATH_POSTFLIGHT_INTERVAL_SECONDS,
            },
        ],
    })
}

pub(crate) fn resident_datapath_postflight_interval_seconds_default() -> u64 {
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
    fn resident_dns_parallel_resources_scale_monotonically_and_report_the_contract() {
        let low =
            ResidentDnsResourceProfile::from_runtime_profile(ResidentRuntimeProfile::LowMemory);
        let balanced =
            ResidentDnsResourceProfile::from_runtime_profile(ResidentRuntimeProfile::Balanced);
        let high = ResidentDnsResourceProfile::from_runtime_profile(
            ResidentRuntimeProfile::HighPerformance,
        );

        assert!(low.flight_entry_limit() < balanced.flight_entry_limit());
        assert!(balanced.flight_entry_limit() < high.flight_entry_limit());
        assert!(low.flight_followers_per_entry() < balanced.flight_followers_per_entry());
        assert!(balanced.flight_followers_per_entry() < high.flight_followers_per_entry());
        assert!(low.flight_retained_bytes() < balanced.flight_retained_bytes());
        assert!(balanced.flight_retained_bytes() < high.flight_retained_bytes());
        assert_eq!(low.upstream_candidate_race_width(), 2);
        assert_eq!(balanced.upstream_candidate_race_width(), 2);
        assert_eq!(high.upstream_candidate_race_width(), 2);
        assert!(low.tcp_connections_per_route() < balanced.tcp_connections_per_route());
        assert!(balanced.tcp_connections_per_route() < high.tcp_connections_per_route());
        assert!(low.tcp_requests_per_connection() < balanced.tcp_requests_per_connection());
        assert!(balanced.tcp_requests_per_connection() < high.tcp_requests_per_connection());
        assert!(low.bind_udp_inflight() < balanced.bind_udp_inflight());
        assert!(balanced.bind_udp_inflight() < high.bind_udp_inflight());
        assert_eq!(low.bind_tcp_connections(), 64);
        assert_eq!(balanced.bind_tcp_connections(), 512);
        assert_eq!(high.bind_tcp_connections(), 1_024);
        assert_eq!(low.bind_tcp_listen_backlog(), 128);
        assert_eq!(balanced.bind_tcp_listen_backlog(), 512);
        assert_eq!(high.bind_tcp_listen_backlog(), 1_024);
        assert!(low.bind_tcp_connections() < balanced.bind_tcp_connections());
        assert!(balanced.bind_tcp_connections() < high.bind_tcp_connections());
        assert!(low.bind_tcp_queries() < balanced.bind_tcp_queries());
        assert!(balanced.bind_tcp_queries() < high.bind_tcp_queries());
        assert!(low.bind_tcp_queries_per_connection() < balanced.bind_tcp_queries_per_connection());
        assert!(
            balanced.bind_tcp_queries_per_connection() < high.bind_tcp_queries_per_connection()
        );

        for resources in [low, balanced, high] {
            let route_capacity = resources
                .tcp_connections_per_route()
                .checked_mul(resources.tcp_requests_per_connection())
                .expect("DNS TCP route capacity must fit usize");
            assert!(route_capacity >= resources.tcp_requests_per_connection());
            assert!(resources.flight_followers_per_entry() > 0);
            assert!(resources.flight_retained_bytes() > 0);
            assert!(resources.upstream_candidate_race_width() <= 2);
            assert!(resources.bind_tcp_queries_per_connection() <= resources.bind_tcp_queries());
            let contract = resources.json();
            assert_eq!(
                contract["flightEntryLimit"],
                json!(resources.flight_entry_limit())
            );
            assert_eq!(
                contract["upstreamCandidateRaceWidth"],
                json!(resources.upstream_candidate_race_width())
            );
            assert_eq!(
                contract["flightFollowersPerEntry"],
                json!(resources.flight_followers_per_entry())
            );
            assert_eq!(
                contract["flightRetainedBytes"],
                json!(resources.flight_retained_bytes())
            );
            assert_eq!(
                contract["tcpConnectionsPerRoute"],
                json!(resources.tcp_connections_per_route())
            );
            assert_eq!(
                contract["tcpRequestsPerConnection"],
                json!(resources.tcp_requests_per_connection())
            );
        }
    }

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
        assert_eq!(low_hysteria2.logical_lease_limit(), None);
        assert_eq!(balanced_hysteria2.logical_lease_limit(), None);
        assert_eq!(high_hysteria2.logical_lease_limit(), None);
        assert!(
            low_hysteria2.logical_lease_soft_watermark()
                < balanced_hysteria2.logical_lease_soft_watermark()
        );
        assert!(
            balanced_hysteria2.logical_lease_soft_watermark()
                < high_hysteria2.logical_lease_soft_watermark()
        );
        assert_eq!(low_hysteria2.udp_session_limit(), None);
        assert_eq!(balanced_hysteria2.udp_session_limit(), None);
        assert_eq!(high_hysteria2.udp_session_limit(), None);
        assert_eq!(balanced_hysteria2.udp_session_soft_watermark(), 512);
        assert!(
            low_hysteria2.udp_session_soft_watermark()
                < balanced_hysteria2.udp_session_soft_watermark()
        );
        assert!(
            balanced_hysteria2.udp_session_soft_watermark()
                < high_hysteria2.udp_session_soft_watermark()
        );
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
            low_hysteria2.initial_connect_attempt_limit()
                < balanced_hysteria2.initial_connect_attempt_limit()
        );
        assert!(
            balanced_hysteria2.initial_connect_attempt_limit()
                < high_hysteria2.initial_connect_attempt_limit()
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
            ResidentRuntimeProfile::LowMemory.udp_session_soft_watermark_default()
                < ResidentRuntimeProfile::Balanced.udp_session_soft_watermark_default()
        );
        assert!(
            ResidentRuntimeProfile::Balanced.udp_session_soft_watermark_default()
                < ResidentRuntimeProfile::HighPerformance.udp_session_soft_watermark_default()
        );
    }

    #[test]
    fn udp_session_idle_lifecycle_scales_without_shortening_proxy_sessions_too_far() {
        let low = ResidentRuntimeProfile::LowMemory;
        let balanced = ResidentRuntimeProfile::Balanced;
        let high = ResidentRuntimeProfile::HighPerformance;

        assert_eq!(low.udp_session_idle_timeout(), Duration::from_secs(60));
        assert_eq!(
            balanced.udp_session_idle_timeout(),
            Duration::from_secs(120)
        );
        assert_eq!(
            high.udp_session_idle_timeout(),
            RESIDENT_UDP_SESSION_IDLE_TIMEOUT_MAX
        );
        assert_eq!(
            low.udp_proxy_session_idle_timeout(),
            balanced.udp_proxy_session_idle_timeout()
        );
        assert_eq!(
            balanced.udp_proxy_session_idle_timeout(),
            Duration::from_secs(120)
        );
        assert_eq!(
            high.udp_proxy_session_idle_timeout(),
            RESIDENT_UDP_SESSION_IDLE_TIMEOUT_MAX
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

    #[test]
    fn h2_receive_windows_are_profile_bounded_and_monotonic() {
        let low =
            H2CarrierOwnerResourceProfile::from_runtime_profile(ResidentRuntimeProfile::LowMemory);
        let balanced =
            H2CarrierOwnerResourceProfile::from_runtime_profile(ResidentRuntimeProfile::Balanced);
        let high = H2CarrierOwnerResourceProfile::from_runtime_profile(
            ResidentRuntimeProfile::HighPerformance,
        );

        assert!(low.stream_receive_window_bytes() < balanced.stream_receive_window_bytes());
        assert!(balanced.stream_receive_window_bytes() < high.stream_receive_window_bytes());
        assert!(low.connection_receive_window_bytes() < balanced.connection_receive_window_bytes());
        assert!(
            balanced.connection_receive_window_bytes() < high.connection_receive_window_bytes()
        );
        for profile in [low, balanced, high] {
            assert!(
                profile.connection_receive_window_bytes() >= profile.stream_receive_window_bytes()
            );
        }
    }

    #[test]
    fn meek_response_limits_scale_with_the_runtime_profile() {
        let low =
            MeekTransportResourceProfile::from_runtime_profile(ResidentRuntimeProfile::LowMemory);
        let balanced =
            MeekTransportResourceProfile::from_runtime_profile(ResidentRuntimeProfile::Balanced);
        let high = MeekTransportResourceProfile::from_runtime_profile(
            ResidentRuntimeProfile::HighPerformance,
        );

        assert!(low.response_header_bytes() < balanced.response_header_bytes());
        assert!(balanced.response_header_bytes() < high.response_header_bytes());
        assert!(low.response_body_bytes() < balanced.response_body_bytes());
        assert!(balanced.response_body_bytes() < high.response_body_bytes());
        assert!(low.owner_limit() < balanced.owner_limit());
        assert!(balanced.owner_limit() < high.owner_limit());
        assert!(low.physical_connection_limit() < balanced.physical_connection_limit());
        assert!(balanced.physical_connection_limit() < high.physical_connection_limit());
        assert!(low.idle_connection_limit() < balanced.idle_connection_limit());
        assert!(balanced.idle_connection_limit() < high.idle_connection_limit());
        assert!(low.idle_connection_timeout() < balanced.idle_connection_timeout());
        assert!(balanced.idle_connection_timeout() < high.idle_connection_timeout());
        assert!(low.physical_connections_per_owner() > 0);
        assert_eq!(
            balanced.response_wire_bytes(),
            balanced
                .response_header_bytes()
                .saturating_add(balanced.response_body_bytes())
        );
    }

    #[test]
    fn vless_mux_owner_limits_scale_with_the_runtime_profile() {
        let low =
            VlessMuxOwnerResourceProfile::from_runtime_profile(ResidentRuntimeProfile::LowMemory);
        let balanced =
            VlessMuxOwnerResourceProfile::from_runtime_profile(ResidentRuntimeProfile::Balanced);
        let high = VlessMuxOwnerResourceProfile::from_runtime_profile(
            ResidentRuntimeProfile::HighPerformance,
        );

        assert!(low.owner_limit() < balanced.owner_limit());
        assert!(balanced.owner_limit() < high.owner_limit());
        assert!(low.physical_connection_limit() < balanced.physical_connection_limit());
        assert!(balanced.physical_connection_limit() < high.physical_connection_limit());
        assert!(low.logical_streams_per_physical() < balanced.logical_streams_per_physical());
        assert!(balanced.logical_streams_per_physical() < high.logical_streams_per_physical());
        assert!(low.logical_buffer_bytes() < balanced.logical_buffer_bytes());
        assert!(balanced.logical_buffer_bytes() < high.logical_buffer_bytes());
        assert!(low.frame_bytes() <= usize::from(u16::MAX));
        assert!(balanced.frame_bytes() <= usize::from(u16::MAX));
        assert!(high.frame_bytes() <= usize::from(u16::MAX));
        assert!(low.idle_timeout() < balanced.idle_timeout());
        assert!(balanced.idle_timeout() < high.idle_timeout());
    }

    #[test]
    fn dns_tcp_udp_hedge_profiles_trade_duplicate_work_for_tail_latency() {
        let low =
            ResidentDnsResourceProfile::from_runtime_profile(ResidentRuntimeProfile::LowMemory)
                .tcp_udp_hedge();
        let balanced =
            ResidentDnsResourceProfile::from_runtime_profile(ResidentRuntimeProfile::Balanced)
                .tcp_udp_hedge();
        let high = ResidentDnsResourceProfile::from_runtime_profile(
            ResidentRuntimeProfile::HighPerformance,
        )
        .tcp_udp_hedge();

        assert_eq!(low.initial_delay(), Duration::from_millis(500));
        assert_eq!(low.minimum_delay(), Duration::from_millis(400));
        assert_eq!(low.maximum_delay(), Duration::from_millis(500));
        assert_eq!(balanced.initial_delay(), Duration::from_millis(400));
        assert_eq!(balanced.minimum_delay(), Duration::from_millis(300));
        assert_eq!(balanced.maximum_delay(), Duration::from_millis(500));
        assert_eq!(high.initial_delay(), Duration::from_millis(300));
        assert_eq!(high.minimum_delay(), Duration::from_millis(300));
        assert_eq!(high.maximum_delay(), Duration::from_millis(500));
        assert_eq!(balanced.learning_samples(), 16);
        assert!(low.initial_delay() > balanced.initial_delay());
        assert!(balanced.initial_delay() > high.initial_delay());
        assert!(low.minimum_delay() > balanced.minimum_delay());
        assert_eq!(balanced.minimum_delay(), high.minimum_delay());
        assert_eq!(low.maximum_delay(), balanced.maximum_delay());
        assert_eq!(balanced.maximum_delay(), high.maximum_delay());
    }
}
