pub const ADAPTER_MODE: &str = "rust-native";
pub const PROTOCOL_SCOPE: &[&str] = &["juicity"];
pub const DEFERRED_PROTOCOL_SCOPE: &[&str] = &["anytls", "transport-combos"];
pub const LIVE_SMOKE_REQUIRED: &[&str] = &[
    "local parser smoke for Juicity",
    "local UUID validation smoke",
    "local pinned certchain decode smoke",
    "local QUIC/underlay contract smoke",
];

pub const ALPN: &[&str] = &["h3"];
pub const TLS_MIN_VERSION: u16 = 772;
pub const ENABLE_DATAGRAMS: bool = false;
pub const KEEPALIVE_SECONDS: u64 = 5;
pub const HANDSHAKE_IDLE_TIMEOUT_SECONDS: u64 = 8;
pub const INITIAL_STREAM_RECEIVE_WINDOW: u64 = 2 * 1024 * 1024;
pub const MAX_STREAM_RECEIVE_WINDOW: u64 = 32 * 1024 * 1024;
pub const INITIAL_CONNECTION_RECEIVE_WINDOW: u64 = 32 * 1024 * 1024;
pub const MAX_CONNECTION_RECEIVE_WINDOW: u64 = 64 * 1024 * 1024;
pub const MAX_OPEN_INCOMING_STREAMS: u64 = 100;
pub const QUIC_MAX_OPEN_INCOMING_STREAMS: u64 = 110;
pub const RESERVED_STREAMS_CAPABILITY: u64 = 5;
pub const UNDERLAY_AUTH_CHANNEL_CAPACITY: u64 = 64;
pub const CONGESTION_DEFAULT_OR_UNKNOWN_USES: &str = "bbr";
pub const RUNTIME_ALPN: &str = "h3";
pub const RUNTIME_KEEPALIVE_SECONDS: u64 = 5;
pub const RUNTIME_HANDSHAKE_IDLE_TIMEOUT_SECONDS: u64 = 8;

pub const TCP_UNDERLAY_USES_UDP: bool = true;
pub const TCP_UNDERLAY_PRESERVES_MARK: bool = true;
pub const TCP_UNDERLAY_DROPS_MPTCP: bool = true;
pub const UDP_UNDERLAY_USES_ORIGINAL: bool = true;
pub const UDP_PORT_ZERO_PACKET_CONN: &str = "transport_packet_conn";
pub const UDP_NONZERO_PORT_PACKET_CONN: &str = "stream_packet_conn";
pub const TRANSPORT_PACKET_CONN_USES_AUTH: bool = true;
/// HKDF/AEAD `info` label used by Juicity's transport packet connection.
///
/// This exact byte string is defined by the reference implementation
/// (`ciphers.JuicityReusedInfo`) and is part of the wire key derivation.
pub const TRANSPORT_PACKET_CONN_CIPHER_INFO: &str = "juicity-reused-info";
pub const PRODUCTION_DATA_PLANE_OWNER: &str = "dae-resident-dataplane";
pub const STANDALONE_SMOKE_SURFACE: &str = "test-support-only";
