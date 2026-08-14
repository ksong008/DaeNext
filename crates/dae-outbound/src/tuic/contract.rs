pub const ADAPTER_MODE: &str = "rust-native";
pub const PROTOCOL_SCOPE: &[&str] = &["tuic"];
pub const DEFERRED_PROTOCOL_SCOPE: &[&str] = &["juicity", "anytls", "transport-combos"];
pub const LIVE_SMOKE_REQUIRED: &[&str] = &[
    "local parser smoke for TUIC",
    "local UUID validation smoke",
    "local QUIC/underlay contract smoke",
];

pub const TLS_MIN_VERSION: u16 = 772;
pub const ENABLE_DATAGRAMS: bool = true;
pub const KEEPALIVE_SECONDS: u64 = 3;
pub const HANDSHAKE_IDLE_TIMEOUT_SECONDS: u64 = 8;
pub const INITIAL_STREAM_RECEIVE_WINDOW: u64 = 2 * 1024 * 1024;
pub const MAX_STREAM_RECEIVE_WINDOW: u64 = 32 * 1024 * 1024;
pub const INITIAL_CONNECTION_RECEIVE_WINDOW: u64 = 32 * 1024 * 1024;
pub const MAX_CONNECTION_RECEIVE_WINDOW: u64 = 64 * 1024 * 1024;
pub const MAX_UDP_RELAY_PACKET_SIZE: u16 = 1400;
pub const CONGESTION_DEFAULT_OR_UNKNOWN_USES: &str = "bbr";

pub const UDP_RELAY_MODE_QUERY_VALUE: &str = "quic";
pub const UDP_RELAY_MODE_ADAPTER_SETS_FLAG: bool = true;
pub const UDP_RELAY_MODE_FLAG_VALUE: u64 = 1;
pub const UDP_RELAY_MODE_PROTOCOL_EFFECTIVE_MODE: &str = "quic";
pub const UDP_RELAY_MODE_COMMON_QUIC_NUMERIC_VALUE: u8 = 0;
pub const UDP_RELAY_MODE_COMMON_NATIVE_VALUE: u8 = 1;
pub const UDP_RELAY_MODE_QUIC_DEFERRED: bool = false;

pub const TCP_UNDERLAY_USES_UDP: bool = true;
pub const TCP_UNDERLAY_PRESERVES_MARK: bool = true;
pub const TCP_UNDERLAY_DROPS_MPTCP: bool = true;
pub const UDP_UNDERLAY_USES_ORIGINAL: bool = true;
pub const TRUE_QUIC_DATA_PLANE_DEFERRED_ITEM: u16 = 113;
