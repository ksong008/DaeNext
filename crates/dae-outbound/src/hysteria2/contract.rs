pub const ADAPTER_MODE: &str = "rust-native";
pub const PROTOCOL_SCOPE: &[&str] = &["hysteria2", "hy2"];
pub const DEFERRED_PROTOCOL_SCOPE: &[&str] = &["tuic", "juicity", "anytls", "transport-combos"];
pub const LIVE_SMOKE_REQUIRED: &[&str] = &[
    "local parser smoke for hysteria2 and hy2",
    "local pinSHA256 normalize smoke",
    "local UDP underlay / port hopping contract smoke",
];
pub const ALWAYS_UDP_UNDERLAY: bool = true;
pub const TCP_TARGET_USES_HYSTERIA2_CLIENT: bool = true;
pub const UDP_TARGET_USES_HYSTERIA2_CLIENT: bool = true;
pub const PRESERVE_MARK: bool = true;
pub const PRESERVE_MPTCP_FIELD_EVEN_FOR_UDP: bool = true;
pub const ROUTE_CACHE_KEY_IS_UNDERLAY_NETWORK: bool = true;
pub const PORT_HOPPING_DETECTS_DASH_OR_COMMA: bool = true;
pub const UDP_HOP_INTERVAL_FROM_EXTRA_OPTION: bool = true;
pub const PRODUCTION_DATA_PLANE_OWNER: &str = "dae-resident-dataplane";
pub const STANDALONE_SMOKE_SURFACE: &str = "test-support-only";
