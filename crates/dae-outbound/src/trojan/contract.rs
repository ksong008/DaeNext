pub const ADAPTER_MODE: &str = "rust-native";
pub const PROTOCOL_SCOPE: &[&str] = &["trojan", "trojan-go", "trojanc"];
pub const DEFERRED_PROTOCOL_SCOPE: &[&str] = &[
    "vmess",
    "vless",
    "hysteria2",
    "tuic",
    "juicity",
    "anytls",
    "transport-combos",
];
pub const LIVE_SMOKE_REQUIRED: &[&str] = &[
    "local parser smoke for trojan and trojan-go",
    "local trojanc TCP request header framing smoke",
    "local trojanc UDP packet-over-TCP framing smoke",
];
pub const DEFAULT_TROJAN_TLS_BEFORE_TROJANC: bool = true;
pub const TROJAN_GRPC_CONTAINS_TLS: bool = true;
pub const TROJAN_GRPC_NO_OUTER_TLS: bool = true;
pub const TROJAN_SS_INNER_LAYER: bool = true;
pub const PRODUCTION_DATA_PLANE_OWNER: &str = "dae-resident-dataplane";
pub const STANDALONE_SMOKE_SURFACE: &str = "test-support-only";
