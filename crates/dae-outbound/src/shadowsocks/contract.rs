pub const ADAPTER_MODE: &str = "rust-native";
pub const PROTOCOL_SCOPE: &[&str] = &["shadowsocks", "shadowsocks-2022"];
pub const DEFERRED_PROTOCOL_SCOPE: &[&str] = &[
    "shadowsocksr",
    "trojan",
    "vmess",
    "vless",
    "hysteria2",
    "tuic",
    "juicity",
    "anytls",
    "transport-combos",
];
pub const LIVE_SMOKE_REQUIRED: &[&str] = &[
    "local parser smoke for SIP002 AEAD",
    "local parser smoke for SS2022 single and multi PSK",
    "local metadata/framing smoke",
    "local replay filter smoke",
];
pub const SIMPLE_OBFS_ALIASES: &[&str] = &["obfs-local", "simpleobfs"];
pub const SIMPLE_OBFS_DEFAULT_HOST: &str = "cloudflare.com";
pub const SIP003_PATH_WITHOUT_SLASH_BEHAVIOR: &str = "append-trailing-slash";
pub const PRODUCTION_DATA_PLANE_OWNER: &str = "dae-resident-dataplane";
pub const STANDALONE_SMOKE_SURFACE: &str = "test-support-only";
