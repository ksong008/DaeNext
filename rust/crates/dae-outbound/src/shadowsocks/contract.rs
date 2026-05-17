pub const ADAPTER_MODE: &str = "native-opt-in";
pub const DEFAULT_GO_PATH: bool = true;
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
pub const SIP003_PATH_WITHOUT_SLASH_GO_BEHAVIOR: &str = "append-trailing-slash";
pub const TRANSPORT_NATIVE_DATA_PLANE_DEFERRED_TO_ITEM: u16 = 113;
