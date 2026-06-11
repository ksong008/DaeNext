pub const ADAPTER_MODE: &str = "rust-native";
pub const PROTOCOL_SCOPE: &[&str] = &["vmess"];
pub const DEFERRED_PROTOCOL_SCOPE: &[&str] = &[
    "vless",
    "hysteria2",
    "tuic",
    "juicity",
    "anytls",
    "transport-combos",
];
pub const LIVE_SMOKE_REQUIRED: &[&str] = &[
    "local parser smoke for VMess AEAD JSON",
    "local parser smoke for legacy VMess",
    "local VMess metadata/header contract smoke",
];
pub const SHARED_TRANSPORT_DEFERRED_TO_ITEM: u16 = 113;
pub const VMESS_REALITY_MUST_ERROR: bool = true;
pub const WS_TLS_USES_WSS: bool = true;
pub const GRPC_DEFAULT_SERVICE_NAME: &str = "GunService";
pub const HEADER_VERSION: u8 = 1;
pub const OPTION_CHUNK_STREAM: u8 = 1;
pub const OPTION_CHUNK_LENGTH_MASKING: u8 = 4;
pub const OPTION_GLOBAL_PADDING: u8 = 8;
pub const SECURITY_AUTO_CIPHER: u8 = 3;
