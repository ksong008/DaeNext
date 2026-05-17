pub const ADAPTER_MODE: &str = "native-opt-in";
pub const DEFAULT_GO_PATH: bool = true;
pub const PROTOCOL_SCOPE: &[&str] = &["vless"];
pub const DEFERRED_PROTOCOL_SCOPE: &[&str] =
    &["hysteria2", "tuic", "juicity", "anytls", "transport-combos"];
pub const LIVE_SMOKE_REQUIRED: &[&str] = &[
    "local parser smoke for VLESS TCP TLS Vision",
    "local parser smoke for VLESS xHTTP TLS and REALITY",
    "local VLESS key/request-header contract smoke",
];
pub const XTLS_RPRX_VISION: &str = "xtls-rprx-vision";
pub const SHARED_TRANSPORT_DEFERRED_TO_ITEM: u16 = 113;
pub const REALITY_ALLOWED_FOR_VLESS: bool = true;
pub const VISION_REQUIRES_TLS_OR_REALITY_HOOK: bool = true;
pub const FLOW_NONE_CANONICAL_EMPTY: bool = true;
pub const GRPC_DEFAULT_SERVICE_NAME: &str = "GunService";
pub const XHTTP_MODE_AUTO_EXPORT_OMITTED: bool = true;
