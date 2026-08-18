pub const ADAPTER_MODE: &str = "rust-native";
pub const PROTOCOL_SCOPE: &[&str] = &["vless"];
pub const DEFERRED_PROTOCOL_SCOPE: &[&str] =
    &["hysteria2", "tuic", "juicity", "anytls", "transport-combos"];
pub const LIVE_SMOKE_REQUIRED: &[&str] = &[
    "local parser smoke for VLESS TCP TLS Vision",
    "local parser smoke for VLESS xHTTP TLS and REALITY",
    "local VLESS key/request-header contract smoke",
];
pub const XTLS_RPRX_VISION: &str = "xtls-rprx-vision";
pub const XTLS_RPRX_VISION_UDP443: &str = "xtls-rprx-vision-udp443";
pub const PRODUCTION_DATA_PLANE_OWNER: &str = "dae-resident-dataplane";
pub const STANDALONE_SMOKE_SURFACE: &str = "test-support-only";
pub const REALITY_ALLOWED_FOR_VLESS: bool = true;
pub const VISION_REQUIRES_TLS_OR_REALITY_HOOK: bool = true;
pub const FLOW_NONE_CANONICAL_EMPTY: bool = true;
pub const GRPC_DEFAULT_SERVICE_NAME: &str = "GunService";
pub const XHTTP_MODE_AUTO_EXPORT_OMITTED: bool = true;

pub fn is_xtls_rprx_vision_flow(flow: &str) -> bool {
    matches!(flow, XTLS_RPRX_VISION | XTLS_RPRX_VISION_UDP443)
}
