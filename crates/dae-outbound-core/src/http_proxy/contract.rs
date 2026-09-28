pub const ADAPTER_MODE: &str = "rust-native";
pub const PROTOCOL_SCOPE: &[&str] = &["http", "https"];
pub const LIVE_SMOKE_REQUIRED: &[&str] = &[
    "local fake HTTP proxy CONNECT",
    "local fake HTTP proxy CONNECT with Basic auth",
    "local fake HTTP transport PUT request",
];
pub use crate::tls_options::ALLOW_INSECURE_ALIASES;
pub const HTTPS_DEFAULT_ALPN_QUERY_VALUE: &str = super::HTTP_1_1_ALPN;
pub const HTTPS_DEFAULT_TLS_IMPLEMENTATION: &str = "tls";
pub const HTTPS_H2_ROUTE_CONTEXT_REQUIRED: bool = true;
