pub const ADAPTER_MODE: &str = "native-opt-in";
pub const DEFAULT_GO_PATH: bool = true;
pub const PROTOCOL_SCOPE: &[&str] = &["http", "https"];
pub const LIVE_SMOKE_REQUIRED: &[&str] = &[
    "local fake HTTP proxy CONNECT",
    "local fake HTTP proxy CONNECT with Basic auth",
    "local fake HTTP transport PUT request",
];
pub const ALLOW_INSECURE_ALIASES: &[&str] = &[
    "allowInsecure",
    "allow_insecure",
    "allowinsecure",
    "skipVerify",
];
pub const HTTPS_DEFAULT_ALPN_QUERY_VALUE: &str = "h2,http/1.1";
pub const HTTPS_DEFAULT_TLS_IMPLEMENTATION: &str = "tls";
pub const HTTPS_H2_ROUTE_CONTEXT_REQUIRED: bool = true;
