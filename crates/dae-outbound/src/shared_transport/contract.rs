pub const ADAPTER_MODE: &str = "rust-native-contract";
pub const PROTOCOL_SCOPE: &[&str] = &["transport-combos"];
pub const TRANSPORT_SCOPE: &[&str] = &[
    "tls",
    "utls",
    "reality",
    "ws",
    "wss",
    "grpc",
    "simpleobfs",
    "httpupgrade",
    "meek",
    "mux",
    "xhttp",
];
pub const LIVE_SMOKE_REQUIRED: &[&str] = &[
    "local transport IR contract smoke",
    "local xHTTP mode/ALPN/path/extra smoke",
    "local gRPC cache key and MagicNetwork contract smoke",
];

pub const ALLOW_INSECURE_ALIASES: &[&str] = &[
    "allowInsecure",
    "allow_insecure",
    "allowinsecure",
    "skipVerify",
];
pub const TLS_SCHEMES: &[&str] = &["tls", "utls"];
pub const TLS_MIN_VERSION: &str = "TLS1.3";
pub const TLS_DEFAULT_ALPN: &[&str] = &["h2", "http/1.1"];
pub const RUSTLS_SHARED_UNDERLAY_TRUE_DATAPLANE: bool = true;
pub const UTLS_FINGERPRINT_DATA_PLANE_DEFERRED: bool = true;
pub const TLS_FRAGMENT_DATA_PLANE_DEFERRED: bool = true;
pub const WS_SCHEMES: &[&str] = &["ws", "wss"];
pub const GLOBAL_TLS_FRAGMENT: bool = true;
pub const UDP_PASSTHROUGH_KEY: &str = "passthroughUdp";
pub const UDP_WITHOUT_PASSTHROUGH: &str = "unsupported";
pub const UTLS_IMITATE_QUERY: &str = "utlsImitate";

pub const REALITY_SPX_DEFAULT: &str = "/";
pub const REALITY_REQUIRES_UTLS_HANDSHAKE_STATE: bool = true;
pub const REALITY_VERIFY_PEER_CERTIFICATE: bool = true;
pub const REALITY_DATA_PLANE_DEFERRED: bool = true;

pub const GRPC_CLEAN_CACHE_HOOK: &str = "CleanGlobalClientConnectionCache";
pub const GRPC_CACHE_KEY_FIELDS: &[&str] = &[
    "address",
    "serverName",
    "dialer_identity",
    "allowInsecure",
    "somark",
    "mptcp",
];
pub const GRPC_BACKOFF_BASE_MS: u64 = 500;
pub const GRPC_BACKOFF_MULTIPLIER: f64 = 1.5;
pub const GRPC_BACKOFF_JITTER: f64 = 0.2;
pub const GRPC_BACKOFF_MAX_SECONDS: u64 = 19;
pub const GRPC_KEEPALIVE_SECONDS: u64 = 30;
pub const GRPC_KEEPALIVE_TIMEOUT_SECONDS: u64 = 10;
pub const GRPC_MIN_CONNECT_TIMEOUT_SECONDS: u64 = 5;

pub const HTTPUPGRADE_REQUEST_METHOD: &str = "GET";
pub const HTTPUPGRADE_CONNECTION_HEADER: &str = "upgrade";
pub const HTTPUPGRADE_UPGRADE_HEADER: &str = "websocket";
pub const HTTPUPGRADE_SUCCESS_STATUS: u16 = 101;
pub const HTTPUPGRADE_HTTPS_ALPN: &[&str] = &["http/1.1"];
pub const HTTPUPGRADE_UDP: &str = "unsupported";

pub const MEEK_URL_SCHEME_REQUIRED: &str = "https";
pub const MEEK_DEFAULT_ALPN: &[&str] = &["http/1.1"];
pub const MEEK_MAX_WRITE: usize = 65_536;
pub const MEEK_INITIAL_POLLING_MS: u64 = 100;
pub const MEEK_MAX_POLLING_MS: u64 = 1000;
pub const MEEK_MIN_POLLING_MS: u64 = 10;
pub const MEEK_BACKOFF: f64 = 1.5;
pub const MEEK_CLEAN_CACHE_HOOK: &str = "CleanGlobalRoundTripperCache";

pub const SIMPLEOBFS_SUPPORTED: &[&str] = &["http", "tls"];
pub const SIMPLEOBFS_TYPE_KEYS: &[&str] = &["type", "obfs"];
pub const SIMPLEOBFS_PATH_KEYS: &[&str] = &["path", "uri"];
pub const SIMPLEOBFS_HOST_KEY: &str = "host";
pub const SIMPLEOBFS_PROTOCOL_LABEL: &str = "simpleobfs(http)";

pub const MUX_REQUEST_HEADER_HEX: &str = "01020304";
pub const MUX_DATA_PLANE_DEFERRED: bool = true;

pub const XHTTP_PACKET_MAX_BYTES_DEFAULT: usize = 1 << 20;
pub const XHTTP_PACKET_MIN_GAP_MS_DEFAULT: u64 = 30;
pub const XHTTP_UNSUPPORTED_EXTRA_FIELDS: &[&str] = &[];
pub const XHTTP_TRUE_DATA_PLANE_DEFERRED: bool = true;
