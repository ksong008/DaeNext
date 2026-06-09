use super::*;
pub(crate) const VLESS_RESPONSE_VERSION: u8 = 0;
pub(crate) const RESIDENT_TCP_ACCEPT_SLEEP: Duration = Duration::from_millis(20);
pub(crate) const RESIDENT_IDLE_SLEEP: Duration = Duration::from_millis(5);
pub(crate) const RESIDENT_TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(300);
pub(crate) const RESIDENT_UDP_SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(300);
pub(crate) const RESIDENT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
pub(crate) const RESIDENT_UDP_RESPONSE_TIMEOUT: Duration = Duration::from_secs(8);
pub(crate) const RESIDENT_TCP_FLOW_STACK_BYTES_ENV: &str = "RESIDENT_TCP_FLOW_STACK_BYTES";
pub(crate) const RESIDENT_TCP_FLOW_STACK_BYTES_LEGACY_ENV: &str =
    "DAE_RESIDENT_TCP_FLOW_STACK_BYTES";
pub(crate) const RESIDENT_TCP_FLOW_STACK_BYTES_DEFAULT: usize = 512 * 1024;
pub(crate) const RESIDENT_TCP_FLOW_STACK_BYTES_MIN: usize = 128 * 1024;
pub(crate) const RESIDENT_TCP_FLOW_STACK_BYTES_MAX: usize = 8 * 1024 * 1024;
pub(crate) const RESIDENT_UDP_SESSION_LIMIT_ENV: &str = "RESIDENT_UDP_SESSION_LIMIT";
pub(crate) const RESIDENT_UDP_SESSION_LIMIT_LEGACY_ENV: &str = "DAE_RESIDENT_UDP_PACKET_WORKERS";
pub(crate) const RESIDENT_UDP_SESSION_LIMIT_DEFAULT: usize = 64;
pub(crate) const RESIDENT_UDP_SESSION_LIMIT_MIN: usize = 1;
pub(crate) const RESIDENT_UDP_SESSION_LIMIT_MAX: usize = 1024;
pub(crate) const RESIDENT_MANUAL_LATENCY_PROBE_CONCURRENCY: usize = 8;
pub(crate) const XTLS_RPRX_VISION: &str = "xtls-rprx-vision";
pub(crate) const VISION_COMMAND_CONTINUE: u8 = 0;
pub(crate) const VISION_COMMAND_END: u8 = 1;
pub(crate) const VISION_COMMAND_DIRECT: u8 = 2;
pub(crate) const TLS_RECORD_HEADER_LEN: usize = 5;
pub(crate) const TLS_RECORD_MAX_PAYLOAD_LEN: usize = 16 * 1024 + 2048;
pub(crate) const XUDP_MUX_TARGET: &str = "v1.mux.cool:666";
pub(crate) const XUDP_COMMAND_NEW: u8 = 1;
pub(crate) const XUDP_OPTION_DATA: u8 = 1;
pub(crate) const XUDP_NETWORK_UDP: u8 = 2;
pub(crate) static RESIDENT_RELOAD_GENERATION: AtomicU64 = AtomicU64::new(1);

pub(crate) fn resident_runtime_defaults_contract() -> Value {
    json!({
        "tcpFlow": {
            "stackBytes": {
                "env": RESIDENT_TCP_FLOW_STACK_BYTES_ENV,
                "default": RESIDENT_TCP_FLOW_STACK_BYTES_DEFAULT,
                "min": RESIDENT_TCP_FLOW_STACK_BYTES_MIN,
                "max": RESIDENT_TCP_FLOW_STACK_BYTES_MAX,
            },
        },
        "udpSessions": {
            "limit": {
                "env": RESIDENT_UDP_SESSION_LIMIT_ENV,
                "default": RESIDENT_UDP_SESSION_LIMIT_DEFAULT,
                "min": RESIDENT_UDP_SESSION_LIMIT_MIN,
                "max": RESIDENT_UDP_SESSION_LIMIT_MAX,
            },
            "idleTimeoutSeconds": RESIDENT_UDP_SESSION_IDLE_TIMEOUT.as_secs(),
            "model": "resident UDP session manager keyed by graph id, outbound, peer, original destination, and packet semantics",
        },
    })
}

pub(crate) fn resident_runtime_environment_defaults() -> Vec<(&'static str, usize)> {
    vec![
        (
            RESIDENT_TCP_FLOW_STACK_BYTES_ENV,
            RESIDENT_TCP_FLOW_STACK_BYTES_DEFAULT,
        ),
        (
            RESIDENT_UDP_SESSION_LIMIT_ENV,
            RESIDENT_UDP_SESSION_LIMIT_DEFAULT,
        ),
    ]
}
