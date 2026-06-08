const VLESS_RESPONSE_VERSION: u8 = 0;
const RESIDENT_TCP_ACCEPT_SLEEP: Duration = Duration::from_millis(20);
const RESIDENT_IDLE_SLEEP: Duration = Duration::from_millis(5);
const RESIDENT_TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(300);
const RESIDENT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const RESIDENT_UDP_RESPONSE_TIMEOUT: Duration = Duration::from_secs(8);
const RESIDENT_TCP_FLOW_STACK_BYTES_ENV: &str = "DAE_RESIDENT_TCP_FLOW_STACK_BYTES";
const RESIDENT_TCP_FLOW_STACK_BYTES_DEFAULT: usize = 512 * 1024;
const RESIDENT_TCP_FLOW_STACK_BYTES_MIN: usize = 128 * 1024;
const RESIDENT_TCP_FLOW_STACK_BYTES_MAX: usize = 8 * 1024 * 1024;
const RESIDENT_UDP_PACKET_WORKERS_ENV: &str = "DAE_RESIDENT_UDP_PACKET_WORKERS";
const RESIDENT_UDP_PACKET_WORKERS_DEFAULT: usize = 64;
const RESIDENT_UDP_PACKET_WORKERS_MIN: usize = 1;
const RESIDENT_UDP_PACKET_WORKERS_MAX: usize = 1024;
const RESIDENT_UDP_PACKET_STACK_BYTES_ENV: &str = "DAE_RESIDENT_UDP_PACKET_STACK_BYTES";
const RESIDENT_UDP_PACKET_STACK_BYTES_DEFAULT: usize = 256 * 1024;
const RESIDENT_UDP_PACKET_STACK_BYTES_MIN: usize = 128 * 1024;
const RESIDENT_UDP_PACKET_STACK_BYTES_MAX: usize = 4 * 1024 * 1024;
const RESIDENT_MANUAL_LATENCY_PROBE_CONCURRENCY: usize = 8;
const XTLS_RPRX_VISION: &str = "xtls-rprx-vision";
const VISION_COMMAND_CONTINUE: u8 = 0;
const VISION_COMMAND_END: u8 = 1;
const VISION_COMMAND_DIRECT: u8 = 2;
const TLS_RECORD_HEADER_LEN: usize = 5;
const TLS_RECORD_MAX_PAYLOAD_LEN: usize = 16 * 1024 + 2048;
const XUDP_MUX_TARGET: &str = "v1.mux.cool:666";
const XUDP_COMMAND_NEW: u8 = 1;
const XUDP_OPTION_DATA: u8 = 1;
const XUDP_NETWORK_UDP: u8 = 2;
static RESIDENT_RELOAD_GENERATION: AtomicU64 = AtomicU64::new(1);

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
        "udpPacketTasks": {
            "limit": {
                "env": RESIDENT_UDP_PACKET_WORKERS_ENV,
                "default": RESIDENT_UDP_PACKET_WORKERS_DEFAULT,
                "min": RESIDENT_UDP_PACKET_WORKERS_MIN,
                "max": RESIDENT_UDP_PACKET_WORKERS_MAX,
            },
            "stackBytes": {
                "env": RESIDENT_UDP_PACKET_STACK_BYTES_ENV,
                "default": RESIDENT_UDP_PACKET_STACK_BYTES_DEFAULT,
                "min": RESIDENT_UDP_PACKET_STACK_BYTES_MIN,
                "max": RESIDENT_UDP_PACKET_STACK_BYTES_MAX,
            },
            "model": "bounded resident packet session manager keyed by graph id, outbound, peer, original destination, and packet semantics",
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
            RESIDENT_UDP_PACKET_WORKERS_ENV,
            RESIDENT_UDP_PACKET_WORKERS_DEFAULT,
        ),
        (
            RESIDENT_UDP_PACKET_STACK_BYTES_ENV,
            RESIDENT_UDP_PACKET_STACK_BYTES_DEFAULT,
        ),
    ]
}
