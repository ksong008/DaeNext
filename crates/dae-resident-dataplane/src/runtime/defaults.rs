use super::*;
// A half-closed upload must keep draining a response across at least one
// ordinary Internet RTT. Download activity refreshes this idle window; it is
// not a fixed delay added to every completed flow.
pub(crate) const RESIDENT_TCP_HALF_CLOSE_DRAIN_IDLE_TIMEOUT: Duration = Duration::from_secs(1);
pub(crate) const RESIDENT_UDP_DNS_SESSION_IDLE_TIMEOUT: Duration =
    Duration::from_millis(dae_datapath::DNS_NAT_TIMEOUT_MS as u64);
pub(crate) const RESIDENT_TCP_LATENCY_PROBE_TIMEOUT_MS_DEFAULT: usize = 10_000;
pub(crate) const RESIDENT_TCP_LATENCY_PROBE_TIMEOUT_MS_MIN: usize = 500;
pub(crate) const RESIDENT_TCP_LATENCY_PROBE_TIMEOUT_MS_MAX: usize = 30_000;
pub(crate) const RESIDENT_TCP_HEALTH_PROBE_TIMEOUT_MS_DEFAULT: usize = 4_000;
#[cfg(test)]
pub(crate) const RESIDENT_TCP_LATENCY_PROBE_TIMEOUT: Duration =
    Duration::from_millis(RESIDENT_TCP_LATENCY_PROBE_TIMEOUT_MS_DEFAULT as u64);
pub(crate) const RESIDENT_RUNTIME_FORCED_TASK_JOIN_GRACE: Duration = Duration::from_millis(250);
pub(crate) const RESIDENT_TCP_FLOW_STACK_BYTES_ENV: &str = "RESIDENT_TCP_FLOW_STACK_BYTES";
pub(crate) const RESIDENT_TCP_FLOW_STACK_BYTES_LEGACY_ENV: &str =
    "DAE_RESIDENT_TCP_FLOW_STACK_BYTES";
pub(crate) const RESIDENT_TCP_FLOW_STACK_BYTES_MIN: usize = 512 * 1024;
pub(crate) const RESIDENT_TCP_FLOW_STACK_BYTES_MAX: usize = 8 * 1024 * 1024;
// Native VLESS Encryption performs ML-KEM-768 key generation/decapsulation on
// the resident Tokio worker. The constant-time ML-KEM path can exceed a
// one-megabyte stack, which used to abort the manual probe/runtime worker with
// `stack overflow` before a TCP request was sent.  Keep the worker stack
// bounded, but reserve enough space for the admitted post-quantum handshake.
pub(crate) const RESIDENT_DNS_TRANSPORT_WORKER_STACK_BYTES_MIN: usize = 2 * 1024 * 1024;
pub(crate) const RESIDENT_TCP_RUNTIME_WORKERS_ENV: &str = "RESIDENT_TCP_RUNTIME_WORKERS";
pub(crate) const RESIDENT_TCP_RUNTIME_WORKERS_MIN: usize = 1;
pub(crate) const RESIDENT_TCP_RUNTIME_WORKERS_MAX: usize = 64;
pub(crate) const RESIDENT_TCP_CONNECTION_LIMIT_ENV: &str = "RESIDENT_TCP_CONNECTION_LIMIT";
pub(crate) const RESIDENT_TCP_CONNECTION_LIMIT_MIN: usize = 16;
pub(crate) const RESIDENT_TCP_CONNECTION_LIMIT_MAX: usize = 65_536;
pub(crate) const RESIDENT_UDP_SESSION_LIMIT_ENV: &str = "RESIDENT_UDP_SESSION_LIMIT";
pub(crate) const RESIDENT_UDP_SESSION_LIMIT_LEGACY_ENV: &str = "DAE_RESIDENT_UDP_PACKET_WORKERS";
pub(crate) const RESIDENT_UDP_SESSION_LIMIT_MIN: usize = 1;
pub(crate) const RESIDENT_UDP_SESSION_LIMIT_MAX: usize = tokio::sync::Semaphore::MAX_PERMITS;
pub(crate) const RESIDENT_UDP_SESSION_QUEUE_DEPTH_ENV: &str = "RESIDENT_UDP_SESSION_QUEUE_DEPTH";
pub(crate) const RESIDENT_UDP_SESSION_QUEUE_DEPTH_DEFAULT: usize = 128;
pub(crate) const RESIDENT_UDP_SESSION_QUEUE_DEPTH_MIN: usize = 1;
pub(crate) const RESIDENT_UDP_SESSION_QUEUE_DEPTH_MAX: usize = 256;
pub(crate) const RESIDENT_UDP_RUNTIME_SHARDS_ENV: &str = "RESIDENT_UDP_RUNTIME_SHARDS";
pub(crate) const RESIDENT_UDP_RUNTIME_SHARDS_MIN: usize = 1;
pub(crate) const RESIDENT_UDP_RUNTIME_SHARDS_MAX: usize = 64;
pub(crate) const RESIDENT_UDP_DISPATCH_QUEUE_DEPTH_ENV: &str = "RESIDENT_UDP_DISPATCH_QUEUE_DEPTH";
pub(crate) const RESIDENT_UDP_DISPATCH_QUEUE_DEPTH_MIN: usize = 16;
pub(crate) const RESIDENT_UDP_DISPATCH_QUEUE_DEPTH_MAX: usize = 65_536;
pub(crate) const RESIDENT_UDP_SOCKET_BUFFER_BYTES_ENV: &str = "RESIDENT_UDP_SOCKET_BUFFER_BYTES";
pub(crate) const RESIDENT_UDP_SOCKET_BUFFER_BYTES_DEFAULT: usize = 512 * 1024;
pub(crate) const RESIDENT_UDP_SOCKET_BUFFER_BYTES_MIN: usize = 64 * 1024;
pub(crate) const RESIDENT_UDP_SOCKET_BUFFER_BYTES_MAX: usize = 8 * 1024 * 1024;
pub(crate) const RESIDENT_DNS_FAST_PATH_CONCURRENCY_ENV: &str =
    "RESIDENT_DNS_FAST_PATH_CONCURRENCY";
pub(crate) const RESIDENT_DNS_FAST_PATH_CONCURRENCY_MIN: usize = 16;
pub(crate) const RESIDENT_DNS_FAST_PATH_CONCURRENCY_MAX: usize = 4096;
pub(crate) const RESIDENT_DNS_FAST_PATH_QUEUE_DEPTH_ENV: &str =
    "RESIDENT_DNS_FAST_PATH_QUEUE_DEPTH";
pub(crate) const RESIDENT_DNS_FAST_PATH_QUEUE_DEPTH_MIN: usize = 16;
pub(crate) const RESIDENT_DNS_FAST_PATH_QUEUE_DEPTH_MAX: usize = 65_536;
pub(crate) const RESIDENT_DNS_UDP_FORWARDER_QUEUE_DEPTH_ENV: &str =
    "RESIDENT_DNS_UDP_FORWARDER_QUEUE_DEPTH";
pub(crate) const RESIDENT_DNS_UDP_FORWARDER_QUEUE_DEPTH_MIN: usize = 16;
pub(crate) const RESIDENT_DNS_UDP_FORWARDER_QUEUE_DEPTH_MAX: usize = 65_536;
pub(crate) const RESIDENT_DNS_UDP_FORWARDER_PENDING_LIMIT_ENV: &str =
    "RESIDENT_DNS_UDP_FORWARDER_PENDING_LIMIT";
pub(crate) const RESIDENT_DNS_UDP_FORWARDER_PENDING_LIMIT_MIN: usize = 16;
pub(crate) const RESIDENT_DNS_UDP_FORWARDER_PENDING_LIMIT_MAX: usize = u16::MAX as usize + 1;
pub(crate) const RESIDENT_DNS_UDP_FORWARDER_ATTEMPTS_ENV: &str =
    "RESIDENT_DNS_UDP_FORWARDER_ATTEMPTS";
pub(crate) const RESIDENT_DNS_UDP_FORWARDER_ATTEMPTS_MIN: usize = 1;
pub(crate) const RESIDENT_DNS_UDP_FORWARDER_ATTEMPTS_MAX: usize = 8;
pub(crate) const RESIDENT_DNS_PROXY_UDP_ACTORS_ENV: &str = "RESIDENT_DNS_PROXY_UDP_ACTORS";
pub(crate) const RESIDENT_DNS_PROXY_UDP_ACTORS_MIN: usize = 1;
pub(crate) const RESIDENT_DNS_PROXY_UDP_ACTORS_MAX: usize = 64;
pub(crate) const RESIDENT_DNS_UPSTREAM_REFRESH_SECONDS_ENV: &str =
    "RESIDENT_DNS_UPSTREAM_REFRESH_SECONDS";
pub(crate) const RESIDENT_DNS_UPSTREAM_REFRESH_SECONDS_DEFAULT: usize = 60;
pub(crate) const RESIDENT_DNS_UPSTREAM_REFRESH_SECONDS_MIN: usize = 1;
pub(crate) const RESIDENT_DNS_UPSTREAM_REFRESH_SECONDS_MAX: usize = 3600;
pub(crate) const RESIDENT_EVENT_QUEUE_DEPTH_ENV: &str = "RESIDENT_EVENT_QUEUE_DEPTH";
pub(crate) const RESIDENT_EVENT_QUEUE_DEPTH_DEFAULT: usize = 4096;
pub(crate) const RESIDENT_EVENT_QUEUE_DEPTH_MIN: usize = 64;
pub(crate) const RESIDENT_EVENT_QUEUE_DEPTH_MAX: usize = 65_536;
pub(crate) const RESIDENT_MANUAL_LATENCY_PROBE_CONCURRENCY_DEFAULT_MIN: usize = 8;
pub(crate) const RESIDENT_MANUAL_LATENCY_PROBE_CONCURRENCY_DEFAULT_MAX: usize = 32;
pub(crate) const RESIDENT_MANUAL_LATENCY_PROBE_CONCURRENCY_MIN: usize = 1;
pub(crate) const RESIDENT_MANUAL_LATENCY_PROBE_CONCURRENCY_MAX: usize = 128;
pub(crate) const RESIDENT_HEALTH_CHECK_CONCURRENCY_DEFAULT: usize = 1;
pub(crate) const RESIDENT_HEALTH_CHECK_CONCURRENCY_MIN: usize = 1;
pub(crate) const RESIDENT_HEALTH_CHECK_CONCURRENCY_MAX: usize = 128;
pub(crate) const VISION_COMMAND_CONTINUE: u8 = 0;
pub(crate) const VISION_COMMAND_END: u8 = 1;
pub(crate) const VISION_COMMAND_DIRECT: u8 = 2;
pub(crate) const TLS_RECORD_HEADER_LEN: usize = 5;
pub(crate) const TLS_RECORD_MAX_PAYLOAD_LEN: usize = 16 * 1024 + 2048;
pub(crate) const XUDP_MUX_TARGET: &str = "v1.mux.cool:666";
pub(crate) const XUDP_COMMAND_NEW: u8 = 1;
pub(crate) const XUDP_COMMAND_KEEP: u8 = 2;
pub(crate) const XUDP_OPTION_DATA: u8 = 1;
pub(crate) const XUDP_NETWORK_UDP: u8 = 2;
static RESIDENT_RUNTIME_GENERATION: AtomicU64 = AtomicU64::new(1);

pub fn next_resident_runtime_generation() -> u64 {
    RESIDENT_RUNTIME_GENERATION.fetch_add(1, Ordering::Relaxed)
}

pub fn resident_runtime_defaults_contract() -> Value {
    let runtime_profile = ResidentRuntimeProfileSelection::selected().profile;
    json!({
        "runtimeProfile": resident_runtime_profile_contract(),
        "tcpFlow": {
            "stackBytes": {
                "configKey": "resident_tcp_flow_stack_bytes",
                "env": RESIDENT_TCP_FLOW_STACK_BYTES_ENV,
                "default": RESIDENT_TCP_FLOW_STACK_BYTES_DEFAULT,
                "min": RESIDENT_TCP_FLOW_STACK_BYTES_MIN,
                "max": RESIDENT_TCP_FLOW_STACK_BYTES_MAX,
            },
            "stackScope": "resident TCP runtime OS threads; Tokio tasks do not receive per-flow stacks",
        },
        "tcpRuntime": {
            "profileSource": "runtimeProfile",
            "workers": {
                "configKey": "resident_tcp_runtime_workers",
                "env": RESIDENT_TCP_RUNTIME_WORKERS_ENV,
                "defaultPolicy": "available_parallelism clamped by the selected resident runtime profile",
                "min": RESIDENT_TCP_RUNTIME_WORKERS_MIN,
                "max": RESIDENT_TCP_RUNTIME_WORKERS_MAX,
            },
            "connectionLimit": {
                "configKey": "resident_tcp_connection_limit",
                "env": RESIDENT_TCP_CONNECTION_LIMIT_ENV,
                "defaultPolicy": "selected resident runtime profile",
                "min": RESIDENT_TCP_CONNECTION_LIMIT_MIN,
                "max": RESIDENT_TCP_CONNECTION_LIMIT_MAX,
                "backpressure": "kernel TCP listen backlog; no unbounded user-space flow queue",
            },
        },
        "udpSessions": {
            "admission": {
                "configKey": "resident_udp_session_limit",
                "env": RESIDENT_UDP_SESSION_LIMIT_ENV,
                "defaultPolicy": "automatic count admission; the runtime profile soft watermark sizes bounded queues and caches",
                "min": RESIDENT_UDP_SESSION_LIMIT_MIN,
                "max": RESIDENT_UDP_SESSION_LIMIT_MAX,
            },
            "queueDepth": {
                "configKey": "resident_udp_session_queue_depth",
                "env": RESIDENT_UDP_SESSION_QUEUE_DEPTH_ENV,
                "default": RESIDENT_UDP_SESSION_QUEUE_DEPTH_DEFAULT,
                "min": RESIDENT_UDP_SESSION_QUEUE_DEPTH_MIN,
                "max": RESIDENT_UDP_SESSION_QUEUE_DEPTH_MAX,
            },
            "runtimeShards": {
                "env": RESIDENT_UDP_RUNTIME_SHARDS_ENV,
                "defaultPolicy": "available_parallelism clamped by runtimeProfile",
                "min": RESIDENT_UDP_RUNTIME_SHARDS_MIN,
                "max": RESIDENT_UDP_RUNTIME_SHARDS_MAX,
            },
            "dispatchQueueDepth": {
                "env": RESIDENT_UDP_DISPATCH_QUEUE_DEPTH_ENV,
                "defaultPolicy": "runtimeProfile",
                "min": RESIDENT_UDP_DISPATCH_QUEUE_DEPTH_MIN,
                "max": RESIDENT_UDP_DISPATCH_QUEUE_DEPTH_MAX,
            },
            "idleTimeoutSeconds": runtime_profile.udp_session_idle_timeout().as_secs(),
            "proxyIdleTimeoutSeconds": runtime_profile.udp_proxy_session_idle_timeout().as_secs(),
            "dnsIdleTimeoutSeconds": RESIDENT_UDP_DNS_SESSION_IDLE_TIMEOUT.as_secs(),
            "idleTimeoutPolicy": "runtime profile with a longer floor for proxy-backed sessions",
            "model": "resident UDP session manager keyed by graph id, outbound, peer, original destination, and packet semantics",
        },
        "dnsFastPath": {
            "concurrency": {
                "env": RESIDENT_DNS_FAST_PATH_CONCURRENCY_ENV,
                "defaultPolicy": "runtimeProfile",
                "min": RESIDENT_DNS_FAST_PATH_CONCURRENCY_MIN,
                "max": RESIDENT_DNS_FAST_PATH_CONCURRENCY_MAX,
            },
            "queueDepth": {
                "env": RESIDENT_DNS_FAST_PATH_QUEUE_DEPTH_ENV,
                "defaultPolicy": "runtimeProfile",
                "min": RESIDENT_DNS_FAST_PATH_QUEUE_DEPTH_MIN,
                "max": RESIDENT_DNS_FAST_PATH_QUEUE_DEPTH_MAX,
            },
        },
        "dnsUdpForwarder": {
            "queueDepth": {
                "env": RESIDENT_DNS_UDP_FORWARDER_QUEUE_DEPTH_ENV,
                "defaultPolicy": "runtimeProfile",
                "min": RESIDENT_DNS_UDP_FORWARDER_QUEUE_DEPTH_MIN,
                "max": RESIDENT_DNS_UDP_FORWARDER_QUEUE_DEPTH_MAX,
            },
            "pendingLimit": {
                "env": RESIDENT_DNS_UDP_FORWARDER_PENDING_LIMIT_ENV,
                "defaultPolicy": "runtimeProfile",
                "min": RESIDENT_DNS_UDP_FORWARDER_PENDING_LIMIT_MIN,
                "max": RESIDENT_DNS_UDP_FORWARDER_PENDING_LIMIT_MAX,
            },
            "attempts": {
                "env": RESIDENT_DNS_UDP_FORWARDER_ATTEMPTS_ENV,
                "defaultPolicy": "runtimeProfile",
                "min": RESIDENT_DNS_UDP_FORWARDER_ATTEMPTS_MIN,
                "max": RESIDENT_DNS_UDP_FORWARDER_ATTEMPTS_MAX,
            },
            "proxyActors": {
                "env": RESIDENT_DNS_PROXY_UDP_ACTORS_ENV,
                "defaultPolicy": "runtimeProfile; only request-scoped proxy UDP executors use more than one actor",
                "min": RESIDENT_DNS_PROXY_UDP_ACTORS_MIN,
                "max": RESIDENT_DNS_PROXY_UDP_ACTORS_MAX,
            },
        },
        "eventWriter": {
            "queueDepth": {
                "configKey": "resident_event_queue_depth",
                "env": RESIDENT_EVENT_QUEUE_DEPTH_ENV,
                "default": RESIDENT_EVENT_QUEUE_DEPTH_DEFAULT,
                "min": RESIDENT_EVENT_QUEUE_DEPTH_MIN,
                "max": RESIDENT_EVENT_QUEUE_DEPTH_MAX,
            },
            "filePersistence": "disabled",
            "model": "bounded resident event dispatcher; admitted events are forwarded to the product log sink and no runtime JSONL event file is created",
        },
        "manualProbe": {
            "concurrency": {
                "configKey": "resident_manual_probe_concurrency",
                "default": resident_manual_latency_probe_concurrency_default(),
                "defaultPolicy": format!(
                    "available_parallelism * 4 clamped to {}..{}",
                    RESIDENT_MANUAL_LATENCY_PROBE_CONCURRENCY_DEFAULT_MIN,
                    RESIDENT_MANUAL_LATENCY_PROBE_CONCURRENCY_DEFAULT_MAX
                ),
                "min": RESIDENT_MANUAL_LATENCY_PROBE_CONCURRENCY_MIN,
                "max": RESIDENT_MANUAL_LATENCY_PROBE_CONCURRENCY_MAX,
            },
            "tcpTimeoutMs": {
                "configKey": "resident_tcp_probe_timeout_ms",
                "default": RESIDENT_TCP_LATENCY_PROBE_TIMEOUT_MS_DEFAULT,
                "min": RESIDENT_TCP_LATENCY_PROBE_TIMEOUT_MS_MIN,
                "max": RESIDENT_TCP_LATENCY_PROBE_TIMEOUT_MS_MAX,
            },
        },
        "healthCheck": {
            "concurrency": {
                "configKey": "resident_health_check_concurrency",
                "default": RESIDENT_HEALTH_CHECK_CONCURRENCY_DEFAULT,
                "min": RESIDENT_HEALTH_CHECK_CONCURRENCY_MIN,
                "max": RESIDENT_HEALTH_CHECK_CONCURRENCY_MAX,
            },
            "tcpTimeoutMs": {
                "default": RESIDENT_TCP_HEALTH_PROBE_TIMEOUT_MS_DEFAULT,
                "policy": "background health uses an independent bounded attempt budget",
            },
            "scheduler": resident_health_scheduler_contract(),
        },
        "dnsUpstreamResolver": {
            "refreshSeconds": {
                "env": RESIDENT_DNS_UPSTREAM_REFRESH_SECONDS_ENV,
                "default": RESIDENT_DNS_UPSTREAM_REFRESH_SECONDS_DEFAULT,
                "min": RESIDENT_DNS_UPSTREAM_REFRESH_SECONDS_MIN,
                "max": RESIDENT_DNS_UPSTREAM_REFRESH_SECONDS_MAX,
            },
        },
    })
}

pub(crate) fn resident_manual_latency_probe_concurrency_default() -> usize {
    std::thread::available_parallelism()
        .map(|parallelism| parallelism.get().saturating_mul(4))
        .unwrap_or(RESIDENT_MANUAL_LATENCY_PROBE_CONCURRENCY_DEFAULT_MIN)
        .clamp(
            RESIDENT_MANUAL_LATENCY_PROBE_CONCURRENCY_DEFAULT_MIN,
            RESIDENT_MANUAL_LATENCY_PROBE_CONCURRENCY_DEFAULT_MAX,
        )
}

pub fn resident_manual_latency_probe_concurrency_from_config(config: &Config) -> usize {
    config
        .global
        .resident_manual_probe_concurrency
        .and_then(|value| usize::try_from(value).ok())
        .unwrap_or_else(resident_manual_latency_probe_concurrency_default)
        .clamp(
            RESIDENT_MANUAL_LATENCY_PROBE_CONCURRENCY_MIN,
            RESIDENT_MANUAL_LATENCY_PROBE_CONCURRENCY_MAX,
        )
}

pub fn resident_tcp_latency_probe_timeout_from_config(config: &Config) -> Duration {
    let timeout_ms = config
        .global
        .resident_tcp_probe_timeout_ms
        .and_then(|value| usize::try_from(value).ok())
        .unwrap_or(RESIDENT_TCP_LATENCY_PROBE_TIMEOUT_MS_DEFAULT)
        .clamp(
            RESIDENT_TCP_LATENCY_PROBE_TIMEOUT_MS_MIN,
            RESIDENT_TCP_LATENCY_PROBE_TIMEOUT_MS_MAX,
        );
    Duration::from_millis(timeout_ms.try_into().unwrap_or(u64::MAX))
}

pub(crate) fn resident_tcp_health_probe_timeout() -> Duration {
    Duration::from_millis(RESIDENT_TCP_HEALTH_PROBE_TIMEOUT_MS_DEFAULT as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resident_manual_probe_auto_default_stays_in_safe_range() {
        let value = resident_manual_latency_probe_concurrency_default();
        assert!(value >= RESIDENT_MANUAL_LATENCY_PROBE_CONCURRENCY_DEFAULT_MIN);
        assert!(value <= RESIDENT_MANUAL_LATENCY_PROBE_CONCURRENCY_DEFAULT_MAX);
    }

    #[test]
    fn resident_manual_probe_config_value_is_clamped() {
        let sections = dae_config::parser::parse_config(
            "global {}\nnode {}\ngroup {}\nrouting { fallback: direct }\ndns {}",
        )
        .unwrap();
        let mut config = dae_config::schema::build_config(&sections).unwrap();
        config.global.resident_manual_probe_concurrency = Some(0);
        assert_eq!(
            resident_manual_latency_probe_concurrency_from_config(&config),
            1
        );
        config.global.resident_manual_probe_concurrency = Some(u64::MAX);
        assert_eq!(
            resident_manual_latency_probe_concurrency_from_config(&config),
            RESIDENT_MANUAL_LATENCY_PROBE_CONCURRENCY_MAX
        );
    }

    #[test]
    fn manual_and_background_tcp_probe_budgets_are_independent() {
        let sections = dae_config::parser::parse_config(
            "global {}\nnode {}\ngroup {}\nrouting { fallback: direct }\ndns {}",
        )
        .unwrap();
        let mut config = dae_config::schema::build_config(&sections).unwrap();
        assert_eq!(
            resident_tcp_latency_probe_timeout_from_config(&config),
            Duration::from_millis(RESIDENT_TCP_LATENCY_PROBE_TIMEOUT_MS_DEFAULT as u64)
        );
        assert_eq!(
            resident_tcp_health_probe_timeout(),
            Duration::from_millis(RESIDENT_TCP_HEALTH_PROBE_TIMEOUT_MS_DEFAULT as u64)
        );
        config.global.resident_tcp_probe_timeout_ms = Some(8_000);
        assert_eq!(
            resident_tcp_latency_probe_timeout_from_config(&config),
            Duration::from_secs(8)
        );
        assert_eq!(
            resident_tcp_health_probe_timeout(),
            Duration::from_millis(RESIDENT_TCP_HEALTH_PROBE_TIMEOUT_MS_DEFAULT as u64)
        );
    }
}
