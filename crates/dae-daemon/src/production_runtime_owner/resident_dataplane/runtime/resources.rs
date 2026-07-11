use super::*;

#[derive(Clone, Debug)]
pub(crate) struct ResidentRuntimeResourceConfig {
    pub(crate) tcp_runtime_profile: ResidentTcpRuntimeProfileSelection,
    pub(crate) tcp_flow_stack_bytes: EffectiveResidentUsize,
    pub(crate) tcp_runtime_workers: EffectiveResidentUsize,
    pub(crate) tcp_connection_limit: EffectiveResidentUsize,
    pub(crate) udp_session_limit: EffectiveResidentUsize,
    pub(crate) udp_session_queue_depth: EffectiveResidentUsize,
    pub(crate) udp_socket_buffer_bytes: EffectiveResidentUsize,
    pub(crate) dns_fast_path_concurrency: EffectiveResidentUsize,
    pub(crate) dns_upstream_refresh_seconds: EffectiveResidentUsize,
    pub(crate) event_queue_depth: EffectiveResidentUsize,
    pub(crate) manual_probe_concurrency: EffectiveResidentUsize,
    pub(crate) tcp_probe_timeout_ms: EffectiveResidentUsize,
    pub(crate) health_check_concurrency: EffectiveResidentUsize,
}

impl ResidentRuntimeResourceConfig {
    pub(crate) fn from_config(config: &Config) -> Self {
        let global = &config.global;
        let tcp_runtime_profile = ResidentTcpRuntimeProfileSelection::selected();
        let available_parallelism = std::thread::available_parallelism()
            .map(|parallelism| parallelism.get())
            .unwrap_or(1);
        let tcp_runtime_workers_default = tcp_runtime_profile
            .profile
            .tcp_runtime_workers_default(available_parallelism);
        let tcp_connection_limit_default =
            tcp_runtime_profile.profile.tcp_connection_limit_default();
        Self {
            tcp_runtime_profile,
            tcp_flow_stack_bytes: effective_resident_usize(
                "resident_tcp_flow_stack_bytes",
                Some(RESIDENT_TCP_FLOW_STACK_BYTES_ENV),
                Some(RESIDENT_TCP_FLOW_STACK_BYTES_LEGACY_ENV),
                global.resident_tcp_flow_stack_bytes,
                RESIDENT_TCP_FLOW_STACK_BYTES_DEFAULT,
                RESIDENT_TCP_FLOW_STACK_BYTES_MIN,
                RESIDENT_TCP_FLOW_STACK_BYTES_MAX,
            ),
            tcp_runtime_workers: effective_resident_usize(
                "resident_tcp_runtime_workers",
                Some(RESIDENT_TCP_RUNTIME_WORKERS_ENV),
                None,
                global.resident_tcp_runtime_workers,
                tcp_runtime_workers_default,
                RESIDENT_TCP_RUNTIME_WORKERS_MIN,
                RESIDENT_TCP_RUNTIME_WORKERS_MAX,
            ),
            tcp_connection_limit: effective_resident_usize(
                "resident_tcp_connection_limit",
                Some(RESIDENT_TCP_CONNECTION_LIMIT_ENV),
                None,
                global.resident_tcp_connection_limit,
                tcp_connection_limit_default,
                RESIDENT_TCP_CONNECTION_LIMIT_MIN,
                RESIDENT_TCP_CONNECTION_LIMIT_MAX,
            ),
            udp_session_limit: effective_resident_usize(
                "resident_udp_session_limit",
                Some(RESIDENT_UDP_SESSION_LIMIT_ENV),
                Some(RESIDENT_UDP_SESSION_LIMIT_LEGACY_ENV),
                global.resident_udp_session_limit,
                RESIDENT_UDP_SESSION_LIMIT_DEFAULT,
                RESIDENT_UDP_SESSION_LIMIT_MIN,
                RESIDENT_UDP_SESSION_LIMIT_MAX,
            ),
            udp_session_queue_depth: effective_resident_usize(
                "resident_udp_session_queue_depth",
                Some(RESIDENT_UDP_SESSION_QUEUE_DEPTH_ENV),
                None,
                global.resident_udp_session_queue_depth,
                RESIDENT_UDP_SESSION_QUEUE_DEPTH_DEFAULT,
                RESIDENT_UDP_SESSION_QUEUE_DEPTH_MIN,
                RESIDENT_UDP_SESSION_QUEUE_DEPTH_MAX,
            ),
            udp_socket_buffer_bytes: effective_resident_usize(
                "resident_udp_socket_buffer_bytes",
                Some(RESIDENT_UDP_SOCKET_BUFFER_BYTES_ENV),
                None,
                None,
                RESIDENT_UDP_SOCKET_BUFFER_BYTES_DEFAULT,
                RESIDENT_UDP_SOCKET_BUFFER_BYTES_MIN,
                RESIDENT_UDP_SOCKET_BUFFER_BYTES_MAX,
            ),
            dns_fast_path_concurrency: effective_resident_usize(
                "resident_dns_fast_path_concurrency",
                Some(RESIDENT_DNS_FAST_PATH_CONCURRENCY_ENV),
                None,
                None,
                resident_dns_fast_path_concurrency(),
                RESIDENT_DNS_FAST_PATH_CONCURRENCY_MIN,
                RESIDENT_DNS_FAST_PATH_CONCURRENCY_MAX,
            ),
            dns_upstream_refresh_seconds: effective_resident_usize(
                "resident_dns_upstream_refresh_seconds",
                Some(RESIDENT_DNS_UPSTREAM_REFRESH_SECONDS_ENV),
                None,
                global.resident_dns_upstream_refresh_seconds,
                RESIDENT_DNS_UPSTREAM_REFRESH_SECONDS_DEFAULT,
                RESIDENT_DNS_UPSTREAM_REFRESH_SECONDS_MIN,
                RESIDENT_DNS_UPSTREAM_REFRESH_SECONDS_MAX,
            ),
            event_queue_depth: effective_resident_usize(
                "resident_event_queue_depth",
                Some(RESIDENT_EVENT_QUEUE_DEPTH_ENV),
                None,
                global.resident_event_queue_depth,
                RESIDENT_EVENT_QUEUE_DEPTH_DEFAULT,
                RESIDENT_EVENT_QUEUE_DEPTH_MIN,
                RESIDENT_EVENT_QUEUE_DEPTH_MAX,
            ),
            manual_probe_concurrency: effective_resident_usize(
                "resident_manual_probe_concurrency",
                None,
                None,
                global.resident_manual_probe_concurrency,
                resident_manual_latency_probe_concurrency_default(),
                RESIDENT_MANUAL_LATENCY_PROBE_CONCURRENCY_MIN,
                RESIDENT_MANUAL_LATENCY_PROBE_CONCURRENCY_MAX,
            ),
            tcp_probe_timeout_ms: effective_resident_usize(
                "resident_tcp_probe_timeout_ms",
                None,
                None,
                global.resident_tcp_probe_timeout_ms,
                RESIDENT_TCP_LATENCY_PROBE_TIMEOUT_MS_DEFAULT,
                RESIDENT_TCP_LATENCY_PROBE_TIMEOUT_MS_MIN,
                RESIDENT_TCP_LATENCY_PROBE_TIMEOUT_MS_MAX,
            ),
            health_check_concurrency: effective_resident_usize(
                "resident_health_check_concurrency",
                None,
                None,
                global.resident_health_check_concurrency,
                RESIDENT_HEALTH_CHECK_CONCURRENCY_DEFAULT,
                RESIDENT_HEALTH_CHECK_CONCURRENCY_MIN,
                RESIDENT_HEALTH_CHECK_CONCURRENCY_MAX,
            ),
        }
    }

    pub(crate) fn json(&self) -> Value {
        json!({
            "schemaVersion": 1,
            "tcpFlow": {
                "stackBytes": self.tcp_flow_stack_bytes.json(),
                "stackScope": "resident TCP runtime OS threads; Tokio tasks do not receive per-flow stacks",
            },
            "tcpRuntime": {
                "profile": self.tcp_runtime_profile.json(),
                "workers": self.tcp_runtime_workers.json(),
                "connectionLimit": self.tcp_connection_limit.json(),
                "admission": "active-flow semaphore before accept; excess connections remain in the kernel listen backlog",
            },
            "udpSessions": {
                "limit": self.udp_session_limit.json(),
                "queueDepth": self.udp_session_queue_depth.json(),
                "socketBufferBytes": self.udp_socket_buffer_bytes.json(),
            },
            "dnsFastPath": {
                "concurrency": self.dns_fast_path_concurrency.json(),
            },
            "dnsUpstreamResolver": {
                "refreshSeconds": self.dns_upstream_refresh_seconds.json(),
            },
            "eventWriter": {
                "queueDepth": self.event_queue_depth.json(),
                "filePersistence": "disabled",
            },
            "manualProbe": {
                "concurrency": self.manual_probe_concurrency.json(),
                "tcpTimeoutMs": self.tcp_probe_timeout_ms.json(),
            },
            "healthCheck": {
                "concurrency": self.health_check_concurrency.json(),
                "scheduler": resident_health_scheduler_contract(),
            },
        })
    }

    pub(crate) fn tcp_probe_timeout(&self) -> Duration {
        Duration::from_millis(
            self.tcp_probe_timeout_ms
                .value()
                .try_into()
                .unwrap_or(u64::MAX),
        )
    }

    pub(crate) fn dns_upstream_refresh_interval(&self) -> Duration {
        Duration::from_secs(
            self.dns_upstream_refresh_seconds
                .value()
                .try_into()
                .unwrap_or(u64::MAX),
        )
    }
}

#[derive(Clone, Debug)]
pub(crate) struct EffectiveResidentUsize {
    value: usize,
    source: EffectiveResidentValueSource,
    config_key: &'static str,
    env: Option<&'static str>,
    compatibility_env: Option<&'static str>,
    default: usize,
    min: usize,
    max: usize,
}

impl EffectiveResidentUsize {
    pub(crate) fn value(&self) -> usize {
        self.value
    }

    fn json(&self) -> Value {
        json!({
            "value": self.value,
            "source": self.source.as_str(),
            "configKey": self.config_key,
            "env": self.env,
            "compatibilityEnv": self.compatibility_env,
            "default": self.default,
            "min": self.min,
            "max": self.max,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EffectiveResidentValueSource {
    Default,
    Config,
    Env,
    CompatibilityEnv,
}

impl EffectiveResidentValueSource {
    fn as_str(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::Config => "config",
            Self::Env => "env",
            Self::CompatibilityEnv => "compatibility-env",
        }
    }
}

fn effective_resident_usize(
    config_key: &'static str,
    env: Option<&'static str>,
    compatibility_env: Option<&'static str>,
    configured: Option<u64>,
    default: usize,
    min: usize,
    max: usize,
) -> EffectiveResidentUsize {
    let (value, source) = env
        .and_then(read_env_usize)
        .map(|value| (value, EffectiveResidentValueSource::Env))
        .or_else(|| {
            compatibility_env
                .and_then(read_env_usize)
                .map(|value| (value, EffectiveResidentValueSource::CompatibilityEnv))
        })
        .or_else(|| configured.map(|value| (value as usize, EffectiveResidentValueSource::Config)))
        .unwrap_or((default, EffectiveResidentValueSource::Default));
    EffectiveResidentUsize {
        value: value.clamp(min, max),
        source,
        config_key,
        env,
        compatibility_env,
        default,
        min,
        max,
    }
}

fn read_env_usize(name: &'static str) -> Option<usize> {
    std::env::var(name)
        .ok()
        .and_then(|value| value.trim().parse::<usize>().ok())
}
