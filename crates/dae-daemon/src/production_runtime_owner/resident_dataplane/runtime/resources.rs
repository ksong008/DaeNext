use super::*;

#[derive(Clone, Debug)]
pub(crate) struct ResidentRuntimeResourceConfig {
    pub(crate) tcp_flow_stack_bytes: EffectiveResidentUsize,
    pub(crate) udp_session_limit: EffectiveResidentUsize,
    pub(crate) udp_session_queue_depth: EffectiveResidentUsize,
    pub(crate) event_queue_depth: EffectiveResidentUsize,
    pub(crate) manual_probe_concurrency: EffectiveResidentUsize,
    pub(crate) health_check_concurrency: EffectiveResidentUsize,
}

impl ResidentRuntimeResourceConfig {
    pub(crate) fn from_config(config: &Config) -> Self {
        let global = &config.global;
        Self {
            tcp_flow_stack_bytes: effective_resident_usize(
                "resident_tcp_flow_stack_bytes",
                Some(RESIDENT_TCP_FLOW_STACK_BYTES_ENV),
                Some(RESIDENT_TCP_FLOW_STACK_BYTES_LEGACY_ENV),
                global.resident_tcp_flow_stack_bytes,
                RESIDENT_TCP_FLOW_STACK_BYTES_DEFAULT,
                RESIDENT_TCP_FLOW_STACK_BYTES_MIN,
                RESIDENT_TCP_FLOW_STACK_BYTES_MAX,
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
                RESIDENT_MANUAL_LATENCY_PROBE_CONCURRENCY_DEFAULT,
                RESIDENT_MANUAL_LATENCY_PROBE_CONCURRENCY_MIN,
                RESIDENT_MANUAL_LATENCY_PROBE_CONCURRENCY_MAX,
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
            },
            "udpSessions": {
                "limit": self.udp_session_limit.json(),
                "queueDepth": self.udp_session_queue_depth.json(),
            },
            "eventWriter": {
                "queueDepth": self.event_queue_depth.json(),
                "filePersistence": "disabled",
            },
            "manualProbe": {
                "concurrency": self.manual_probe_concurrency.json(),
            },
            "healthCheck": {
                "concurrency": self.health_check_concurrency.json(),
            },
        })
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
