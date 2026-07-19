use super::*;

#[derive(Clone, Debug)]
pub(crate) struct ResidentRuntimeResourceConfig {
    pub(crate) runtime_profile: ResidentRuntimeProfileSelection,
    pub(crate) tcp_flow_stack_bytes: EffectiveResidentUsize,
    pub(crate) tcp_runtime_workers: EffectiveResidentUsize,
    pub(crate) tcp_connection_limit: EffectiveResidentUsize,
    pub(crate) udp_session_limit: EffectiveResidentUsize,
    pub(crate) udp_session_queue_depth: EffectiveResidentUsize,
    pub(crate) udp_runtime_shards: EffectiveResidentUsize,
    pub(crate) udp_dispatch_queue_depth: EffectiveResidentUsize,
    pub(crate) udp_socket_buffer_bytes: EffectiveResidentUsize,
    pub(crate) dns_fast_path_concurrency: EffectiveResidentUsize,
    pub(crate) dns_fast_path_queue_depth: EffectiveResidentUsize,
    pub(crate) dns_udp_forwarder_queue_depth: EffectiveResidentUsize,
    pub(crate) dns_udp_forwarder_pending_limit: EffectiveResidentUsize,
    pub(crate) dns_udp_forwarder_attempts: EffectiveResidentUsize,
    pub(crate) dns_proxy_udp_actors: EffectiveResidentUsize,
    pub(crate) dns_upstream_refresh_seconds: EffectiveResidentUsize,
    pub(crate) event_queue_depth: EffectiveResidentUsize,
    pub(crate) manual_probe_concurrency: EffectiveResidentUsize,
    pub(crate) tcp_probe_timeout_ms: EffectiveResidentUsize,
    pub(crate) health_check_concurrency: EffectiveResidentUsize,
}

impl ResidentRuntimeResourceConfig {
    pub(crate) fn from_config(config: &Config) -> Self {
        let global = &config.global;
        let runtime_profile = ResidentRuntimeProfileSelection::selected();
        let available_parallelism = std::thread::available_parallelism()
            .map(|parallelism| parallelism.get())
            .unwrap_or(1);
        let tcp_runtime_workers_default = runtime_profile
            .profile
            .tcp_runtime_workers_default(available_parallelism);
        let tcp_connection_limit_default = runtime_profile.profile.tcp_connection_limit_default();
        let udp_session_limit_default = runtime_profile.profile.udp_session_limit_default();
        let udp_session_queue_depth_default =
            runtime_profile.profile.udp_session_queue_depth_default();
        let udp_runtime_shards_default = runtime_profile
            .profile
            .udp_runtime_shards_default(available_parallelism);
        let udp_dispatch_queue_depth_default =
            runtime_profile.profile.udp_dispatch_queue_depth_default();
        let dns_fast_path_concurrency_default =
            runtime_profile.profile.dns_fast_path_concurrency_default();
        let dns_fast_path_queue_depth_default =
            runtime_profile.profile.dns_fast_path_queue_depth_default();
        let dns_udp_forwarder_queue_depth_default = runtime_profile
            .profile
            .dns_udp_forwarder_queue_depth_default();
        let dns_udp_forwarder_pending_limit_default = runtime_profile
            .profile
            .dns_udp_forwarder_pending_limit_default();
        let dns_udp_forwarder_attempts_default =
            runtime_profile.profile.dns_udp_forwarder_attempts_default();
        let dns_proxy_udp_actors_default = runtime_profile.profile.dns_proxy_udp_actors_default();
        Self {
            runtime_profile,
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
                udp_session_limit_default,
                RESIDENT_UDP_SESSION_LIMIT_MIN,
                RESIDENT_UDP_SESSION_LIMIT_MAX,
            ),
            udp_session_queue_depth: effective_resident_usize(
                "resident_udp_session_queue_depth",
                Some(RESIDENT_UDP_SESSION_QUEUE_DEPTH_ENV),
                None,
                global.resident_udp_session_queue_depth,
                udp_session_queue_depth_default,
                RESIDENT_UDP_SESSION_QUEUE_DEPTH_MIN,
                RESIDENT_UDP_SESSION_QUEUE_DEPTH_MAX,
            ),
            udp_runtime_shards: effective_resident_usize(
                "resident_udp_runtime_shards",
                Some(RESIDENT_UDP_RUNTIME_SHARDS_ENV),
                None,
                None,
                udp_runtime_shards_default,
                RESIDENT_UDP_RUNTIME_SHARDS_MIN,
                RESIDENT_UDP_RUNTIME_SHARDS_MAX,
            ),
            udp_dispatch_queue_depth: effective_resident_usize(
                "resident_udp_dispatch_queue_depth",
                Some(RESIDENT_UDP_DISPATCH_QUEUE_DEPTH_ENV),
                None,
                None,
                udp_dispatch_queue_depth_default,
                RESIDENT_UDP_DISPATCH_QUEUE_DEPTH_MIN,
                RESIDENT_UDP_DISPATCH_QUEUE_DEPTH_MAX,
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
                dns_fast_path_concurrency_default,
                RESIDENT_DNS_FAST_PATH_CONCURRENCY_MIN,
                RESIDENT_DNS_FAST_PATH_CONCURRENCY_MAX,
            ),
            dns_fast_path_queue_depth: effective_resident_usize(
                "resident_dns_fast_path_queue_depth",
                Some(RESIDENT_DNS_FAST_PATH_QUEUE_DEPTH_ENV),
                None,
                None,
                dns_fast_path_queue_depth_default,
                RESIDENT_DNS_FAST_PATH_QUEUE_DEPTH_MIN,
                RESIDENT_DNS_FAST_PATH_QUEUE_DEPTH_MAX,
            ),
            dns_udp_forwarder_queue_depth: effective_resident_usize(
                "resident_dns_udp_forwarder_queue_depth",
                Some(RESIDENT_DNS_UDP_FORWARDER_QUEUE_DEPTH_ENV),
                None,
                None,
                dns_udp_forwarder_queue_depth_default,
                RESIDENT_DNS_UDP_FORWARDER_QUEUE_DEPTH_MIN,
                RESIDENT_DNS_UDP_FORWARDER_QUEUE_DEPTH_MAX,
            ),
            dns_udp_forwarder_pending_limit: effective_resident_usize(
                "resident_dns_udp_forwarder_pending_limit",
                Some(RESIDENT_DNS_UDP_FORWARDER_PENDING_LIMIT_ENV),
                None,
                None,
                dns_udp_forwarder_pending_limit_default,
                RESIDENT_DNS_UDP_FORWARDER_PENDING_LIMIT_MIN,
                RESIDENT_DNS_UDP_FORWARDER_PENDING_LIMIT_MAX,
            ),
            dns_udp_forwarder_attempts: effective_resident_usize(
                "resident_dns_udp_forwarder_attempts",
                Some(RESIDENT_DNS_UDP_FORWARDER_ATTEMPTS_ENV),
                None,
                None,
                dns_udp_forwarder_attempts_default,
                RESIDENT_DNS_UDP_FORWARDER_ATTEMPTS_MIN,
                RESIDENT_DNS_UDP_FORWARDER_ATTEMPTS_MAX,
            ),
            dns_proxy_udp_actors: effective_resident_usize(
                "resident_dns_proxy_udp_actors",
                Some(RESIDENT_DNS_PROXY_UDP_ACTORS_ENV),
                None,
                None,
                dns_proxy_udp_actors_default,
                RESIDENT_DNS_PROXY_UDP_ACTORS_MIN,
                RESIDENT_DNS_PROXY_UDP_ACTORS_MAX,
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
        let quic_udp =
            QuicUdpDatagramResourceProfile::from_runtime_profile(self.runtime_profile.profile);
        let hysteria2 =
            Hysteria2OwnerResourceProfile::from_runtime_profile(self.runtime_profile.profile);
        let anytls = AnyTlsOwnerResourceProfile::from_runtime_profile(self.runtime_profile.profile);
        let h2_carriers =
            H2CarrierOwnerResourceProfile::from_runtime_profile(self.runtime_profile.profile);
        let meek = MeekTransportResourceProfile::from_runtime_profile(self.runtime_profile.profile);
        json!({
            "runtimeProfile": self.runtime_profile.json(),
            "schemaVersion": 1,
            "tcpFlow": {
                "stackBytes": self.tcp_flow_stack_bytes.json(),
                "stackScope": "resident TCP runtime OS threads; Tokio tasks do not receive per-flow stacks",
            },
            "tcpRuntime": {
                "profileSource": "runtimeProfile",
                "workers": self.tcp_runtime_workers.json(),
                "connectionLimit": self.tcp_connection_limit.json(),
                "admission": "active-flow semaphore before accept; excess connections remain in the kernel listen backlog",
            },
            "udpSessions": {
                "limit": self.udp_session_limit.json(),
                "queueDepth": self.udp_session_queue_depth.json(),
                "runtimeShards": self.udp_runtime_shards.json(),
                "dispatchQueueDepth": self.udp_dispatch_queue_depth.json(),
                "socketBufferBytes": self.udp_socket_buffer_bytes.json(),
            },
            "quicEndpoints": {
                "profileSource": "runtimeProfile",
                "limit": self.runtime_profile.profile.quic_endpoint_limit_default(),
                "chargedBytes": self.runtime_profile.profile.quic_endpoint_charged_bytes_default(),
                "scope": "process-wide connecting, ready, failed and draining Quinn Endpoint owners",
            },
            "quicUdpDatagrams": {
                "profileSource": "runtimeProfile",
                "pendingFragmentPackets": quic_udp.pending_fragment_packets(),
                "pendingFragmentBytes": quic_udp.pending_fragment_bytes(),
                "packetIdLeases": quic_udp.packet_id_leases(),
                "pmtuRetries": quic_udp.pmtu_retries(),
                "fragmentTtlMs": quic_udp.fragment_ttl().as_millis(),
                "packetIdLeaseTtlMs": quic_udp.packet_id_lease_ttl().as_millis(),
                "fragmentQuarantineTtlMs": quic_udp.fragment_quarantine_ttl().as_millis(),
                "scope": "per logical QUIC UDP session; count and bytes are enforced independently",
            },
            "hysteria2Owners": {
                "profileSource": "runtimeProfile",
                "ownerLimit": hysteria2.owner_limit(),
                "commandQueueDepth": hysteria2.command_queue_depth(),
                "logicalLeaseLimit": hysteria2.logical_lease_limit(),
                "udpSessionLimit": hysteria2.udp_session_limit(),
                "udpSessionQueueDepth": hysteria2.udp_session_queue_depth(),
                "udpSessionQueueBytes": hysteria2.udp_session_queue_bytes(),
                "udpOwnerQueueBytes": hysteria2.udp_owner_queue_bytes(),
                "udpSessionQuarantineLimit": hysteria2.udp_session_quarantine_limit(),
                "udpSessionQuarantineTtlMs": hysteria2.udp_session_quarantine_ttl().as_millis(),
                "retryCooldownMs": hysteria2.retry_cooldown().as_millis(),
                "portHopResolvedCandidateLimit": hysteria2.port_hop_resolved_candidate_limit(),
                "portHopTransitionSocketLimit": hysteria2.port_hop_transition_socket_limit(),
                "scope": "one generation and normalized node identity per shared Hysteria2 QUIC and H3 owner",
            },
            "anytlsOwners": {
                "profileSource": "runtimeProfile",
                "ownerLimit": anytls.owner_limit(),
                "physicalSessionLimit": anytls.physical_session_limit(),
                "physicalSessionsPerOwner": anytls.physical_sessions_per_owner(),
                "commandQueueDepth": anytls.command_queue_depth(),
                "physicalControlQueueDepth": anytls.physical_control_queue_depth(),
                "logicalBufferBytesPerDirection": anytls.logical_buffer_bytes(),
                "idleSessionsPerOwner": anytls.idle_session_limit(),
                "idleSessionTimeoutMs": anytls.idle_session_timeout().as_millis(),
                "idleProbeThresholdMs": anytls.idle_probe_threshold().as_millis(),
                "idleProbeTimeoutMs": anytls.idle_probe_timeout().as_millis(),
                "sidQuarantineLimit": anytls.sid_quarantine_limit(),
                "sidQuarantineTtlMs": anytls.sid_quarantine_ttl().as_millis(),
                "scope": "one generation and complete AnyTLS physical-session identity; one active logical SID per physical session",
            },
            "h2CarrierOwners": {
                "profileSource": "runtimeProfile",
                "ownerLimit": h2_carriers.owner_limit(),
                "physicalConnectionLimit": h2_carriers.physical_connection_limit(),
                "reusablePhysicalConnectionsPerOwner": 1,
                "drainingConnectionsCountTowardPhysicalBudget": true,
                "runtimeWorkerThreads": self.tcp_runtime_workers.json(),
                "scope": "one generation and complete TLS HTTP/2 carrier identity; server SETTINGS controls logical stream concurrency",
            },
            "meekTransportOwners": {
                "profileSource": "runtimeProfile",
                "ownerLimit": meek.owner_limit(),
                "physicalConnectionLimit": meek.physical_connection_limit(),
                "physicalConnectionsPerOwner": meek.physical_connections_per_owner(),
                "idleConnectionsPerOwner": meek.idle_connection_limit(),
                "idleConnectionTimeoutMs": meek.idle_connection_timeout().as_millis(),
                "requestBodyBytes": dae_outbound::shared_transport::contract::MEEK_MAX_WRITE,
                "responseHeaderBytes": meek.response_header_bytes(),
                "responseBodyBytes": meek.response_body_bytes(),
                "responseWireBytes": meek.response_wire_bytes(),
                "runtimeWorkerThreads": self.tcp_runtime_workers.json(),
                "scope": "one generation and complete TLS HTTP/1.1 Meek transport identity; logical sessions remain independent",
            },
            "dnsFastPath": {
                "concurrency": self.dns_fast_path_concurrency.json(),
                "queueDepth": self.dns_fast_path_queue_depth.json(),
            },
            "dnsUdpForwarder": {
                "queueDepth": self.dns_udp_forwarder_queue_depth.json(),
                "pendingLimit": self.dns_udp_forwarder_pending_limit.json(),
                "attempts": self.dns_udp_forwarder_attempts.json(),
                "proxyActors": self.dns_proxy_udp_actors.json(),
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
