use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use dae_config::{Config, DynamicFunctionValue, Function, Group, Param};
use dae_core_types::OutboundIndex;
use dae_datapath::TcpDialMode;
use dae_outbound::{
    Annotation, AnyTLSLink, Dialer, DialerGroup, DialerSet, Filter, FilterParam, NetworkType,
    SelectionPolicy,
    http_proxy::{HttpProxyLink, HttpScheme},
    hysteria2::{
        DEFAULT_TRUE_QUIC_UDP_HOP_INTERVAL_MS, Hysteria2Link, build_port_hop_schedule,
        server_contract as hysteria2_server_contract,
    },
    juicity::JuicityLink,
    parse_link_chain,
    shadowsocks::ss2022::{cipher_conf, validate_psk_list},
    shadowsocks::{CipherFamily, classify_cipher},
    shadowsocks::{ShadowsocksLink, cipher_spec},
    shared_transport::{MeekRoundTripOptions, UtlsFingerprint, ir, resolve_utls_client_hello_id},
    trojan::{TrojanLink, TrojanTransportType},
    tuic::TuicLink,
    vless::{VLESSLink, password_to_key},
    vmess::VMessLink,
};
use serde_json::{Value, json};
use url::Url;

use super::{
    XTLS_RPRX_VISION,
    dns::{ResidentDnsPlan, build_resident_dns_plan},
    link_hash, redacted_link_source,
};

#[derive(Clone, Debug, Eq, PartialEq)]
struct SelectedGroupNode {
    match_index: usize,
    tag: String,
    link: String,
    annotation_add_latency_ms: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ResidentNodeLinkShape {
    pub(super) tag: String,
    pub(super) scheme: String,
    pub(super) link: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ResidentUtlsFingerprintPlan {
    pub(super) source: &'static str,
    pub(super) requested: String,
    pub(super) name: String,
    pub(super) canonical: String,
    pub(super) family: String,
    pub(super) client: String,
    pub(super) randomized: bool,
    pub(super) alpn_policy: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum GroupNodeSelection {
    Selected(Vec<SelectedGroupNode>),
    NoCandidate {
        explicit_name_filter: bool,
        unresolved_names: Vec<String>,
    },
}

#[derive(Clone, Debug)]
pub(super) enum ResidentProxyProtocolPlan {
    VlessVisionTcpTls {
        key: [u8; 16],
    },
    Socks5Tcp {
        username: String,
        password: String,
    },
    HttpProxyTcp {
        username: String,
        password: String,
        transport: bool,
        transport_host: String,
        transport_path: String,
    },
    ShadowsocksAeadTcp {
        cipher: String,
        password: String,
        salt_len: usize,
    },
    Shadowsocks2022Tcp {
        cipher: String,
        password: String,
        salt_len: usize,
        packet_nonce_len: usize,
    },
    ShadowsocksSimpleObfsHttpTcp {
        cipher: String,
        password: String,
        salt_len: usize,
        host: String,
        path: String,
    },
    ShadowsocksSimpleObfsTlsTcp {
        cipher: String,
        password: String,
        salt_len: usize,
        host: String,
    },
    ShadowsocksV2rayPluginTlsWsTcp {
        cipher: String,
        password: String,
        salt_len: usize,
        host: String,
        path: String,
    },
    Shadowsocks2022SimpleObfsHttpTcp {
        cipher: String,
        password: String,
        salt_len: usize,
        host: String,
        path: String,
    },
    TrojanTcpTls {
        password: String,
    },
    TrojanInnerShadowsocksTcpTls {
        password: String,
        inner_cipher: String,
        inner_password: String,
    },
    AnyTlsTcpTls {
        auth: String,
    },
    VmessAeadTcp {
        id: String,
    },
    Hysteria2QuicTcp {
        auth: String,
        pin_sha256: String,
        max_rx: u64,
        port_hop_ports: Vec<u16>,
    },
    TuicQuicTcp {
        uuid: String,
        password: String,
        alpn: Vec<String>,
        allow_insecure: bool,
    },
    JuicityQuicTcp {
        uuid: String,
        password: String,
        allow_insecure: bool,
        pinned_certchain_sha256: String,
    },
}

#[derive(Clone, Debug)]
pub(super) struct ResidentProxyPlan {
    pub(super) graph_id: String,
    pub(super) graph_link_hash: String,
    pub(super) redacted_link_source: String,
    pub(super) protocol: String,
    pub(super) group_name: String,
    pub(super) group_policy: String,
    pub(super) node_tag: String,
    pub(super) server_host: String,
    pub(super) server_port: u16,
    pub(super) server_name: String,
    pub(super) alpn: Vec<String>,
    pub(super) flow: String,
    pub(super) net: String,
    pub(super) stream_host: String,
    pub(super) stream_path: String,
    pub(super) tls: String,
    pub(super) allow_insecure: bool,
    pub(super) utls_fingerprint: Option<ResidentUtlsFingerprintPlan>,
    pub(super) handler: ResidentProxyProtocolPlan,
    pub(super) chain_parent: Option<Box<ResidentProxyPlan>>,
    pub(super) mark: u32,
    pub(super) mptcp: bool,
}

impl ResidentProxyPlan {
    pub(super) fn executable_graph_descriptor(&self) -> ResidentExecutableGraphDescriptor {
        ResidentExecutableGraphDescriptor::from_proxy(self)
    }

    pub(super) fn executable_graph_value(&self) -> Value {
        self.executable_graph_descriptor().to_value()
    }

    pub(super) fn executable_graph_value_for_reload_generation(
        &self,
        reload_generation: u64,
    ) -> Value {
        self.executable_graph_descriptor()
            .to_value_for_reload_generation(reload_generation)
    }

    pub(super) fn runtime_component_evidence_value(&self) -> Value {
        self.executable_graph_descriptor()
            .runtime_component_evidence_value()
    }

    pub(super) fn runtime_component_evidence_value_for_reload_generation(
        &self,
        reload_generation: u64,
    ) -> Value {
        self.executable_graph_descriptor()
            .runtime_component_evidence_value_for_reload_generation(reload_generation)
    }

    pub(super) fn vless_key(&self) -> Result<[u8; 16], String> {
        match self.handler {
            ResidentProxyProtocolPlan::VlessVisionTcpTls { key } => Ok(key),
            _ => Err(format!(
                "resident proxy {} node {} is not a VLESS handler",
                self.protocol, self.node_tag
            )),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ResidentExecutableGraphDescriptor {
    graph_id: String,
    link_hash: String,
    redacted_link_source: String,
    protocol_framing: String,
    endpoint_host_hash: String,
    endpoint_port: u16,
    transport_underlay: String,
    security_underlay: String,
    stream_wrapper: String,
    stream_host_hash: Option<String>,
    stream_path: String,
    packet_semantics: String,
    flow: String,
    alpn: Vec<String>,
    allow_insecure: bool,
    utls_fingerprint: Option<ResidentUtlsFingerprintPlan>,
    chain_parent_count: usize,
    mark: u32,
    mptcp: bool,
}

impl ResidentExecutableGraphDescriptor {
    fn from_proxy(proxy: &ResidentProxyPlan) -> Self {
        Self {
            graph_id: proxy.graph_id.clone(),
            link_hash: proxy.graph_link_hash.clone(),
            redacted_link_source: proxy.redacted_link_source.clone(),
            protocol_framing: proxy.protocol.clone(),
            endpoint_host_hash: link_hash(&proxy.server_host),
            endpoint_port: proxy.server_port,
            transport_underlay: graph_transport_underlay(proxy),
            security_underlay: graph_security_underlay(proxy),
            stream_wrapper: graph_stream_wrapper(proxy),
            stream_host_hash: if proxy.stream_host.is_empty() {
                None
            } else {
                Some(link_hash(&proxy.stream_host))
            },
            stream_path: proxy.stream_path.clone(),
            packet_semantics: graph_packet_semantics(proxy),
            flow: proxy.flow.clone(),
            alpn: proxy.alpn.clone(),
            allow_insecure: proxy.allow_insecure,
            utls_fingerprint: proxy.utls_fingerprint.clone(),
            chain_parent_count: usize::from(proxy.chain_parent.is_some()),
            mark: proxy.mark,
            mptcp: proxy.mptcp,
        }
    }

    pub(super) fn to_value(&self) -> Value {
        self.to_value_with_reload_generation(None)
    }

    pub(super) fn to_value_for_reload_generation(&self, reload_generation: u64) -> Value {
        self.to_value_with_reload_generation(Some(reload_generation))
    }

    fn to_value_with_reload_generation(&self, reload_generation: Option<u64>) -> Value {
        let underlay_factory = self.underlay_factory_value();
        let stream_wrapper_factory = self.stream_wrapper_factory_value();
        let chain_executor = self.chain_executor_value();
        let generation_cache = self.generation_cache_value(reload_generation);
        let packet_session_manager = self.packet_session_manager_value();
        let probe_executor = self.probe_executor_value(reload_generation);
        json!({
            "schemaVersion": 1,
            "graphId": self.graph_id,
            "linkIdentity": {
                "schemaVersion": 1,
                "linkHash": self.link_hash,
                "redactedSource": self.redacted_link_source,
            },
            "endpoint": {
                "hostHash": self.endpoint_host_hash,
                "port": self.endpoint_port,
            },
            "transportUnderlay": self.transport_underlay,
            "securityUnderlay": self.security_underlay,
            "streamWrapper": self.stream_wrapper,
            "streamWrapperEndpoint": {
                "hostHash": self.stream_host_hash,
                "path": self.stream_path,
            },
            "protocolFraming": self.protocol_framing,
            "packetSemantics": self.packet_semantics,
            "chain": {
                "mode": if self.chain_parent_count > 0 { "parent-proxy" } else { "none" },
                "parentCount": self.chain_parent_count,
                "flattened": false,
            },
            "routing": {
                "mark": self.mark,
                "mptcp": self.mptcp,
            },
            "admission": {
                "status": "admitted",
                "source": "resident-plan",
                "unsupportedReason": Value::Null,
            },
            "runtimeComponents": {
                "underlayFactory": underlay_factory,
                "streamWrapperFactory": stream_wrapper_factory,
                "chainExecutor": chain_executor,
                "generationCache": generation_cache,
                "packetSessionManager": packet_session_manager,
                "probeExecutor": probe_executor,
            },
            "evidenceState": "compiled-resident-graph",
        })
    }

    pub(super) fn runtime_component_evidence_value(&self) -> Value {
        self.runtime_component_evidence_value_with_reload_generation(None)
    }

    pub(super) fn runtime_component_evidence_value_for_reload_generation(
        &self,
        reload_generation: u64,
    ) -> Value {
        self.runtime_component_evidence_value_with_reload_generation(Some(reload_generation))
    }

    fn runtime_component_evidence_value_with_reload_generation(
        &self,
        reload_generation: Option<u64>,
    ) -> Value {
        json!({
            "schemaVersion": 1,
            "graphId": self.graph_id,
            "underlayFactory": self.underlay_factory_value(),
            "streamWrapperFactory": self.stream_wrapper_factory_value(),
            "chainExecutor": self.chain_executor_value(),
            "generationCache": self.generation_cache_value(reload_generation),
            "packetSessionManager": self.packet_session_manager_value(),
            "probeExecutor": self.probe_executor_value(reload_generation),
        })
    }

    fn underlay_factory_value(&self) -> Value {
        let fingerprint = self.utls_fingerprint.as_ref().map(|fingerprint| {
            json!({
                "source": fingerprint.source,
                "requested": &fingerprint.requested,
                "canonical": &fingerprint.canonical,
                "family": &fingerprint.family,
                "client": &fingerprint.client,
                "randomized": fingerprint.randomized,
                "alpnPolicy": &fingerprint.alpn_policy,
            })
        });
        let provider = match self.security_underlay.as_str() {
            "fingerprint-aware-tls" => "boringssl",
            "standard-tls" => "rustls",
            "quic-tls" => "quinn-rustls",
            "aead" => "protocol-aead-codec",
            "aead-2022" => "protocol-aead-2022-codec",
            "none" => "plain",
            _ => "unsupported",
        };
        let status = if provider == "unsupported" {
            "fail-closed"
        } else {
            "admitted"
        };
        let unsupported_reason = if provider == "unsupported" {
            json!("security underlay is not backed by a resident runtime factory")
        } else {
            Value::Null
        };
        json!({
            "schemaVersion": 1,
            "status": status,
            "provider": provider,
            "transportUnderlay": self.transport_underlay,
            "securityUnderlay": self.security_underlay,
            "verificationPolicy": if self.allow_insecure { "explicit-insecure" } else { "system-roots" },
            "allowInsecure": self.allow_insecure,
            "alpn": self.alpn,
            "flow": self.flow,
            "fingerprint": fingerprint,
            "unsupportedReason": unsupported_reason,
        })
    }

    fn stream_wrapper_factory_value(&self) -> Value {
        let (status, provider, unsupported_reason) = match self.stream_wrapper.as_str() {
            "none" => ("admitted", "none", Value::Null),
            "frame-stream" => ("admitted", "resident-frame-stream", Value::Null),
            "quic-stream" => ("admitted", "resident-quic-stream", Value::Null),
            "packet-stream" => ("admitted", "resident-packet-stream", Value::Null),
            "websocket" => ("admitted", "resident-websocket-binary-frame", Value::Null),
            "httpupgrade" => ("admitted", "resident-http-upgrade-stream", Value::Null),
            "grpc" => ("admitted", "resident-grpc-h2-stream", Value::Null),
            "meek" => ("admitted", "resident-meek-polling", Value::Null),
            "xhttp" => ("admitted", "resident-xhttp-h2-packet-up", Value::Null),
            "simple-obfs-http" => ("admitted", "resident-simple-obfs-http", Value::Null),
            "simple-obfs-tls" => ("admitted", "resident-simple-obfs-tls", Value::Null),
            "v2ray-plugin-tls-websocket" => (
                "admitted",
                "resident-v2ray-plugin-tls-websocket",
                Value::Null,
            ),
            _ => (
                "fail-closed",
                "unsupported",
                json!("stream wrapper is not backed by a resident runtime factory"),
            ),
        };
        json!({
            "schemaVersion": 1,
            "status": status,
            "wrapper": self.stream_wrapper,
            "provider": provider,
            "endpoint": {
                "hostHash": self.stream_host_hash,
                "path": self.stream_path,
            },
            "protocolFraming": self.protocol_framing,
            "unsupportedReason": unsupported_reason,
        })
    }

    fn chain_executor_value(&self) -> Value {
        let (mode, executor) = if self.chain_parent_count > 0 {
            ("parent-proxy", "resident-parent-connect-chain")
        } else {
            ("none", "single-resident-graph")
        };
        json!({
            "schemaVersion": 1,
            "status": "admitted",
            "mode": mode,
            "parentCount": self.chain_parent_count,
            "flattened": false,
            "executor": executor,
            "unsupportedReason": Value::Null,
        })
    }

    fn generation_cache_value(&self, reload_generation: Option<u64>) -> Value {
        json!({
            "schemaVersion": 1,
            "graphId": self.graph_id,
            "reloadGeneration": reload_generation,
            "materialized": reload_generation.is_some(),
            "generationSource": if reload_generation.is_some() { "resident-runtime" } else { "resident-plan" },
            "owner": "resident-dataplane-runtime",
            "cacheScope": "graph-and-reload-generation",
            "survivesReload": false,
            "cleanupPolicy": "drop-on-graph-diff-or-runtime-stop",
            "sharedProviderCaches": [
                "tls-client-config",
                "fingerprint-aware-tls-connector",
                "quic-client-config"
            ],
        })
    }

    fn packet_session_manager_value(&self) -> Value {
        json!({
            "schemaVersion": 1,
            "status": "admitted",
            "manager": "bounded-resident-packet-session",
            "graphId": self.graph_id,
            "packetSemantics": self.packet_semantics,
            "keyFields": [
                "graphId",
                "outbound",
                "peer",
                "originalDestination",
                "packetSemantics"
            ],
            "limitSource": "resident-udp-packet-worker-limit",
            "transientExchangeCompatible": true,
        })
    }

    fn probe_executor_value(&self, reload_generation: Option<u64>) -> Value {
        json!({
            "schemaVersion": 1,
            "status": "admitted",
            "executor": "resident-executable-graph",
            "graphId": self.graph_id,
            "reloadGeneration": reload_generation,
            "materialized": reload_generation.is_some(),
            "sharesTrafficExecutor": true,
            "latencyState": "group-selector",
            "unsupportedReason": Value::Null,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ResidentGraphIdentity {
    graph_id: String,
    link_hash: String,
    redacted_link_source: String,
}

fn resident_graph_identity(link: &str) -> ResidentGraphIdentity {
    let link_hash = link_hash(link);
    let graph_hash = link_hash.trim_start_matches("sha256:");
    ResidentGraphIdentity {
        graph_id: format!("resident-graph:{}", &graph_hash[..16.min(graph_hash.len())]),
        redacted_link_source: redacted_link_source(link),
        link_hash,
    }
}

fn graph_transport_underlay(proxy: &ResidentProxyPlan) -> String {
    match proxy.tls.as_str() {
        "quic" => "quic".to_owned(),
        _ => "tcp".to_owned(),
    }
}

fn graph_security_underlay(proxy: &ResidentProxyPlan) -> String {
    if proxy.utls_fingerprint.is_some() {
        "fingerprint-aware-tls".to_owned()
    } else {
        match proxy.tls.as_str() {
            "" | "none" => "none".to_owned(),
            "aead" => "aead".to_owned(),
            "quic" => "quic-tls".to_owned(),
            "tls" => "standard-tls".to_owned(),
            other => other.to_owned(),
        }
    }
}

fn graph_stream_wrapper(proxy: &ResidentProxyPlan) -> String {
    match proxy.handler {
        ResidentProxyProtocolPlan::AnyTlsTcpTls { .. } => return "frame-stream".to_owned(),
        ResidentProxyProtocolPlan::Hysteria2QuicTcp { .. }
        | ResidentProxyProtocolPlan::TuicQuicTcp { .. }
        | ResidentProxyProtocolPlan::JuicityQuicTcp { .. } => return "quic-stream".to_owned(),
        _ => {}
    }
    match proxy.net.as_str() {
        "" | "tcp" | "udp" => "none".to_owned(),
        "grpc" => "grpc".to_owned(),
        "httpupgrade" => "httpupgrade".to_owned(),
        other => other.to_owned(),
    }
}

fn graph_packet_semantics(proxy: &ResidentProxyPlan) -> String {
    match proxy.handler {
        ResidentProxyProtocolPlan::Socks5Tcp { .. } => "udp-associate".to_owned(),
        ResidentProxyProtocolPlan::HttpProxyTcp { .. } => "protocol-closed".to_owned(),
        ResidentProxyProtocolPlan::VlessVisionTcpTls { .. } => "xudp".to_owned(),
        ResidentProxyProtocolPlan::ShadowsocksAeadTcp { .. } => "datagram-aead".to_owned(),
        ResidentProxyProtocolPlan::Shadowsocks2022Tcp { .. } => "datagram-aead-2022".to_owned(),
        ResidentProxyProtocolPlan::ShadowsocksSimpleObfsHttpTcp { .. }
        | ResidentProxyProtocolPlan::ShadowsocksSimpleObfsTlsTcp { .. }
        | ResidentProxyProtocolPlan::ShadowsocksV2rayPluginTlsWsTcp { .. }
        | ResidentProxyProtocolPlan::Shadowsocks2022SimpleObfsHttpTcp { .. } => {
            "plugin-wrapper-stream".to_owned()
        }
        ResidentProxyProtocolPlan::Hysteria2QuicTcp { .. }
        | ResidentProxyProtocolPlan::TuicQuicTcp { .. }
        | ResidentProxyProtocolPlan::JuicityQuicTcp { .. } => "quic-datagram-or-stream".to_owned(),
        _ => "udp-over-stream-or-datagram".to_owned(),
    }
}

fn canonical_resident_vless_net(net: &str) -> String {
    match net {
        "" | "tcp" => "tcp".to_owned(),
        "ws" | "websocket" => "websocket".to_owned(),
        "httpupgrade" => "httpupgrade".to_owned(),
        "grpc" => "grpc".to_owned(),
        "xhttp" => "xhttp".to_owned(),
        other => other.to_owned(),
    }
}

fn resident_stream_host(host: &str, server_name: &str) -> String {
    if host.is_empty() {
        server_name.to_owned()
    } else {
        host.to_owned()
    }
}

fn resident_stream_path(path: &str) -> String {
    if path.is_empty() {
        "/".to_owned()
    } else {
        path.to_owned()
    }
}

fn resident_csv_values(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect()
}

fn resident_xhttp_stream_path(path: &str) -> String {
    let normalized = ir::normalize_xhttp_path_and_query(path);
    if normalized.query.is_empty() {
        normalized.path
    } else {
        format!("{}?{}", normalized.path, normalized.query)
    }
}

fn resident_xhttp_extra_is_empty(extra: &str) -> bool {
    let extra = extra.trim();
    if extra.is_empty() {
        return true;
    }
    serde_json::from_str::<Value>(extra)
        .is_ok_and(|value| value.as_object().is_some_and(|object| object.is_empty()))
}

fn resident_grpc_service_name(service_name: &str) -> String {
    if service_name.is_empty() {
        "GunService".to_owned()
    } else {
        service_name.trim_start_matches('/').to_owned()
    }
}

#[derive(Clone, Debug)]
pub(super) struct ResidentProxyCandidatePlan {
    pub(super) match_index: usize,
    pub(super) annotation_add_latency_ms: i64,
    pub(super) link: String,
    pub(super) link_hash: String,
    pub(super) redacted_link_source: String,
    pub(super) proxy: ResidentProxyPlan,
}

#[derive(Clone, Debug)]
pub(super) struct ResidentProxyProbePlan {
    pub(super) node_tag: String,
    pub(super) link: String,
    pub(super) link_hash: String,
    pub(super) redacted_link_source: String,
    pub(super) tcp_check: ResidentTcpCheckPlan,
    pub(super) udp_check: ResidentUdpCheckPlan,
    pub(super) proxy: ResidentProxyPlan,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ResidentTcpCheckPlan {
    pub(super) scheme: String,
    pub(super) target: String,
    pub(super) host: String,
    pub(super) path: String,
    pub(super) method: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ResidentUdpCheckPlan {
    pub(super) target: SocketAddrV4,
    pub(super) host: String,
    pub(super) lookup_host: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ResidentProxyLatencySnapshot {
    pub(super) node_tag: String,
    pub(super) graph_id: String,
    pub(super) link_hash: String,
    pub(super) redacted_link_source: String,
    pub(super) latency_ms: Option<i64>,
    pub(super) alive: bool,
    pub(super) checked_at_unix: i64,
    pub(super) message: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum ResidentGroupPolicyPlan {
    Fixed { index: usize },
    Random,
    MinLastLatency,
    MinAverage10,
    MinMovingAverage,
}

impl ResidentGroupPolicyPlan {
    pub(super) fn as_str(&self) -> &'static str {
        match self {
            Self::Fixed { .. } => "fixed",
            Self::Random => "random",
            Self::MinLastLatency => "min",
            Self::MinAverage10 => "min_avg10",
            Self::MinMovingAverage => "min_moving_avg",
        }
    }

    pub(super) fn fixed_index(&self) -> Option<usize> {
        match self {
            Self::Fixed { index } => Some(*index),
            _ => None,
        }
    }

    pub(super) fn needs_latency_state(&self) -> bool {
        matches!(
            self,
            Self::MinLastLatency | Self::MinAverage10 | Self::MinMovingAverage
        )
    }

    pub(super) fn needs_alive_state(&self) -> bool {
        !matches!(self, Self::Fixed { .. })
    }
}

#[derive(Clone, Debug)]
pub(super) struct ResidentProxyGroupPlan {
    pub(super) group_name: String,
    pub(super) group_policy: ResidentGroupPolicyPlan,
    matched_candidate_count: usize,
    candidates: Vec<ResidentProxyCandidatePlan>,
    selector: Arc<Mutex<DialerGroup>>,
    check_interval: Duration,
    tcp_check: ResidentTcpCheckPlan,
    udp_check: ResidentUdpCheckPlan,
}

impl ResidentProxyGroupPlan {
    pub(super) fn group_policy_name(&self) -> &'static str {
        self.group_policy.as_str()
    }

    pub(super) fn candidate_count(&self) -> usize {
        self.matched_candidate_count
    }

    pub(super) fn admitted_candidate_count(&self) -> usize {
        self.candidates.len()
    }

    pub(super) fn annotation_latency_offset_count(&self) -> usize {
        self.candidates
            .iter()
            .filter(|candidate| candidate.annotation_add_latency_ms != 0)
            .count()
    }

    pub(super) fn latency_state_wired(&self) -> bool {
        if !self.group_policy.needs_latency_state() {
            return true;
        }
        self.selector
            .lock()
            .ok()
            .and_then(|selector| selector.alive_set(NetworkType::TCP4).cloned())
            .map(|alive_set| alive_set.latency_state_allocated)
            .unwrap_or(false)
    }

    pub(super) fn alive_state_wired(&self) -> bool {
        if !self.group_policy.needs_alive_state() {
            return true;
        }
        self.selector
            .lock()
            .map(|selector| selector.has_alive_state())
            .unwrap_or(false)
    }

    pub(super) fn default_proxy_snapshot(&self) -> Option<ResidentProxyPlan> {
        self.snapshot_candidate()
            .map(|candidate| candidate.proxy.clone())
    }

    pub(super) fn needs_background_checks(&self) -> bool {
        self.group_policy.needs_alive_state()
    }

    pub(super) fn check_interval(&self) -> Duration {
        self.check_interval
    }

    pub(super) fn probe_candidates(&self) -> Vec<ResidentProxyProbePlan> {
        self.candidates
            .iter()
            .map(|candidate| ResidentProxyProbePlan {
                node_tag: candidate.proxy.node_tag.clone(),
                link: candidate.link.clone(),
                link_hash: candidate.link_hash.clone(),
                redacted_link_source: candidate.redacted_link_source.clone(),
                tcp_check: self.tcp_check.clone(),
                udp_check: self.udp_check.clone(),
                proxy: candidate.proxy.clone(),
            })
            .collect()
    }

    pub(super) fn latency_snapshots(&self) -> Vec<ResidentProxyLatencySnapshot> {
        let Ok(selector) = self.selector.lock() else {
            return Vec::new();
        };
        self.candidates
            .iter()
            .enumerate()
            .map(|(index, candidate)| {
                let (latency_ms, alive, checked_at_unix, ok) = selector
                    .dialers
                    .get(index)
                    .map(|dialer| dialer.last_latency_snapshot(NetworkType::TCP4))
                    .unwrap_or((0, false, 0, false));
                ResidentProxyLatencySnapshot {
                    node_tag: candidate.proxy.node_tag.clone(),
                    graph_id: candidate.proxy.graph_id.clone(),
                    link_hash: candidate.link_hash.clone(),
                    redacted_link_source: candidate.redacted_link_source.clone(),
                    latency_ms: ok.then_some(latency_ms),
                    alive: ok && alive,
                    checked_at_unix,
                    message: resident_latency_message(ok, alive, latency_ms),
                }
            })
            .collect()
    }

    pub(super) fn select_proxy_for_tcp(&self) -> Result<ResidentProxyPlan, String> {
        self.select_proxy_for_network("tcp4")
    }

    pub(super) fn select_proxy_for_udp(&self) -> Result<ResidentProxyPlan, String> {
        self.select_proxy_for_network("udp4")
    }

    fn select_proxy_for_network(&self, network: &str) -> Result<ResidentProxyPlan, String> {
        self.select_candidate(network)
            .map(|candidate| candidate.proxy.clone())
    }

    fn snapshot_candidate(&self) -> Option<&ResidentProxyCandidatePlan> {
        match self.group_policy {
            ResidentGroupPolicyPlan::Fixed { index } => self
                .candidates
                .iter()
                .find(|candidate| candidate.match_index == index),
            ResidentGroupPolicyPlan::Random
            | ResidentGroupPolicyPlan::MinLastLatency
            | ResidentGroupPolicyPlan::MinAverage10
            | ResidentGroupPolicyPlan::MinMovingAverage => self.candidates.first(),
        }
    }

    fn select_candidate(&self, network: &str) -> Result<&ResidentProxyCandidatePlan, String> {
        if self.candidates.is_empty() {
            return Err(format!(
                "resident dataplane group {} has no admitted candidate for {network}",
                self.group_name
            ));
        }
        match self.group_policy {
            ResidentGroupPolicyPlan::Fixed { index } => self
                .candidates
                .iter()
                .find(|candidate| candidate.match_index == index)
                .ok_or_else(|| {
                    format!(
                        "resident dataplane group {} fixed policy index {} is not admitted for {network}",
                        self.group_name, index
                    )
                }),
            ResidentGroupPolicyPlan::MinLastLatency
            | ResidentGroupPolicyPlan::MinAverage10
            | ResidentGroupPolicyPlan::MinMovingAverage
            | ResidentGroupPolicyPlan::Random => {
                let network_type = resident_selector_network_type(network)?;
                let selected = self
                    .selector
                    .lock()
                    .map_err(|_| {
                        format!(
                            "resident dataplane group {} selector lock is poisoned",
                            self.group_name
                        )
                    })?
                    .select(network_type, false)
                    .map_err(|err| {
                        format!(
                            "resident dataplane group {} selector failed for {network}: {err}",
                            self.group_name
                        )
                    })?;
                self.candidates.get(selected.index).ok_or_else(|| {
                    format!(
                        "resident dataplane group {} selector returned missing candidate {} for {network}",
                        self.group_name, selected.index
                    )
                })
            }
        }
    }

    pub(super) fn record_check_result(
        &self,
        node_tag: &str,
        network_type: NetworkType,
        latency_ms: Option<i64>,
        checked_at_unix: i64,
    ) -> Result<(), String> {
        let Some(index) = self
            .candidates
            .iter()
            .position(|candidate| candidate.proxy.node_tag == node_tag)
        else {
            return Err(format!(
                "resident dataplane group {} has no admitted candidate named {node_tag}",
                self.group_name
            ));
        };
        self.selector
            .lock()
            .map_err(|_| {
                format!(
                    "resident dataplane group {} selector lock is poisoned",
                    self.group_name
                )
            })?
            .record_check_result(index, network_type, latency_ms, checked_at_unix);
        Ok(())
    }

    pub(super) fn record_check_result_for_link(
        &self,
        link: &str,
        network_type: NetworkType,
        latency_ms: Option<i64>,
        checked_at_unix: i64,
    ) -> Result<usize, String> {
        let indexes = self
            .candidates
            .iter()
            .enumerate()
            .filter_map(|(index, candidate)| (candidate.link == link).then_some(index))
            .collect::<Vec<_>>();
        if indexes.is_empty() {
            return Ok(0);
        }
        let mut selector = self.selector.lock().map_err(|_| {
            format!(
                "resident dataplane group {} selector lock is poisoned",
                self.group_name
            )
        })?;
        for index in &indexes {
            selector.record_check_result(*index, network_type, latency_ms, checked_at_unix);
        }
        Ok(indexes.len())
    }

    #[cfg(test)]
    pub(super) fn fixed_single_for_test(proxy: ResidentProxyPlan) -> Self {
        Self {
            group_name: proxy.group_name.clone(),
            group_policy: ResidentGroupPolicyPlan::Fixed { index: 0 },
            matched_candidate_count: 1,
            candidates: vec![ResidentProxyCandidatePlan {
                match_index: 0,
                annotation_add_latency_ms: 0,
                link: proxy.node_tag.clone(),
                link_hash: link_hash(&proxy.node_tag),
                redacted_link_source: redacted_link_source(&proxy.node_tag),
                proxy,
            }],
            selector: Arc::new(Mutex::new(DialerGroup::new(
                "test",
                vec![Dialer::new("test", "")],
                vec![Annotation::default()],
                SelectionPolicy::Fixed { index: 0 },
                true,
                0,
            ))),
            check_interval: Duration::from_secs(30),
            tcp_check: ResidentTcpCheckPlan {
                scheme: "http".to_owned(),
                target: "cp.cloudflare.com:80".to_owned(),
                host: "cp.cloudflare.com".to_owned(),
                path: "/".to_owned(),
                method: "HEAD".to_owned(),
            },
            udp_check: ResidentUdpCheckPlan {
                target: SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 53),
                host: "dns.google".to_owned(),
                lookup_host: "connectivitycheck.gstatic.com.".to_owned(),
            },
        }
    }
}

fn resident_latency_message(ok: bool, alive: bool, latency_ms: i64) -> String {
    if !ok {
        "no latency result".to_owned()
    } else if alive {
        format!("{latency_ms}ms")
    } else {
        "unavailable".to_owned()
    }
}

#[derive(Clone, Debug)]
pub(super) struct ResidentDataplanePlan {
    pub(super) enabled: bool,
    pub(super) unsupported_reason: Option<String>,
    pub(super) proxies: BTreeMap<u8, ResidentProxyGroupPlan>,
    pub(super) default_outbound: Option<u8>,
    pub(super) tcp_dial_mode: TcpDialMode,
    pub(super) sniffing_timeout: Duration,
    pub(super) dns: ResidentDnsPlan,
}

impl ResidentDataplanePlan {
    pub(super) fn default_proxy_group(&self) -> Option<&ResidentProxyGroupPlan> {
        self.default_outbound
            .and_then(|outbound| self.proxies.get(&outbound))
    }

    pub(super) fn default_proxy_snapshot(&self) -> Option<ResidentProxyPlan> {
        self.default_proxy_group()
            .and_then(ResidentProxyGroupPlan::default_proxy_snapshot)
    }
}

pub(super) fn build_resident_dataplane_plan(
    config: &Config,
) -> Result<ResidentDataplanePlan, String> {
    let node_links = tagged_node_links(config);
    let (proxies, default_outbound) = resident_proxy_plans(config, &node_links)?;
    if default_outbound
        .and_then(|outbound| proxies.get(&outbound))
        .and_then(ResidentProxyGroupPlan::default_proxy_snapshot)
        .is_none()
    {
        return Ok(ResidentDataplanePlan {
            enabled: false,
            unsupported_reason: Some(
                "no user-defined routing outbound with a resolvable node link was found".to_owned(),
            ),
            proxies,
            default_outbound: None,
            tcp_dial_mode: parse_tcp_dial_mode(config)?,
            sniffing_timeout: Duration::ZERO,
            dns: ResidentDnsPlan::asis(config.global.so_mark_from_dae),
        });
    };
    let tcp_dial_mode = parse_tcp_dial_mode(config)?;
    let sniffing_timeout = tcp_sniffing_timeout(config, tcp_dial_mode);
    let dns = build_resident_dns_plan(config)?;
    Ok(ResidentDataplanePlan {
        enabled: true,
        unsupported_reason: None,
        proxies,
        default_outbound,
        tcp_dial_mode,
        sniffing_timeout,
        dns,
    })
}

pub(super) fn build_resident_manual_probe_plans(
    config: &Config,
) -> BTreeMap<String, Result<ResidentProxyProbePlan, String>> {
    let mut plans = BTreeMap::new();
    for (node_tag, link) in tagged_node_links(config) {
        let plan = build_resident_manual_probe_plan(config, node_tag, link.clone());
        plans.entry(link).or_insert(plan);
    }
    plans
}

fn build_resident_manual_probe_plan(
    config: &Config,
    node_tag: String,
    link: String,
) -> Result<ResidentProxyProbePlan, String> {
    let group_name = "__manual_native_probe".to_owned();
    let mut proxy = build_proxy_plan(config, group_name.clone(), node_tag.clone(), link.clone())?;
    proxy.group_policy = "manual_probe".to_owned();
    let group = Group {
        name: group_name,
        filter: Vec::new(),
        filter_annotation: Vec::new(),
        policy: DynamicFunctionValue::Nil,
        tcp_check_url: None,
        tcp_check_http_method: String::new(),
        udp_check_dns: None,
        check_interval: Default::default(),
        check_tolerance: Default::default(),
    };
    Ok(ResidentProxyProbePlan {
        node_tag,
        link_hash: link_hash(&link),
        redacted_link_source: redacted_link_source(&link),
        link,
        tcp_check: group_tcp_check_plan(config, &group)?,
        udp_check: group_udp_check_plan(config, &group)?,
        proxy,
    })
}

fn resident_proxy_plans(
    config: &Config,
    node_links: &BTreeMap<String, String>,
) -> Result<(BTreeMap<u8, ResidentProxyGroupPlan>, Option<u8>), String> {
    let mut proxies = BTreeMap::new();
    let mut default_outbound = None;
    for outbound in referenced_user_outbounds(config) {
        if node_links.contains_key(&outbound) {
            return Err(format!(
                "resident dataplane cannot assign direct node outbound {outbound} to a stable Go-compatible outbound index; put the node behind a group before enabling Rust resident dataplane",
            ));
        }
        let Some((group_index, group)) = config
            .group
            .iter()
            .enumerate()
            .find(|(_, group)| group.name == outbound)
        else {
            continue;
        };
        let outbound_index = (OutboundIndex::USER_DEFINED_MIN.value() as usize + group_index) as u8;
        if proxies.contains_key(&outbound_index) {
            continue;
        }
        let group_policy = parse_group_policy(&group.policy)
            .map_err(|err| format!("resident dataplane group {} policy: {err}", group.name))?;
        let matched_nodes = match select_group_nodes(group, node_links)? {
            GroupNodeSelection::Selected(nodes) => nodes,
            GroupNodeSelection::NoCandidate {
                explicit_name_filter,
                unresolved_names,
            } => {
                let names = if unresolved_names.is_empty() {
                    "<empty>".to_owned()
                } else {
                    unresolved_names.join(", ")
                };
                let reason = if explicit_name_filter {
                    format!(
                        "resident dataplane cannot resolve group {} name filter node(s): {names}; subscription-backed groups must be materialized before Rust resident dataplane can own runtime",
                        group.name
                    )
                } else {
                    format!(
                        "resident dataplane cannot resolve any node for referenced group {}",
                        group.name
                    )
                };
                return Err(reason);
            }
        };
        let matched_candidate_count = matched_nodes.len();
        let build_nodes = if let Some(index) = group_policy.fixed_index() {
            let Some(node) = matched_nodes.get(index) else {
                return Err(format!(
                    "resident dataplane group {} fixed policy index {} is out of range for {} matched node(s)",
                    group.name, index, matched_candidate_count
                ));
            };
            vec![node.clone()]
        } else {
            matched_nodes
        };
        let mut candidates = Vec::with_capacity(build_nodes.len());
        for node in build_nodes {
            let link = node.link.clone();
            let mut proxy =
                build_proxy_plan(config, group.name.clone(), node.tag.clone(), node.link)?;
            proxy.group_policy = group_policy.as_str().to_owned();
            candidates.push(ResidentProxyCandidatePlan {
                match_index: node.match_index,
                annotation_add_latency_ms: node.annotation_add_latency_ms,
                link_hash: link_hash(&link),
                redacted_link_source: redacted_link_source(&link),
                link,
                proxy,
            });
        }
        if candidates.is_empty() {
            return Err(format!(
                "resident dataplane cannot resolve any admitted candidate for referenced group {}",
                group.name
            ));
        }
        let selector = build_resident_group_selector(
            &group.name,
            &group_policy,
            &candidates,
            group_check_tolerance_ms(config, group),
        );
        let group_plan = ResidentProxyGroupPlan {
            group_name: group.name.clone(),
            group_policy,
            matched_candidate_count,
            selector: Arc::new(Mutex::new(selector)),
            candidates,
            check_interval: group_check_interval(config, group),
            tcp_check: group_tcp_check_plan(config, group)?,
            udp_check: group_udp_check_plan(config, group)?,
        };
        default_outbound.get_or_insert(outbound_index);
        proxies.insert(outbound_index, group_plan);
    }
    Ok((proxies, default_outbound))
}

fn build_resident_group_selector(
    group_name: &str,
    group_policy: &ResidentGroupPolicyPlan,
    candidates: &[ResidentProxyCandidatePlan],
    check_tolerance_ms: i64,
) -> DialerGroup {
    let selector_policy = match group_policy {
        ResidentGroupPolicyPlan::Fixed { .. } => SelectionPolicy::Fixed { index: 0 },
        ResidentGroupPolicyPlan::Random => SelectionPolicy::Random,
        ResidentGroupPolicyPlan::MinLastLatency => SelectionPolicy::MinLastLatency,
        ResidentGroupPolicyPlan::MinAverage10 => SelectionPolicy::MinAverage10,
        ResidentGroupPolicyPlan::MinMovingAverage => SelectionPolicy::MinMovingAverage,
    };
    DialerGroup::new(
        group_name,
        candidates
            .iter()
            .map(|candidate| {
                Dialer::new(candidate.proxy.node_tag.clone(), "").with_link(candidate.link.clone())
            })
            .collect(),
        candidates
            .iter()
            .map(|candidate| Annotation {
                add_latency_ms: candidate.annotation_add_latency_ms,
            })
            .collect(),
        selector_policy,
        true,
        check_tolerance_ms,
    )
}

fn group_check_tolerance_ms(config: &Config, group: &Group) -> i64 {
    let nanos = if group.check_tolerance.as_nanos() != 0 {
        group.check_tolerance.as_nanos()
    } else {
        config.global.check_tolerance.as_nanos()
    };
    duration_nanos_to_millis(nanos)
}

fn group_check_interval(config: &Config, group: &Group) -> Duration {
    let nanos = if group.check_interval.as_nanos() != 0 {
        group.check_interval.as_nanos()
    } else {
        config.global.check_interval.as_nanos()
    };
    duration_nanos_to_duration(nanos)
}

fn duration_nanos_to_duration(nanos: i64) -> Duration {
    if nanos <= 0 {
        return Duration::ZERO;
    }
    Duration::from_nanos(nanos as u64)
}

fn group_tcp_check_plan(config: &Config, group: &Group) -> Result<ResidentTcpCheckPlan, String> {
    let urls = group
        .tcp_check_url
        .as_ref()
        .filter(|urls| !urls.is_empty())
        .unwrap_or(&config.global.tcp_check_url);
    let raw = urls
        .first()
        .filter(|raw| !raw.is_empty())
        .map(String::as_str)
        .unwrap_or("http://cp.cloudflare.com");
    let url = Url::parse(raw).map_err(|err| {
        format!(
            "resident dataplane group {} tcp_check_url {raw}: {err}",
            group.name
        )
    })?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(format!(
            "resident dataplane group {} tcp_check_url supports http or https check targets, got scheme {}",
            group.name,
            url.scheme()
        ));
    }
    let host = url.host_str().ok_or_else(|| {
        format!(
            "resident dataplane group {} tcp_check_url {raw} has no host",
            group.name
        )
    })?;
    let port = url.port_or_known_default().unwrap_or(80);
    let mut path = url.path().to_owned();
    if path.is_empty() {
        path = "/".to_owned();
    }
    if let Some(query) = url.query()
        && !query.is_empty()
    {
        path.push('?');
        path.push_str(query);
    }
    let method = if !group.tcp_check_http_method.is_empty() {
        group.tcp_check_http_method.clone()
    } else if !config.global.tcp_check_http_method.is_empty() {
        config.global.tcp_check_http_method.clone()
    } else {
        "HEAD".to_owned()
    };
    let explicit_addresses = if urls.len() > 1 { &urls[1..] } else { &[] };
    Ok(ResidentTcpCheckPlan {
        scheme: url.scheme().to_owned(),
        target: tcp_check_target(host, port, explicit_addresses),
        host: host.to_owned(),
        path,
        method,
    })
}

fn group_udp_check_plan(config: &Config, group: &Group) -> Result<ResidentUdpCheckPlan, String> {
    let values = group
        .udp_check_dns
        .as_ref()
        .filter(|values| !values.is_empty())
        .unwrap_or(&config.global.udp_check_dns);
    let raw = values
        .first()
        .filter(|raw| !raw.is_empty())
        .map(String::as_str)
        .unwrap_or("dns.google:53");
    let (host, port) = split_check_host_port(raw).map_err(|err| {
        format!(
            "resident dataplane group {} udp_check_dns {raw}: {err}",
            group.name
        )
    })?;
    let explicit_addresses = if values.len() > 1 { &values[1..] } else { &[] };
    let target = explicit_or_resolved_ipv4(&host, port, explicit_addresses).map_err(|err| {
        format!(
            "resident dataplane group {} udp_check_dns {raw}: {err}",
            group.name
        )
    })?;
    Ok(ResidentUdpCheckPlan {
        target,
        host,
        lookup_host: "connectivitycheck.gstatic.com.".to_owned(),
    })
}

fn split_check_host_port(raw: &str) -> Result<(String, u16), String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err("empty host:port".to_owned());
    }
    if let Some(rest) = raw.strip_prefix('[') {
        let Some((host, after_host)) = rest.split_once(']') else {
            return Err("missing closing bracket for IPv6 host".to_owned());
        };
        let port = after_host
            .strip_prefix(':')
            .ok_or_else(|| "missing port after IPv6 host".to_owned())?;
        return Ok((host.to_owned(), parse_check_port(port)?));
    }
    let Some((host, port)) = raw.rsplit_once(':') else {
        return Err("expected host:port".to_owned());
    };
    if host.is_empty() {
        return Err("empty host".to_owned());
    }
    Ok((host.to_owned(), parse_check_port(port)?))
}

fn parse_check_port(raw: &str) -> Result<u16, String> {
    raw.parse::<u16>()
        .map_err(|err| format!("invalid port {raw}: {err}"))
}

fn tcp_check_target(host: &str, port: u16, explicit_addresses: &[String]) -> String {
    for raw in explicit_addresses {
        let raw = raw.trim();
        if raw.parse::<Ipv4Addr>().is_ok() {
            return format!("{raw}:{port}");
        }
    }
    format!("{host}:{port}")
}

fn explicit_or_resolved_ipv4(
    host: &str,
    port: u16,
    explicit_addresses: &[String],
) -> Result<SocketAddrV4, String> {
    for raw in explicit_addresses {
        let raw = raw.trim();
        if raw.is_empty() {
            continue;
        }
        if let Ok(ip) = raw.parse::<Ipv4Addr>() {
            return Ok(SocketAddrV4::new(ip, port));
        }
    }
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        return Ok(SocketAddrV4::new(ip, port));
    }
    let authority = format!("{host}:{port}");
    authority
        .to_socket_addrs()
        .map_err(|err| format!("resolve {authority}: {err}"))?
        .find_map(|addr| match addr {
            SocketAddr::V4(addr) => Some(addr),
            SocketAddr::V6(_) => None,
        })
        .ok_or_else(|| format!("resolve {authority}: no IPv4 address"))
}

fn duration_nanos_to_millis(nanos: i64) -> i64 {
    if nanos <= 0 {
        return 0;
    }
    (nanos + 999_999) / 1_000_000
}

fn resident_selector_network_type(network: &str) -> Result<NetworkType, String> {
    match network {
        "tcp4" => Ok(NetworkType::TCP4),
        "udp4" => Ok(NetworkType::DNS_UDP4),
        other => Err(format!("unsupported resident selector network: {other}")),
    }
}

fn build_proxy_plan(
    config: &Config,
    group_name: String,
    node_tag: String,
    link: String,
) -> Result<ResidentProxyPlan, String> {
    if link.contains(" -> ") || link.contains("->") {
        return build_chained_proxy_plan(config, group_name, node_tag, link);
    }
    let scheme = link_scheme(&link).unwrap_or_default();
    match scheme.as_str() {
        "vless" => build_vless_proxy_plan(config, group_name, node_tag, link),
        "socks" | "socks5" => build_socks5_proxy_plan(config, group_name, node_tag, link),
        "http" | "https" => build_http_proxy_plan(config, group_name, node_tag, link),
        "ss" | "shadowsocks" => build_shadowsocks_proxy_plan(config, group_name, node_tag, link),
        "trojan" | "trojan-go" => build_trojan_proxy_plan(config, group_name, node_tag, link),
        "anytls" => build_anytls_proxy_plan(config, group_name, node_tag, link),
        "vmess" => build_vmess_proxy_plan(config, group_name, node_tag, link),
        "hysteria2" | "hy2" => build_hysteria2_proxy_plan(config, group_name, node_tag, link),
        "tuic" => build_tuic_proxy_plan(config, group_name, node_tag, link),
        "juicity" => build_juicity_proxy_plan(config, group_name, node_tag, link),
        _ => Err(format!(
            "resident dataplane selected unsupported {scheme} node {node_tag}; no resident executor is admitted for this node shape; shape remains fail-closed for this config",
        )),
    }
}

fn build_chained_proxy_plan(
    config: &Config,
    group_name: String,
    node_tag: String,
    link: String,
) -> Result<ResidentProxyPlan, String> {
    let parsed =
        parse_link_chain(&link).map_err(|err| format!("parse chained node {node_tag}: {err}"))?;
    if parsed.nodes.len() != 2 {
        return Err(format!(
            "resident dataplane nested chain executor admits two-node chains only for node {node_tag}; got {} node(s)",
            parsed.nodes.len()
        ));
    }
    let parent_node = parsed.nodes[0].clone();
    let child_node = parsed.nodes[1].clone();
    let parent = build_proxy_plan(
        config,
        group_name.clone(),
        format!("{node_tag}:parent"),
        parent_node.raw,
    )?;
    let mut child = build_proxy_plan(config, group_name, node_tag.clone(), child_node.raw)?;
    if !resident_chain_parent_supported(&parent) {
        return Err(format!(
            "resident dataplane nested chain executor admits plain SOCKS5/HTTP CONNECT parent only for node {node_tag}; got {}",
            parent.protocol
        ));
    }
    if !resident_chain_child_supported(&child) {
        return Err(format!(
            "resident dataplane nested chain executor admits resident TCP child handlers only for node {node_tag}; got {}/{}",
            child.protocol, child.net
        ));
    }
    let graph = resident_graph_identity(&link);
    child.graph_id = graph.graph_id;
    child.graph_link_hash = graph.link_hash;
    child.redacted_link_source = graph.redacted_link_source;
    child.chain_parent = Some(Box::new(parent));
    Ok(child)
}

fn resident_chain_parent_supported(parent: &ResidentProxyPlan) -> bool {
    match &parent.handler {
        ResidentProxyProtocolPlan::Socks5Tcp { .. } => parent.tls == "none",
        ResidentProxyProtocolPlan::HttpProxyTcp { .. } => parent.tls == "none",
        _ => false,
    }
}

fn resident_chain_child_supported(child: &ResidentProxyPlan) -> bool {
    match &child.handler {
        ResidentProxyProtocolPlan::Socks5Tcp { .. } => true,
        ResidentProxyProtocolPlan::HttpProxyTcp { .. } => child.tls == "none",
        ResidentProxyProtocolPlan::ShadowsocksAeadTcp { .. }
        | ResidentProxyProtocolPlan::Shadowsocks2022Tcp { .. }
        | ResidentProxyProtocolPlan::ShadowsocksSimpleObfsHttpTcp { .. }
        | ResidentProxyProtocolPlan::ShadowsocksSimpleObfsTlsTcp { .. }
        | ResidentProxyProtocolPlan::ShadowsocksV2rayPluginTlsWsTcp { .. }
        | ResidentProxyProtocolPlan::Shadowsocks2022SimpleObfsHttpTcp { .. } => true,
        ResidentProxyProtocolPlan::VmessAeadTcp { .. } => {
            matches!(child.net.as_str(), "tcp" | "websocket" | "httpupgrade") && child.tls == "none"
        }
        _ => false,
    }
}

fn build_vless_proxy_plan(
    config: &Config,
    group_name: String,
    node_tag: String,
    link: String,
) -> Result<ResidentProxyPlan, String> {
    let vless =
        VLESSLink::parse(&link).map_err(|err| format!("parse VLESS node {node_tag}: {err}"))?;
    vless
        .validate_flow_client(true)
        .map_err(|err| format!("validate VLESS flow for {node_tag}: {err}"))?;
    vless
        .validate_transport_contract()
        .map_err(|err| format!("validate VLESS transport for {node_tag}: {err}"))?;
    let net = canonical_resident_vless_net(&vless.net);
    match net.as_str() {
        "tcp" if vless.flow != XTLS_RPRX_VISION => {
            return Err(format!(
                "resident dataplane vless native experiment admits tcp flow={XTLS_RPRX_VISION}, got '{}' for node {node_tag}; resident shape remains fail-closed for this config",
                vless.flow
            ));
        }
        "websocket" | "httpupgrade" | "grpc" | "xhttp" | "meek" if !vless.flow.is_empty() => {
            return Err(format!(
                "resident dataplane vless wrapped-stream handler admits only empty flow, got '{}' for node {node_tag}; resident shape remains fail-closed for this config",
                vless.flow
            ));
        }
        "tcp" | "websocket" | "httpupgrade" | "grpc" | "xhttp" | "meek" => {}
        other => {
            return Err(format!(
                "resident dataplane vless handler currently supports tcp, websocket, httpupgrade, grpc, xhttp, and meek transports only, got {other} for node {node_tag}"
            ));
        }
    }
    if vless.tls != "tls" {
        return Err(format!(
            "resident dataplane vless handler currently supports security=tls only, got {} for node {node_tag}",
            vless.tls
        ));
    }
    if vless.allow_insecure || config.global.allow_insecure {
        return Err(
            "resident dataplane vless TLS handler does not admit allow_insecure; resident shape remains fail-closed for this config"
                .to_owned(),
        );
    }
    if net == "xhttp" {
        let mode = ir::normalize_xhttp_mode(&vless.xhttp_mode, "https", &vless.tls, false);
        if !mode.ok {
            return Err(format!(
                "resident dataplane vless xHTTP transport rejected mode for node {node_tag}: {}",
                mode.error_contains
            ));
        }
        if mode.normalized != "packet-up" {
            return Err(format!(
                "resident dataplane vless xHTTP transport admits packet-up mode only, got {} for node {node_tag}; resident shape remains fail-closed for this config",
                mode.normalized
            ));
        }
        let alpn_result = ir::validate_xhttp_alpn(&vless.tls, &vless.alpn);
        if !alpn_result.ok {
            return Err(format!(
                "resident dataplane vless xHTTP transport rejected ALPN for node {node_tag}: {}",
                alpn_result.error_contains
            ));
        }
        if alpn_result.use_h3 {
            return Err(format!(
                "resident dataplane vless xHTTP transport admits HTTP/2 packet-up only, got h3 for node {node_tag}; resident shape remains fail-closed for this config"
            ));
        }
        if !resident_xhttp_extra_is_empty(&vless.xhttp_extra) {
            return Err(format!(
                "resident dataplane vless xHTTP transport admits default extra settings only for node {node_tag}; resident shape remains fail-closed for this config"
            ));
        }
    }
    let meek_options = if net == "meek" {
        Some(
            MeekRoundTripOptions::from_https_url(&vless.path, Vec::new()).map_err(|err| {
                format!(
                    "resident dataplane vless Meek transport requires a standard https url for node {node_tag}: {err}"
                )
            })?,
        )
    } else {
        None
    };
    let utls_fingerprint = resident_utls_fingerprint_plan(config, Some(&vless.fingerprint))?;
    let server_port = vless.port.parse::<u16>().map_err(|err| {
        format!(
            "invalid VLESS port {} for node {node_tag}: {err}",
            vless.port
        )
    })?;
    let key = password_to_key(&vless.id)
        .map_err(|err| format!("parse VLESS key for {node_tag}: {err}"))?;
    let server_name = if vless.sni.is_empty() {
        vless.add.clone()
    } else {
        vless.sni.clone()
    };
    let alpn = if matches!(net.as_str(), "grpc" | "xhttp") && vless.alpn.is_empty() {
        vec!["h2".to_owned()]
    } else {
        split_alpn(&vless.alpn)
    };
    let stream_host = if let Some(meek_options) = &meek_options {
        meek_options.host.clone()
    } else if matches!(net.as_str(), "websocket" | "httpupgrade" | "grpc" | "xhttp") {
        resident_stream_host(&vless.host, &server_name)
    } else {
        String::new()
    };
    let stream_path = if net == "grpc" {
        resident_grpc_service_name(&vless.path)
    } else if let Some(meek_options) = &meek_options {
        meek_options.path.clone()
    } else if net == "xhttp" {
        resident_xhttp_stream_path(&vless.path)
    } else if matches!(net.as_str(), "websocket" | "httpupgrade") {
        resident_stream_path(&vless.path)
    } else {
        String::new()
    };
    let graph = resident_graph_identity(&link);
    Ok(ResidentProxyPlan {
        graph_id: graph.graph_id,
        graph_link_hash: graph.link_hash,
        redacted_link_source: graph.redacted_link_source,
        protocol: "vless".to_owned(),
        group_name,
        group_policy: String::new(),
        node_tag,
        server_host: vless.add,
        server_port,
        server_name,
        alpn,
        flow: vless.flow,
        net,
        stream_host,
        stream_path,
        tls: vless.tls,
        allow_insecure: false,
        utls_fingerprint,
        handler: ResidentProxyProtocolPlan::VlessVisionTcpTls { key },
        chain_parent: None,
        mark: config.global.so_mark_from_dae,
        mptcp: config.global.mptcp,
    })
}

fn build_socks5_proxy_plan(
    config: &Config,
    group_name: String,
    node_tag: String,
    link: String,
) -> Result<ResidentProxyPlan, String> {
    let parsed = Url::parse(&link).map_err(|err| format!("parse SOCKS node {node_tag}: {err}"))?;
    if !matches!(parsed.scheme(), "socks" | "socks5") {
        return Err(format!(
            "resident dataplane socks5 handler got unsupported scheme {} for node {node_tag}",
            parsed.scheme()
        ));
    }
    let server_host = parsed
        .host_str()
        .ok_or_else(|| format!("parse SOCKS node {node_tag}: missing host"))?
        .to_owned();
    let server_port = parsed.port().unwrap_or(1080);
    let graph = resident_graph_identity(&link);
    Ok(ResidentProxyPlan {
        graph_id: graph.graph_id,
        graph_link_hash: graph.link_hash,
        redacted_link_source: graph.redacted_link_source,
        protocol: "socks5".to_owned(),
        group_name,
        group_policy: String::new(),
        node_tag,
        server_host,
        server_port,
        server_name: String::new(),
        alpn: Vec::new(),
        flow: String::new(),
        net: "tcp".to_owned(),
        stream_host: String::new(),
        stream_path: String::new(),
        tls: "none".to_owned(),
        allow_insecure: false,
        utls_fingerprint: None,
        handler: ResidentProxyProtocolPlan::Socks5Tcp {
            username: parsed.username().to_owned(),
            password: parsed.password().unwrap_or_default().to_owned(),
        },
        chain_parent: None,
        mark: config.global.so_mark_from_dae,
        mptcp: config.global.mptcp,
    })
}

fn build_http_proxy_plan(
    config: &Config,
    group_name: String,
    node_tag: String,
    link: String,
) -> Result<ResidentProxyPlan, String> {
    let parsed = HttpProxyLink::parse(&link)
        .map_err(|err| format!("parse HTTP proxy node {node_tag}: {err}"))?;
    if parsed.allow_insecure || config.global.allow_insecure {
        return Err(format!(
            "resident dataplane HTTP proxy handler does not admit allow_insecure for node {node_tag}"
        ));
    }
    if parsed.protocol == HttpScheme::Https && !parsed.utls_imitate.is_empty() {
        return Err(format!(
            "resident dataplane HTTPS proxy handler does not admit fingerprint/utls imitation for node {node_tag}"
        ));
    }
    if parsed.protocol == HttpScheme::Https && parsed.tls_implementation != "tls" {
        return Err(format!(
            "resident dataplane HTTPS proxy handler admits standard tlsImplementation only for node {node_tag}"
        ));
    }
    let (tls, server_name, alpn) = match parsed.protocol {
        HttpScheme::Http => ("none".to_owned(), String::new(), Vec::new()),
        HttpScheme::Https => (
            "tls".to_owned(),
            parsed.effective_sni(),
            resident_csv_values(&parsed.alpn),
        ),
    };
    let graph = resident_graph_identity(&link);
    Ok(ResidentProxyPlan {
        graph_id: graph.graph_id,
        graph_link_hash: graph.link_hash,
        redacted_link_source: graph.redacted_link_source,
        protocol: "http-proxy".to_owned(),
        group_name,
        group_policy: String::new(),
        node_tag,
        server_host: parsed.server,
        server_port: parsed.port,
        server_name,
        alpn,
        flow: String::new(),
        net: if parsed.transport {
            "http-transport".to_owned()
        } else {
            "tcp".to_owned()
        },
        stream_host: parsed.host.clone(),
        stream_path: parsed.path.clone(),
        tls,
        allow_insecure: false,
        utls_fingerprint: None,
        handler: ResidentProxyProtocolPlan::HttpProxyTcp {
            username: parsed.username,
            password: parsed.password,
            transport: parsed.transport,
            transport_host: parsed.host,
            transport_path: parsed.path,
        },
        chain_parent: None,
        mark: config.global.so_mark_from_dae,
        mptcp: config.global.mptcp,
    })
}

fn build_shadowsocks_proxy_plan(
    config: &Config,
    group_name: String,
    node_tag: String,
    link: String,
) -> Result<ResidentProxyPlan, String> {
    let parsed = ShadowsocksLink::parse(&link)
        .map_err(|err| format!("parse Shadowsocks node {node_tag}: {err}"))?;
    let plugin = parsed.plugin.clone();
    if !resident_shadowsocks_plugin_supported(&plugin.name, &plugin.opts.obfs, &plugin.opts.tls) {
        return Err(format!(
            "resident dataplane Shadowsocks plugin wrapper admits simple-obfs http/tls and v2ray-plugin tls websocket only for node {node_tag}; got {}",
            resident_shadowsocks_plugin_display(&plugin.name, &plugin.opts.obfs, &plugin.opts.tls)
        ));
    }
    let cipher_info = classify_cipher(&parsed.cipher)
        .map_err(|err| format!("admit Shadowsocks cipher for node {node_tag}: {err}"))?;
    let (net, stream_host, stream_path, tls, handler) = match cipher_info.family {
        CipherFamily::Aead => {
            let spec = cipher_spec(&parsed.cipher)
                .map_err(|err| format!("admit Shadowsocks cipher for node {node_tag}: {err}"))?;
            if plugin.name == "simple-obfs" {
                let stream_host = if plugin.opts.host.is_empty() {
                    parsed.server.clone()
                } else {
                    plugin.opts.host.clone()
                };
                if plugin.opts.obfs == "tls" {
                    (
                        "simple-obfs-tls".to_owned(),
                        stream_host.clone(),
                        String::new(),
                        "aead".to_owned(),
                        ResidentProxyProtocolPlan::ShadowsocksSimpleObfsTlsTcp {
                            cipher: spec.cipher.to_owned(),
                            password: parsed.password.clone(),
                            salt_len: spec.salt_len,
                            host: stream_host,
                        },
                    )
                } else {
                    let stream_path = if plugin.opts.path.is_empty() {
                        "/".to_owned()
                    } else {
                        plugin.opts.path.clone()
                    };
                    (
                        "simple-obfs-http".to_owned(),
                        stream_host.clone(),
                        stream_path.clone(),
                        "aead".to_owned(),
                        ResidentProxyProtocolPlan::ShadowsocksSimpleObfsHttpTcp {
                            cipher: spec.cipher.to_owned(),
                            password: parsed.password.clone(),
                            salt_len: spec.salt_len,
                            host: stream_host,
                            path: stream_path,
                        },
                    )
                }
            } else if plugin.name == "v2ray-plugin" {
                let stream_host = if plugin.opts.host.is_empty() {
                    parsed.server.clone()
                } else {
                    plugin.opts.host.clone()
                };
                let stream_path = if plugin.opts.path.is_empty() {
                    "/".to_owned()
                } else {
                    plugin.opts.path.clone()
                };
                (
                    "v2ray-plugin-tls-websocket".to_owned(),
                    stream_host.clone(),
                    stream_path.clone(),
                    "tls".to_owned(),
                    ResidentProxyProtocolPlan::ShadowsocksV2rayPluginTlsWsTcp {
                        cipher: spec.cipher.to_owned(),
                        password: parsed.password.clone(),
                        salt_len: spec.salt_len,
                        host: stream_host,
                        path: stream_path,
                    },
                )
            } else {
                (
                    "tcp".to_owned(),
                    String::new(),
                    String::new(),
                    "aead".to_owned(),
                    ResidentProxyProtocolPlan::ShadowsocksAeadTcp {
                        cipher: spec.cipher.to_owned(),
                        password: parsed.password.clone(),
                        salt_len: spec.salt_len,
                    },
                )
            }
        }
        CipherFamily::Aead2022 => {
            if !plugin.name.is_empty() {
                if !(plugin.name == "simple-obfs"
                    && plugin.opts.obfs == "http"
                    && plugin.opts.tls.is_empty())
                {
                    return Err(format!(
                        "resident dataplane Shadowsocks 2022 plugin wrapper admits simple-obfs http only for node {node_tag}; got {}",
                        resident_shadowsocks_plugin_display(
                            &plugin.name,
                            &plugin.opts.obfs,
                            &plugin.opts.tls
                        )
                    ));
                }
            }
            validate_psk_list(&cipher_info.cipher, &parsed.password)
                .map_err(|err| format!("admit Shadowsocks 2022 PSK for node {node_tag}: {err}"))?;
            let conf = cipher_conf(&cipher_info.cipher).ok_or_else(|| {
                format!(
                    "admit Shadowsocks 2022 cipher for node {node_tag}: unsupported shadowsocks 2022 cipher: {}",
                    cipher_info.cipher
                )
            })?;
            if plugin.name == "simple-obfs" {
                let stream_host = if plugin.opts.host.is_empty() {
                    parsed.server.clone()
                } else {
                    plugin.opts.host.clone()
                };
                let stream_path = if plugin.opts.path.is_empty() {
                    "/".to_owned()
                } else {
                    plugin.opts.path.clone()
                };
                (
                    "simple-obfs-http".to_owned(),
                    stream_host.clone(),
                    stream_path.clone(),
                    "aead-2022".to_owned(),
                    ResidentProxyProtocolPlan::Shadowsocks2022SimpleObfsHttpTcp {
                        cipher: conf.cipher.to_owned(),
                        password: parsed.password.clone(),
                        salt_len: conf.salt_len,
                        host: stream_host,
                        path: stream_path,
                    },
                )
            } else {
                (
                    "tcp".to_owned(),
                    String::new(),
                    String::new(),
                    "aead-2022".to_owned(),
                    ResidentProxyProtocolPlan::Shadowsocks2022Tcp {
                        cipher: conf.cipher.to_owned(),
                        password: parsed.password.clone(),
                        salt_len: conf.salt_len,
                        packet_nonce_len: conf.packet_nonce_len,
                    },
                )
            }
        }
        CipherFamily::Stream => {
            return Err(format!(
                "admit Shadowsocks cipher for node {node_tag}: cipher family is not resident Shadowsocks packet-capable cipher: {}",
                cipher_info.cipher
            ));
        }
    };
    let graph = resident_graph_identity(&link);
    Ok(ResidentProxyPlan {
        graph_id: graph.graph_id,
        graph_link_hash: graph.link_hash,
        redacted_link_source: graph.redacted_link_source,
        protocol: "shadowsocks".to_owned(),
        group_name,
        group_policy: String::new(),
        node_tag,
        server_host: parsed.server,
        server_port: parsed.port,
        server_name: if tls == "tls" {
            stream_host.clone()
        } else {
            String::new()
        },
        alpn: if tls == "tls" {
            vec!["http/1.1".to_owned()]
        } else {
            Vec::new()
        },
        flow: String::new(),
        net,
        stream_host,
        stream_path,
        tls,
        allow_insecure: false,
        utls_fingerprint: None,
        handler,
        chain_parent: None,
        mark: config.global.so_mark_from_dae,
        mptcp: config.global.mptcp,
    })
}

fn resident_shadowsocks_plugin_supported(name: &str, obfs: &str, tls: &str) -> bool {
    name.is_empty()
        || (name == "simple-obfs" && matches!(obfs, "http" | "tls") && tls.is_empty())
        || (name == "v2ray-plugin" && obfs.is_empty() && tls == "tls")
}

fn resident_shadowsocks_plugin_display(name: &str, obfs: &str, tls: &str) -> String {
    if name.is_empty() {
        return "none".to_owned();
    }
    let mut fields = vec![name.to_owned()];
    if !obfs.is_empty() {
        fields.push(format!("obfs={obfs}"));
    }
    if !tls.is_empty() {
        fields.push("tls".to_owned());
    }
    fields.join(";")
}

fn build_trojan_proxy_plan(
    config: &Config,
    group_name: String,
    node_tag: String,
    link: String,
) -> Result<ResidentProxyPlan, String> {
    let parsed =
        TrojanLink::parse(&link).map_err(|err| format!("parse Trojan node {node_tag}: {err}"))?;
    let transport_kind = parsed.transport_kind();
    let websocket = parsed.protocol == "trojan-go" && transport_kind == TrojanTransportType::Ws;
    let httpupgrade =
        parsed.protocol == "trojan-go" && transport_kind == TrojanTransportType::HttpUpgrade;
    let grpc = parsed.protocol == "trojan-go" && transport_kind == TrojanTransportType::Grpc;
    let plain = parsed.protocol == "trojan" && transport_kind == TrojanTransportType::None;
    if !plain && !websocket && !httpupgrade && !grpc {
        return Err(format!(
            "resident dataplane generic TLS/TCP handler admits only plain trojan, trojan-go websocket, trojan-go httpupgrade, and trojan-go grpc endpoints for node {node_tag}; transport={} protocol={}",
            parsed.transport_type, parsed.protocol
        ));
    }
    let inner_shadowsocks = parse_trojan_go_inner_shadowsocks(&parsed.encryption, &node_tag)?;
    if inner_shadowsocks.is_some() && !websocket {
        return Err(format!(
            "resident dataplane trojan inner Shadowsocks layer admits WebSocket transport only for node {node_tag}; resident shape remains fail-closed for this config"
        ));
    }
    if parsed.allow_insecure || config.global.allow_insecure {
        return Err(
            "resident dataplane generic TLS/TCP handler does not admit allow_insecure; resident shape remains fail-closed for this config"
                .to_owned(),
        );
    }
    let utls_fingerprint = resident_utls_fingerprint_plan(config, None)?;
    let net = if websocket {
        "websocket"
    } else if httpupgrade {
        "httpupgrade"
    } else if grpc {
        "grpc"
    } else {
        "tcp"
    }
    .to_owned();
    let stream_host = if websocket || httpupgrade || grpc {
        resident_stream_host(&parsed.host, &parsed.sni)
    } else {
        String::new()
    };
    let stream_path = if grpc {
        resident_grpc_service_name(&parsed.service_name)
    } else if websocket || httpupgrade {
        resident_stream_path(&parsed.path)
    } else {
        String::new()
    };
    let graph = resident_graph_identity(&link);
    Ok(ResidentProxyPlan {
        graph_id: graph.graph_id,
        graph_link_hash: graph.link_hash,
        redacted_link_source: graph.redacted_link_source,
        protocol: "trojan".to_owned(),
        group_name,
        group_policy: String::new(),
        node_tag,
        server_host: parsed.server,
        server_port: parsed.port,
        server_name: parsed.sni,
        alpn: if grpc {
            vec!["h2".to_owned()]
        } else {
            Vec::new()
        },
        flow: String::new(),
        net,
        stream_host,
        stream_path,
        tls: "tls".to_owned(),
        allow_insecure: false,
        utls_fingerprint,
        handler: if let Some((inner_cipher, inner_password)) = inner_shadowsocks {
            ResidentProxyProtocolPlan::TrojanInnerShadowsocksTcpTls {
                password: parsed.password,
                inner_cipher,
                inner_password,
            }
        } else {
            ResidentProxyProtocolPlan::TrojanTcpTls {
                password: parsed.password,
            }
        },
        chain_parent: None,
        mark: config.global.so_mark_from_dae,
        mptcp: config.global.mptcp,
    })
}

fn parse_trojan_go_inner_shadowsocks(
    encryption: &str,
    node_tag: &str,
) -> Result<Option<(String, String)>, String> {
    if encryption.is_empty() {
        return Ok(None);
    }
    let mut fields = encryption.split(';');
    let Some(kind) = fields.next() else {
        return Ok(None);
    };
    if kind != "ss" {
        return Err(format!(
            "resident dataplane trojan inner encryption admits Shadowsocks only for node {node_tag}; got {kind}"
        ));
    }
    let Some(cipher_or_pair) = fields.next() else {
        return Err(format!(
            "resident dataplane trojan inner Shadowsocks encryption requires cipher for node {node_tag}"
        ));
    };
    let (cipher, password) = if let Some((cipher, password)) = cipher_or_pair.split_once(':') {
        (cipher.to_owned(), password.to_owned())
    } else {
        let Some(password) = fields.next() else {
            return Err(format!(
                "resident dataplane trojan inner Shadowsocks encryption requires password for node {node_tag}"
            ));
        };
        (cipher_or_pair.to_owned(), password.to_owned())
    };
    let spec = cipher_spec(&cipher).map_err(|err| {
        format!("admit Trojan-Go inner Shadowsocks cipher for node {node_tag}: {err}")
    })?;
    if password.is_empty() {
        return Err(format!(
            "resident dataplane trojan inner Shadowsocks encryption requires non-empty password for node {node_tag}"
        ));
    }
    Ok(Some((spec.cipher.to_owned(), password)))
}

fn build_anytls_proxy_plan(
    config: &Config,
    group_name: String,
    node_tag: String,
    link: String,
) -> Result<ResidentProxyPlan, String> {
    let parsed =
        AnyTLSLink::parse(&link).map_err(|err| format!("parse AnyTLS node {node_tag}: {err}"))?;
    if parsed.insecure || config.global.allow_insecure {
        return Err(
            "resident dataplane generic TLS/TCP handler does not admit AnyTLS insecure mode; resident shape remains fail-closed for this config"
                .to_owned(),
        );
    }
    let url =
        Url::parse(&link).map_err(|err| format!("parse AnyTLS endpoint {node_tag}: {err}"))?;
    let server_host = url
        .host_str()
        .ok_or_else(|| format!("parse AnyTLS endpoint {node_tag}: missing host"))?
        .to_owned();
    let server_port = url.port().unwrap_or(443);
    let utls_fingerprint = resident_utls_fingerprint_plan(config, None)?;
    let graph = resident_graph_identity(&link);
    Ok(ResidentProxyPlan {
        graph_id: graph.graph_id,
        graph_link_hash: graph.link_hash,
        redacted_link_source: graph.redacted_link_source,
        protocol: "anytls".to_owned(),
        group_name,
        group_policy: String::new(),
        node_tag,
        server_host,
        server_port,
        server_name: parsed.tls_server_name,
        alpn: Vec::new(),
        flow: String::new(),
        net: "tcp".to_owned(),
        stream_host: String::new(),
        stream_path: String::new(),
        tls: "tls".to_owned(),
        allow_insecure: false,
        utls_fingerprint,
        handler: ResidentProxyProtocolPlan::AnyTlsTcpTls { auth: parsed.auth },
        chain_parent: None,
        mark: config.global.so_mark_from_dae,
        mptcp: config.global.mptcp,
    })
}

fn build_tuic_proxy_plan(
    config: &Config,
    group_name: String,
    node_tag: String,
    link: String,
) -> Result<ResidentProxyPlan, String> {
    let parsed =
        TuicLink::parse(&link).map_err(|err| format!("parse TUIC node {node_tag}: {err}"))?;
    parsed
        .validate_uuid()
        .map_err(|err| format!("validate TUIC UUID for {node_tag}: {err}"))?;
    if parsed.password.is_empty() {
        return Err(format!(
            "resident dataplane generic QUIC handler requires TUIC password for node {node_tag}; resident shape remains fail-closed for this config"
        ));
    }
    let server_name = if parsed.sni.is_empty() {
        parsed.server.clone()
    } else {
        parsed.sni.clone()
    };
    let alpn = if parsed.alpn.is_empty() {
        vec!["h3".to_owned()]
    } else {
        parsed.alpn.clone()
    };
    let allow_insecure =
        parsed.allow_insecure || config.global.allow_insecure || parsed.disable_sni;
    let graph = resident_graph_identity(&link);
    Ok(ResidentProxyPlan {
        graph_id: graph.graph_id,
        graph_link_hash: graph.link_hash,
        redacted_link_source: graph.redacted_link_source,
        protocol: "tuic".to_owned(),
        group_name,
        group_policy: String::new(),
        node_tag,
        server_host: parsed.server,
        server_port: parsed.port,
        server_name,
        alpn: alpn.clone(),
        flow: String::new(),
        net: "udp".to_owned(),
        stream_host: String::new(),
        stream_path: String::new(),
        tls: "quic".to_owned(),
        allow_insecure,
        utls_fingerprint: None,
        handler: ResidentProxyProtocolPlan::TuicQuicTcp {
            uuid: parsed.user,
            password: parsed.password,
            alpn,
            allow_insecure,
        },
        chain_parent: None,
        mark: config.global.so_mark_from_dae,
        mptcp: config.global.mptcp,
    })
}

fn build_hysteria2_proxy_plan(
    config: &Config,
    group_name: String,
    node_tag: String,
    link: String,
) -> Result<ResidentProxyPlan, String> {
    let parsed = Hysteria2Link::parse(&link)
        .map_err(|err| format!("parse Hysteria2 node {node_tag}: {err}"))?;
    if parsed.insecure || config.global.allow_insecure {
        return Err(
            "resident dataplane generic QUIC handler does not admit Hysteria2 insecure mode; resident shape remains fail-closed for this config"
                .to_owned(),
        );
    }
    if parsed.pin_sha256.is_empty() {
        return Err(format!(
            "resident dataplane generic QUIC handler requires Hysteria2 pinSHA256 for node {node_tag}; resident shape remains fail-closed for this config"
        ));
    }
    let auth = if parsed.password.is_empty() {
        parsed.user.clone()
    } else {
        format!("{}:{}", parsed.user, parsed.password)
    };
    if auth.is_empty() {
        return Err(format!(
            "resident dataplane generic QUIC handler requires Hysteria2 auth for node {node_tag}; resident shape remains fail-closed for this config"
        ));
    }
    let server = hysteria2_server_contract(&parsed.server);
    let (server_port, port_hop_ports) = if server.port_hopping {
        let schedule =
            build_port_hop_schedule(&parsed.server, DEFAULT_TRUE_QUIC_UDP_HOP_INTERVAL_MS, 1)
                .map_err(|err| {
                    format!("admit Hysteria2 port hopping for node {node_tag}: {err}")
                })?;
        let server_port = *schedule.selected_ports.first().ok_or_else(|| {
            format!("admit Hysteria2 port hopping for node {node_tag}: no selected port")
        })?;
        (server_port, schedule.normalized_ports)
    } else {
        let server_port = server.port.parse::<u16>().map_err(|err| {
            format!(
                "invalid Hysteria2 port {} for node {node_tag}: {err}",
                server.port
            )
        })?;
        (server_port, Vec::new())
    };
    let server_name = if parsed.sni.is_empty() {
        server.host.clone()
    } else {
        parsed.sni.clone()
    };
    let graph = resident_graph_identity(&link);
    Ok(ResidentProxyPlan {
        graph_id: graph.graph_id,
        graph_link_hash: graph.link_hash,
        redacted_link_source: graph.redacted_link_source,
        protocol: "hysteria2".to_owned(),
        group_name,
        group_policy: String::new(),
        node_tag,
        server_host: server.host,
        server_port,
        server_name,
        alpn: vec!["h3".to_owned()],
        flow: String::new(),
        net: "udp".to_owned(),
        stream_host: String::new(),
        stream_path: String::new(),
        tls: "quic".to_owned(),
        allow_insecure: false,
        utls_fingerprint: None,
        handler: ResidentProxyProtocolPlan::Hysteria2QuicTcp {
            auth,
            pin_sha256: parsed.pin_sha256,
            max_rx: parsed.max_rx,
            port_hop_ports,
        },
        chain_parent: None,
        mark: config.global.so_mark_from_dae,
        mptcp: config.global.mptcp,
    })
}

fn build_juicity_proxy_plan(
    config: &Config,
    group_name: String,
    node_tag: String,
    link: String,
) -> Result<ResidentProxyPlan, String> {
    let parsed =
        JuicityLink::parse(&link).map_err(|err| format!("parse Juicity node {node_tag}: {err}"))?;
    parsed
        .validate_uuid()
        .map_err(|err| format!("validate Juicity UUID for {node_tag}: {err}"))?;
    if parsed.password.is_empty() {
        return Err(format!(
            "resident dataplane generic QUIC handler requires Juicity password for node {node_tag}; resident shape remains fail-closed for this config"
        ));
    }
    let allow_insecure = parsed.allow_insecure || config.global.allow_insecure;
    if !allow_insecure && parsed.pinned_certchain_sha256.is_empty() {
        return Err(format!(
            "resident dataplane generic QUIC handler requires Juicity allow_insecure or pinned_certchain_sha256 for node {node_tag}; resident shape remains fail-closed for this config"
        ));
    }
    let server_name = if parsed.sni.is_empty() {
        parsed.server.clone()
    } else {
        parsed.sni.clone()
    };
    let graph = resident_graph_identity(&link);
    Ok(ResidentProxyPlan {
        graph_id: graph.graph_id,
        graph_link_hash: graph.link_hash,
        redacted_link_source: graph.redacted_link_source,
        protocol: "juicity".to_owned(),
        group_name,
        group_policy: String::new(),
        node_tag,
        server_host: parsed.server,
        server_port: parsed.port,
        server_name,
        alpn: vec!["h3".to_owned()],
        flow: String::new(),
        net: "udp".to_owned(),
        stream_host: String::new(),
        stream_path: String::new(),
        tls: "quic".to_owned(),
        allow_insecure,
        utls_fingerprint: None,
        handler: ResidentProxyProtocolPlan::JuicityQuicTcp {
            uuid: parsed.user,
            password: parsed.password,
            allow_insecure,
            pinned_certchain_sha256: parsed.pinned_certchain_sha256,
        },
        chain_parent: None,
        mark: config.global.so_mark_from_dae,
        mptcp: config.global.mptcp,
    })
}

fn build_vmess_proxy_plan(
    config: &Config,
    group_name: String,
    node_tag: String,
    link: String,
) -> Result<ResidentProxyPlan, String> {
    let parsed =
        VMessLink::parse(&link).map_err(|err| format!("parse VMess node {node_tag}: {err}"))?;
    parsed
        .validate_aead()
        .map_err(|err| format!("validate VMess AEAD for {node_tag}: {err}"))?;
    parsed
        .validate_transport()
        .map_err(|err| format!("validate VMess transport for {node_tag}: {err}"))?;
    let net = match parsed.net.as_str() {
        "" | "tcp" => "tcp".to_owned(),
        "ws" | "websocket" => "websocket".to_owned(),
        "httpupgrade" => "httpupgrade".to_owned(),
        "grpc" => "grpc".to_owned(),
        other => other.to_owned(),
    };
    match net.as_str() {
        "tcp" | "websocket" | "httpupgrade" | "grpc" => {}
        other => {
            return Err(format!(
                "resident dataplane generic AEAD TCP handler admits only VMess tcp, websocket, httpupgrade, and grpc endpoints for node {node_tag}; got {other}"
            ));
        }
    }
    if net == "tcp" && !parsed.tls.is_empty() && parsed.tls != "none" {
        return Err(format!(
            "resident dataplane generic AEAD TCP handler admits only plain VMess TCP endpoints for node {node_tag}; got tls={}",
            parsed.tls
        ));
    }
    if net == "websocket" && !matches!(parsed.tls.as_str(), "" | "none" | "tls") {
        return Err(format!(
            "resident dataplane VMess websocket handler admits only plain WebSocket or TLS WebSocket for node {node_tag}; got tls={}",
            parsed.tls
        ));
    }
    if net == "httpupgrade" && !matches!(parsed.tls.as_str(), "" | "none" | "tls") {
        return Err(format!(
            "resident dataplane VMess httpupgrade handler admits only plain HTTP Upgrade or TLS HTTP Upgrade for node {node_tag}; got tls={}",
            parsed.tls
        ));
    }
    if net == "grpc" && parsed.tls != "tls" {
        return Err(format!(
            "resident dataplane VMess grpc handler admits TLS HTTP/2 endpoints only for node {node_tag}; got tls={}",
            if parsed.tls.is_empty() {
                "none"
            } else {
                parsed.tls.as_str()
            }
        ));
    }
    if parsed.allow_insecure || config.global.allow_insecure {
        return Err(
            "resident dataplane generic AEAD TCP handler does not admit allow_insecure; resident shape remains fail-closed for this config"
                .to_owned(),
        );
    }
    let server_port = parsed.port.parse::<u16>().map_err(|err| {
        format!(
            "invalid VMess port {} for node {node_tag}: {err}",
            parsed.port
        )
    })?;
    let stream_host = if matches!(net.as_str(), "websocket" | "httpupgrade" | "grpc") {
        resident_stream_host(&parsed.host, &parsed.add)
    } else {
        String::new()
    };
    let stream_path = if net == "grpc" {
        resident_grpc_service_name(&parsed.path)
    } else if matches!(net.as_str(), "websocket" | "httpupgrade") {
        resident_stream_path(&parsed.path)
    } else {
        String::new()
    };
    let tls = if net == "grpc"
        || (matches!(net.as_str(), "websocket" | "httpupgrade") && parsed.tls == "tls")
    {
        "tls"
    } else {
        "none"
    };
    let server_name = if tls == "tls" {
        if parsed.sni.is_empty() {
            parsed.add.clone()
        } else {
            parsed.sni.clone()
        }
    } else {
        String::new()
    };
    let alpn = if net == "grpc" {
        vec!["h2".to_owned()]
    } else {
        Vec::new()
    };
    let utls_fingerprint = if tls == "tls" {
        resident_utls_fingerprint_plan(config, Some(parsed.fingerprint.as_str()))?
    } else {
        None
    };
    let graph = resident_graph_identity(&link);
    Ok(ResidentProxyPlan {
        graph_id: graph.graph_id,
        graph_link_hash: graph.link_hash,
        redacted_link_source: graph.redacted_link_source,
        protocol: "vmess".to_owned(),
        group_name,
        group_policy: String::new(),
        node_tag,
        server_host: parsed.add,
        server_port,
        server_name,
        alpn,
        flow: String::new(),
        net,
        stream_host,
        stream_path,
        tls: tls.to_owned(),
        allow_insecure: false,
        utls_fingerprint,
        handler: ResidentProxyProtocolPlan::VmessAeadTcp { id: parsed.id },
        chain_parent: None,
        mark: config.global.so_mark_from_dae,
        mptcp: config.global.mptcp,
    })
}

pub(super) fn build_resident_proxy_plan_for_node(
    config: &Config,
    group_name: String,
    node_tag: String,
    link: String,
) -> Result<ResidentProxyPlan, String> {
    build_proxy_plan(config, group_name, node_tag, link)
}

pub(super) fn resident_node_link_shapes(config: &Config) -> Vec<ResidentNodeLinkShape> {
    tagged_node_links(config)
        .into_iter()
        .map(|(tag, link)| ResidentNodeLinkShape {
            tag,
            scheme: link_scheme(&link).unwrap_or_default(),
            link,
        })
        .collect()
}

fn resident_utls_fingerprint_plan(
    config: &Config,
    link_fingerprint: Option<&str>,
) -> Result<Option<ResidentUtlsFingerprintPlan>, String> {
    let link_fingerprint = link_fingerprint.unwrap_or_default().trim();
    if !link_fingerprint.is_empty() && !link_fingerprint.eq_ignore_ascii_case("unsafe") {
        return resolve_optional_resident_utls_fingerprint("link fp", link_fingerprint);
    }
    if link_fingerprint.eq_ignore_ascii_case("unsafe") {
        return Ok(None);
    }

    if config
        .global
        .tls_implementation
        .trim()
        .eq_ignore_ascii_case("utls")
    {
        let global_fingerprint = config.global.utls_imitate.trim();
        if global_fingerprint.is_empty() {
            return resolve_resident_utls_fingerprint("default fingerprint", "chrome").map(Some);
        }
        return resolve_optional_resident_utls_fingerprint(
            "global utls_imitate",
            global_fingerprint,
        );
    }

    Ok(None)
}

fn resolve_optional_resident_utls_fingerprint(
    source: &'static str,
    requested: &str,
) -> Result<Option<ResidentUtlsFingerprintPlan>, String> {
    if requested.eq_ignore_ascii_case("unsafe") {
        return Ok(None);
    }
    resolve_resident_utls_fingerprint(source, requested).map(Some)
}

fn resolve_resident_utls_fingerprint(
    source: &'static str,
    requested: &str,
) -> Result<ResidentUtlsFingerprintPlan, String> {
    let fingerprint = resolve_utls_client_hello_id(requested)
        .map_err(|err| format!("resident dataplane unsupported {source} {requested}: {err}"))?;
    Ok(resident_utls_fingerprint_plan_from(
        source,
        requested,
        fingerprint,
    ))
}

fn resident_utls_fingerprint_plan_from(
    source: &'static str,
    requested: &str,
    fingerprint: UtlsFingerprint,
) -> ResidentUtlsFingerprintPlan {
    ResidentUtlsFingerprintPlan {
        source,
        requested: requested.to_owned(),
        name: fingerprint.name.to_owned(),
        canonical: fingerprint.canonical.to_owned(),
        family: fingerprint.family.to_owned(),
        client: fingerprint.client.to_owned(),
        randomized: fingerprint.randomized,
        alpn_policy: fingerprint.alpn_policy.to_owned(),
    }
}

fn parse_tcp_dial_mode(config: &Config) -> Result<TcpDialMode, String> {
    config
        .global
        .dial_mode
        .parse::<TcpDialMode>()
        .map_err(|err| format!("resident dataplane dial_mode: {err}"))
}

fn tcp_sniffing_timeout(config: &Config, dial_mode: TcpDialMode) -> Duration {
    if dial_mode == TcpDialMode::Ip {
        return Duration::ZERO;
    }
    let nanos = config.global.sniffing_timeout.as_nanos();
    if nanos <= 0 {
        Duration::ZERO
    } else {
        Duration::from_nanos(nanos as u64)
    }
}

fn referenced_user_outbounds(config: &Config) -> Vec<String> {
    let mut outbounds = Vec::new();
    for rule in &config.routing.rules {
        push_user_outbound(&mut outbounds, &rule.outbound.name);
    }
    match &config.routing.fallback {
        DynamicFunctionValue::String(name) => push_user_outbound(&mut outbounds, name),
        DynamicFunctionValue::Function(function) => {
            push_user_outbound(&mut outbounds, &function.name)
        }
        DynamicFunctionValue::FunctionList(functions) => {
            for function in functions {
                push_user_outbound(&mut outbounds, &function.name);
            }
        }
        DynamicFunctionValue::Nil => {}
    }
    outbounds
}

fn push_user_outbound(outbounds: &mut Vec<String>, name: &str) {
    if matches!(
        name,
        "direct" | "block" | "must_rules" | "logical_or" | "logical_and"
    ) {
        return;
    }
    if !outbounds.iter().any(|seen| seen == name) {
        outbounds.push(name.to_owned());
    }
}

fn select_group_nodes(
    group: &Group,
    node_links: &BTreeMap<String, String>,
) -> Result<GroupNodeSelection, String> {
    let (explicit_name_filter, unresolved_names) =
        unresolved_positive_name_filters(group, node_links);
    let filter_groups = outbound_filter_groups(group);
    let annotations = outbound_filter_annotations(group)?;
    let dialer_set = DialerSet {
        dialers: node_links
            .iter()
            .map(|(tag, link)| Dialer::new(tag.clone(), "").with_link(link.clone()))
            .collect(),
    };
    let matched = dialer_set
        .filter_and_annotate(&filter_groups, &annotations)
        .map_err(|err| format!("resident dataplane group {} filter: {err}", group.name))?;
    if matched.is_empty() {
        return Ok(GroupNodeSelection::NoCandidate {
            explicit_name_filter,
            unresolved_names,
        });
    }
    let mut nodes = Vec::with_capacity(matched.len());
    for (match_index, matched) in matched.into_iter().enumerate() {
        let link = node_links
            .get(&matched.name)
            .ok_or_else(|| {
                format!(
                    "group {} selected missing node {}",
                    group.name, matched.name
                )
            })?
            .clone();
        nodes.push(SelectedGroupNode {
            match_index,
            tag: matched.name,
            link,
            annotation_add_latency_ms: matched.annotation.add_latency_ms,
        });
    }
    Ok(GroupNodeSelection::Selected(nodes))
}

fn unresolved_positive_name_filters(
    group: &Group,
    node_links: &BTreeMap<String, String>,
) -> (bool, Vec<String>) {
    let mut unresolved_names = Vec::<String>::new();
    let mut explicit_name_filter = false;
    for filter in &group.filter {
        for function in filter {
            if function.name != "name" || function.not {
                continue;
            }
            explicit_name_filter = true;
            for param in &function.params {
                if param.key.is_empty() && !node_links.contains_key(&param.val) {
                    unresolved_names.push(param.val.clone());
                }
            }
        }
    }
    (explicit_name_filter, unresolved_names)
}

fn outbound_filter_groups(group: &Group) -> Vec<Vec<Filter>> {
    group
        .filter
        .iter()
        .map(|filters| filters.iter().map(outbound_filter).collect())
        .collect()
}

fn outbound_filter(function: &Function) -> Filter {
    Filter {
        name: function.name.clone(),
        not: function.not,
        params: function
            .params
            .iter()
            .map(|param| FilterParam::new(param.key.clone(), param.val.clone()))
            .collect(),
    }
}

fn outbound_filter_annotations(group: &Group) -> Result<Vec<Annotation>, String> {
    if group.filter.is_empty() {
        return Ok(Vec::new());
    }
    if group.filter_annotation.is_empty() {
        return Ok(vec![Annotation::default(); group.filter.len()]);
    }
    if group.filter_annotation.len() != group.filter.len() {
        return Err(format!(
            "unmatched filter annotation length: {} filters and {} annotations",
            group.filter.len(),
            group.filter_annotation.len()
        ));
    }
    group
        .filter_annotation
        .iter()
        .map(|params| match params {
            Some(params) => annotation_from_params(params),
            None => Ok(Annotation::default()),
        })
        .collect()
}

fn annotation_from_params(params: &[Param]) -> Result<Annotation, String> {
    let pairs = params
        .iter()
        .map(|param| (param.key.as_str(), param.val.as_str()))
        .collect::<Vec<_>>();
    Annotation::from_params(&pairs).map_err(|err| err.to_string())
}

fn parse_group_policy(policy: &DynamicFunctionValue) -> Result<ResidentGroupPolicyPlan, String> {
    match policy {
        DynamicFunctionValue::Nil => Ok(ResidentGroupPolicyPlan::Fixed { index: 0 }),
        DynamicFunctionValue::String(value) => parse_group_policy_string(value),
        DynamicFunctionValue::Function(function) => parse_group_policy_function(function),
        DynamicFunctionValue::FunctionList(functions) if functions.len() == 1 => {
            parse_group_policy_function(&functions[0])
        }
        DynamicFunctionValue::FunctionList(functions) => Err(format!(
            "policy should be exact 1 function: got {}",
            functions.len()
        )),
    }
}

fn parse_group_policy_string(value: &str) -> Result<ResidentGroupPolicyPlan, String> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(ResidentGroupPolicyPlan::Fixed { index: 0 });
    }
    if let Some(raw) = value
        .strip_prefix("fixed(")
        .and_then(|rest| rest.strip_suffix(')'))
    {
        let index = raw
            .trim()
            .parse::<usize>()
            .map_err(|err| format!("invalid fixed policy index {raw}: {err}"))?;
        return Ok(ResidentGroupPolicyPlan::Fixed { index });
    }
    match value {
        "fixed" => Ok(ResidentGroupPolicyPlan::Fixed { index: 0 }),
        "random" => Ok(ResidentGroupPolicyPlan::Random),
        "min" => Ok(ResidentGroupPolicyPlan::MinLastLatency),
        "min_avg10" | "min_average10" => Ok(ResidentGroupPolicyPlan::MinAverage10),
        "min_moving_avg" => Ok(ResidentGroupPolicyPlan::MinMovingAverage),
        other => Err(format!("unexpected policy: {other}")),
    }
}

fn parse_group_policy_function(function: &Function) -> Result<ResidentGroupPolicyPlan, String> {
    match function.name.as_str() {
        "fixed" => {
            if function.not {
                return Err("policy param does not support not operator: !fixed()".to_owned());
            }
            let Some(param) = function.params.first() else {
                return Ok(ResidentGroupPolicyPlan::Fixed { index: 0 });
            };
            if param.key != "" {
                return Err(r#"invalid "fixed" param format"#.to_owned());
            }
            let index = param
                .val
                .parse::<usize>()
                .map_err(|err| format!(r#"invalid "fixed" param format: {err}"#))?;
            Ok(ResidentGroupPolicyPlan::Fixed { index })
        }
        "random" => Ok(ResidentGroupPolicyPlan::Random),
        "min" => Ok(ResidentGroupPolicyPlan::MinLastLatency),
        "min_avg10" | "min_average10" => Ok(ResidentGroupPolicyPlan::MinAverage10),
        "min_moving_avg" => Ok(ResidentGroupPolicyPlan::MinMovingAverage),
        other => Err(format!("unexpected policy: {other}")),
    }
}

fn tagged_node_links(config: &Config) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for raw in &config.node {
        let (tag, link) = split_keyable_link(raw);
        if link.contains("://") {
            let tag = tag.unwrap_or_else(|| link.clone());
            out.insert(tag, link);
        }
    }
    out
}

fn link_scheme(link: &str) -> Option<String> {
    link.split_once("://")
        .map(|(scheme, _)| scheme.to_ascii_lowercase())
}

fn split_keyable_link(raw: &str) -> (Option<String>, String) {
    let trimmed = raw.trim();
    let Some(scheme_pos) = trimmed.find("://") else {
        return (None, unquote_config_value(trimmed));
    };
    let before_scheme = &trimmed[..scheme_pos];
    if let Some(colon) = before_scheme.rfind(':') {
        let tag = unquote_config_value(&trimmed[..colon]);
        let link = unquote_config_value(&trimmed[colon + 1..]);
        if !tag.is_empty() {
            return (Some(tag), link);
        }
    }
    (None, unquote_config_value(trimmed))
}

fn unquote_config_value(value: &str) -> String {
    let value = value.trim();
    if value.len() >= 2 {
        let bytes = value.as_bytes();
        if (bytes[0] == b'\'' && bytes[value.len() - 1] == b'\'')
            || (bytes[0] == b'"' && bytes[value.len() - 1] == b'"')
        {
            return value[1..value.len() - 1].to_owned();
        }
    }
    value.to_owned()
}

fn split_alpn(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(str::to_owned)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use dae_outbound::shadowsocks::Sip003;

    fn assert_protocol_matrix_source_uses_generic_semantics(source: &str) {
        let lower = source.to_ascii_lowercase();
        let forbidden_terms = [
            ["matrix", "-"].concat(),
            ["invalid", "-", "test", "-", "format"].concat(),
        ];
        for forbidden in forbidden_terms {
            assert!(
                !lower.contains(&forbidden),
                "protocol matrix source fixtures must use protocol-generic semantics, found {forbidden}"
            );
        }
        for link in url_like_source_literals(source) {
            assert_resident_source_fixture_uses_generic_semantics(&link);
        }
    }

    #[test]
    fn protocol_matrix_source_fixtures_use_generic_semantics() {
        assert_protocol_matrix_source_uses_generic_semantics(include_str!("plan.rs"));
    }

    fn url_like_source_literals(source: &str) -> Vec<String> {
        let mut links = Vec::new();
        let mut offset = 0;
        while let Some(relative_pos) = source[offset..].find("://") {
            let scheme_end = offset + relative_pos;
            let mut start = scheme_end;
            while start > 0 {
                let previous = source.as_bytes()[start - 1];
                if previous.is_ascii_alphanumeric() || matches!(previous, b'+' | b'-' | b'.') {
                    start -= 1;
                } else {
                    break;
                }
            }

            let mut end = scheme_end + 3;
            while end < source.len() {
                let next = source.as_bytes()[end];
                if next.is_ascii_whitespace()
                    || matches!(next, b'"' | b'\'' | b'`' | b'<' | b'>' | b')' | b']')
                {
                    break;
                }
                end += 1;
            }

            links.push(source[start..end].to_owned());
            offset = end;
        }
        links
    }

    fn assert_resident_source_fixture_uses_generic_semantics(link: &str) {
        let lower = link.to_ascii_lowercase();
        let forbidden_terms = [
            ["matrix", "-"].concat(),
            ["invalid", "-", "test", "-", "format"].concat(),
        ];
        for forbidden in forbidden_terms {
            assert!(
                !lower.contains(&forbidden),
                "source fixture must use common import semantics, found {forbidden} in {link}"
            );
        }
        assert!(
            !link.contains('#'),
            "source fixture must not use fragment labels as matrix evidence: {link}"
        );
        if let Some(userinfo) = source_link_userinfo(link) {
            let lower_userinfo = userinfo.to_ascii_lowercase();
            for forbidden in ["matrix", "-password", "-auth"] {
                assert!(
                    !lower_userinfo.contains(forbidden),
                    "source fixture userinfo must be protocol-generic, found {forbidden} in {link}"
                );
            }
        }
    }

    fn source_link_userinfo(link: &str) -> Option<&str> {
        let authority = link.split_once("://")?.1;
        let authority = authority.split(['/', '?', '#']).next().unwrap_or(authority);
        authority.rsplit_once('@').map(|(userinfo, _)| userinfo)
    }

    fn parse_config(input: &str) -> Config {
        let sections = dae_config::parser::parse_config(input).unwrap();
        dae_config::schema::build_config(&sections).unwrap()
    }

    fn shadowsocks_fixture_url(_ps: &str, add: &str, port: u16) -> String {
        ShadowsocksLink {
            name: String::new(),
            server: add.to_owned(),
            port,
            password: "password".to_owned(),
            cipher: "aes-128-gcm".to_owned(),
            plugin: Sip003::default(),
            udp: true,
            protocol: "shadowsocks".to_owned(),
        }
        .export_url()
    }

    fn shadowsocks_plugin_fixture_url(_ps: &str, add: &str, port: u16) -> String {
        ShadowsocksLink {
            name: String::new(),
            server: add.to_owned(),
            port,
            password: "password".to_owned(),
            cipher: "aes-128-gcm".to_owned(),
            plugin: Sip003::parse("simple-obfs;obfs=http"),
            udp: false,
            protocol: "shadowsocks".to_owned(),
        }
        .export_url()
    }

    fn shadowsocks_simple_obfs_tls_fixture_url(_ps: &str, add: &str, port: u16) -> String {
        ShadowsocksLink {
            name: String::new(),
            server: add.to_owned(),
            port,
            password: "password".to_owned(),
            cipher: "aes-128-gcm".to_owned(),
            plugin: Sip003::parse("simple-obfs;obfs=tls"),
            udp: false,
            protocol: "shadowsocks".to_owned(),
        }
        .export_url()
    }

    fn shadowsocks_v2ray_plugin_tls_fixture_url(_ps: &str, add: &str, port: u16) -> String {
        format!(
            "ss://aes-128-gcm:password@{add}:{port}?plugin=v2ray-plugin%3Btls%3Bobfs-host%3Dfront.example%3Bobfs-uri%3D%2Fss"
        )
    }

    fn shadowsocks_2022_simple_obfs_http_fixture_url(_ps: &str, add: &str, port: u16) -> String {
        format!(
            "ss://2022-blake3-aes-128-gcm:MTIzNDU2Nzg5MDEyMzQ1Ng%3D%3D@{add}:{port}?plugin=simple-obfs%3Bobfs%3Dhttp%3Bobfs-host%3Dfront.example%3Bobfs-uri%3D%2F"
        )
    }

    fn shadowsocks_unsupported_plugin_fixture_url(_ps: &str, add: &str, port: u16) -> String {
        format!("ss://aes-128-gcm:password@{add}:{port}?plugin=unknown-plugin")
    }

    fn vless_fixture_url(
        _ps: &str,
        add: &str,
        port: u16,
        net: &str,
        host: &str,
        path: &str,
        sni: &str,
        flow: &str,
        fingerprint: &str,
    ) -> String {
        VLESSLink {
            ps: String::new(),
            add: add.to_owned(),
            port: port.to_string(),
            id: "01234567-89ab-cdef-0123-456789abcdef".to_owned(),
            net: net.to_owned(),
            r#type: "none".to_owned(),
            host: host.to_owned(),
            sni: sni.to_owned(),
            path: path.to_owned(),
            xhttp_mode: String::new(),
            xhttp_extra: String::new(),
            tls: "tls".to_owned(),
            flow: flow.to_owned(),
            alpn: String::new(),
            allow_insecure: false,
            fingerprint: fingerprint.to_owned(),
            public_key: String::new(),
            short_id: String::new(),
            spider_x: String::new(),
            protocol: "vless".to_owned(),
        }
        .export_url()
    }

    fn vless_xhttp_parser_fixture_url(mode: &str, alpn: &str, extra: &str) -> String {
        VLESSLink {
            ps: String::new(),
            add: "198.51.100.10".to_owned(),
            port: "443".to_owned(),
            id: "7c12c745-63a5-433d-9e60-022e469b5bd4".to_owned(),
            net: "xhttp".to_owned(),
            r#type: "none".to_owned(),
            host: "edge.transport.invalid".to_owned(),
            sni: "edge.transport.invalid".to_owned(),
            path: "/resource?ed=2048".to_owned(),
            xhttp_mode: mode.to_owned(),
            xhttp_extra: extra.to_owned(),
            tls: "tls".to_owned(),
            flow: String::new(),
            alpn: alpn.to_owned(),
            allow_insecure: false,
            fingerprint: String::new(),
            public_key: String::new(),
            short_id: String::new(),
            spider_x: String::new(),
            protocol: "vless".to_owned(),
        }
        .export_url()
    }

    fn trojan_fixture_url(_ps: &str, add: &str, port: u16) -> String {
        TrojanLink {
            name: String::new(),
            server: add.to_owned(),
            port,
            password: "password".to_owned(),
            sni: "office.example".to_owned(),
            transport_type: String::new(),
            encryption: String::new(),
            host: String::new(),
            path: String::new(),
            service_name: String::new(),
            allow_insecure: false,
            protocol: "trojan".to_owned(),
        }
        .export_url()
    }

    fn trojan_websocket_fixture_url(_ps: &str, add: &str, port: u16) -> String {
        TrojanLink {
            name: String::new(),
            server: add.to_owned(),
            port,
            password: "password".to_owned(),
            sni: "office.example".to_owned(),
            transport_type: "ws".to_owned(),
            encryption: String::new(),
            host: "front.example".to_owned(),
            path: "/trojan".to_owned(),
            service_name: String::new(),
            allow_insecure: false,
            protocol: "trojan-go".to_owned(),
        }
        .export_url()
    }

    fn trojan_httpupgrade_fixture_url(_ps: &str, add: &str, port: u16) -> String {
        TrojanLink {
            name: String::new(),
            server: add.to_owned(),
            port,
            password: "password".to_owned(),
            sni: "office.example".to_owned(),
            transport_type: "httpupgrade".to_owned(),
            encryption: String::new(),
            host: "front.example".to_owned(),
            path: "/trojan-upgrade".to_owned(),
            service_name: String::new(),
            allow_insecure: false,
            protocol: "trojan-go".to_owned(),
        }
        .export_url()
    }

    fn trojan_grpc_fixture_url(_ps: &str, add: &str, port: u16) -> String {
        TrojanLink {
            name: String::new(),
            server: add.to_owned(),
            port,
            password: "password".to_owned(),
            sni: "office.example".to_owned(),
            transport_type: "grpc".to_owned(),
            encryption: String::new(),
            host: "front.example".to_owned(),
            path: String::new(),
            service_name: "TrojanGunService".to_owned(),
            allow_insecure: false,
            protocol: "trojan-go".to_owned(),
        }
        .export_url()
    }

    fn hysteria2_fixture_url(_ps: &str, add: &str, port: u16) -> String {
        hysteria2_fixture_url_with_pin("", &format!("{add}:{port}"), "AA-BB-CC")
    }

    fn hysteria2_fixture_url_with_pin(_ps: &str, server: &str, pin_sha256: &str) -> String {
        Hysteria2Link {
            name: String::new(),
            user: "auth-token".to_owned(),
            password: String::new(),
            server: server.to_owned(),
            insecure: false,
            sni: "office.example".to_owned(),
            pin_sha256: pin_sha256.to_owned(),
            max_tx: 0,
            max_rx: 0,
        }
        .export_url()
    }

    fn tuic_fixture_url(_ps: &str, add: &str, port: u16, allow_insecure: bool) -> String {
        TuicLink {
            name: String::new(),
            user: "01234567-89ab-cdef-0123-456789abcdef".to_owned(),
            password: "password".to_owned(),
            server: add.to_owned(),
            port,
            sni: "office.example".to_owned(),
            allow_insecure,
            disable_sni: false,
            congestion_control: String::new(),
            alpn: vec!["h3".to_owned()],
            udp_relay_mode: String::new(),
            protocol: "tuic".to_owned(),
        }
        .export_url()
    }

    fn juicity_fixture_url(_ps: &str, add: &str, port: u16, allow_insecure: bool) -> String {
        JuicityLink {
            name: String::new(),
            user: "01234567-89ab-cdef-0123-456789abcdef".to_owned(),
            password: "password".to_owned(),
            server: add.to_owned(),
            port,
            sni: "office.example".to_owned(),
            allow_insecure,
            congestion_control: String::new(),
            pinned_certchain_sha256: String::new(),
            protocol: "juicity".to_owned(),
        }
        .export_url()
    }

    fn vmess_fixture_url(
        _ps: &str,
        add: &str,
        port: u16,
        net: &str,
        host: &str,
        path: &str,
        tls: &str,
    ) -> String {
        vmess_fixture_url_with_sni(add, port, net, host, path, tls, "")
    }

    fn vmess_fixture_url_with_sni(
        add: &str,
        port: u16,
        net: &str,
        host: &str,
        path: &str,
        tls: &str,
        sni: &str,
    ) -> String {
        VMessLink {
            ps: String::new(),
            add: add.to_owned(),
            port: port.to_string(),
            id: "01234567-89ab-cdef-0123-456789abcdef".to_owned(),
            aid: "0".to_owned(),
            net: net.to_owned(),
            r#type: "none".to_owned(),
            host: host.to_owned(),
            sni: sni.to_owned(),
            path: path.to_owned(),
            tls: tls.to_owned(),
            allow_insecure: false,
            fingerprint: String::new(),
            v: "2".to_owned(),
            protocol: "vmess".to_owned(),
        }
        .export_url()
    }

    fn vmess_legacy_fixture_url() -> String {
        "vmess://YXV0bzowMTIzNDU2Ny04OWFiLWNkZWYtMDEyMy00NTY3ODlhYmNkZWZAMjAzLjAuMTEzLjEwOjI4NDUy?alterId=0&obfs=tcp"
            .to_owned()
    }

    fn resident_admitted_source_fixture_links() -> Vec<String> {
        vec![
            "socks5://user:password@proxy.example.net:1080".to_owned(),
            "http://user:password@proxy.example.net:80".to_owned(),
            "https://user:password@secure-proxy.example.net:443".to_owned(),
            shadowsocks_fixture_url("ss", "203.0.113.10", 28446),
            shadowsocks_plugin_fixture_url("ss-plugin", "203.0.113.10", 28447),
            trojan_fixture_url("trojan", "203.0.113.10", 28444),
            trojan_websocket_fixture_url("trojan-ws", "203.0.113.10", 28456),
            "anytls://password@secure-stream.example.net:443?sni=secure-stream.example.net"
                .to_owned(),
            vmess_fixture_url("vmess", "203.0.113.10", 28452, "tcp", "", "", ""),
            vmess_fixture_url(
                "vmess-ws",
                "203.0.113.10",
                28454,
                "ws",
                "front.example",
                "/vmess",
                "",
            ),
            vmess_fixture_url_with_sni(
                "203.0.113.10",
                28454,
                "ws",
                "front.example",
                "/vmess",
                "tls",
                "office.example",
            ),
            vmess_fixture_url_with_sni(
                "203.0.113.10",
                28460,
                "httpupgrade",
                "front.example",
                "/vmess-upgrade",
                "tls",
                "office.example",
            ),
            vless_fixture_url(
                "vless-ws",
                "203.0.113.10",
                28443,
                "ws",
                "front.example",
                "/ws",
                "office.example",
                "",
                "",
            ),
            hysteria2_fixture_url("hy2", "203.0.113.10", 28453),
            hysteria2_fixture_url_with_pin("hy2-hop", "203.0.113.10:28453,28454-28455", "AA-BB-CC"),
            tuic_fixture_url("tuic", "203.0.113.10", 28454, true),
            tuic_fixture_url("tuic-verified", "203.0.113.10", 28454, false),
            juicity_fixture_url("juicity", "203.0.113.10", 28455, true),
        ]
    }

    fn assert_common_source_import_round_trips(link: &str) {
        let scheme = link
            .split_once("://")
            .map(|(scheme, _)| scheme)
            .unwrap_or_default();
        match scheme {
            "socks" | "socks5" => {
                let parsed = Url::parse(link).unwrap();
                assert!(parsed.has_host(), "{link}");
                assert!(parsed.port().is_some(), "{link}");
                assert!(!parsed.username().is_empty(), "{link}");
            }
            "http" | "https" => {
                assert_eq!(HttpProxyLink::parse(link).unwrap().export_url(), link);
            }
            "ss" => {
                assert_eq!(ShadowsocksLink::parse(link).unwrap().export_url(), link);
            }
            "trojan" | "trojan-go" => {
                assert_eq!(TrojanLink::parse(link).unwrap().export_url(), link);
            }
            "anytls" => {
                assert_eq!(AnyTLSLink::parse(link).unwrap().export_url(), link);
            }
            "vmess" => {
                assert_eq!(VMessLink::parse(link).unwrap().export_url(), link);
            }
            "vless" => {
                assert_eq!(VLESSLink::parse(link).unwrap().export_url(), link);
            }
            "hysteria2" | "hy2" => {
                assert_eq!(Hysteria2Link::parse(link).unwrap().export_url(), link);
            }
            "tuic" => {
                assert_eq!(TuicLink::parse(link).unwrap().export_url(), link);
            }
            "juicity" => {
                assert_eq!(JuicityLink::parse(link).unwrap().export_url(), link);
            }
            other => panic!("unexpected resident source fixture scheme {other}: {link}"),
        }
    }

    #[test]
    fn resident_admitted_source_fixtures_use_common_canonical_formats() {
        let links = resident_admitted_source_fixture_links();
        assert!(links.len() >= 10);
        for link in links {
            assert_resident_source_fixture_uses_generic_semantics(&link);
            assert_common_source_import_round_trips(&link);
        }
    }

    #[test]
    fn resident_legacy_import_normalizes_to_current_executor() {
        let config = parse_config(
            r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        }
        routing {
        fallback: direct
        }
        "#,
        );
        let legacy = vmess_legacy_fixture_url();
        assert_resident_source_fixture_uses_generic_semantics(&legacy);
        let normalized = VMessLink::parse(&legacy).unwrap().export_url();
        assert_ne!(normalized, legacy);
        let proxy = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "legacy_import".to_owned(),
            legacy,
        )
        .unwrap();
        assert_eq!(proxy.protocol, "vmess");
        assert_eq!(proxy.net, "tcp");
        assert!(matches!(
            proxy.handler,
            ResidentProxyProtocolPlan::VmessAeadTcp { .. }
        ));
    }

    #[test]
    fn resident_dataplane_plan_selects_vless_group_node() {
        let config = parse_config(
            r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        }
        node {
        vless_live: 'vless://01234567-89ab-cdef-0123-456789abcdef@156.246.90.2:443?security=tls&type=tcp&sni=office.example&flow=xtls-rprx-vision&alpn=h2,http/1.1'
        }
        group {
        proxy {
            filter: name(vless_live)
            policy: fixed(0)
        }
        }
        routing {
        pname(dae) -> must_direct
        l4proto(tcp) && dport(443) -> proxy
        fallback: direct
        }
        "#,
        );
        let plan = build_resident_dataplane_plan(&config).unwrap();
        let proxy = plan.default_proxy_snapshot().unwrap();
        assert!(plan.enabled);
        assert_eq!(plan.proxies.len(), 1);
        assert_eq!(proxy.group_name, "proxy");
        assert_eq!(proxy.node_tag, "vless_live");
        assert_eq!(proxy.server_host, "156.246.90.2");
        assert_eq!(proxy.server_port, 443);
        assert_eq!(proxy.server_name, "office.example");
        assert_eq!(proxy.flow, "xtls-rprx-vision");
        assert_eq!(proxy.alpn, ["h2", "http/1.1"]);
        assert_eq!(proxy.mark, 1234);
    }

    #[test]
    fn group_node_selection_keeps_fixed_policy_order() {
        let config = parse_config(
            r#"
        global {
        lan_interface: daerust0
        }
        node {
        node_a: 'socks://127.0.0.1:1080'
        node_b: 'socks://127.0.0.1:1081'
        }
        group {
        proxy {
            filter: name(node_a, node_b)
            policy: fixed(1)
        }
        }
        routing {
        l4proto(tcp) -> proxy
        fallback: direct
        }
        "#,
        );
        let links = tagged_node_links(&config);
        let selected = select_group_nodes(&config.group[0], &links).unwrap();
        match selected {
            GroupNodeSelection::Selected(nodes) => {
                assert_eq!(nodes.len(), 2);
                assert_eq!(nodes[0].tag, "node_a");
                assert_eq!(nodes[0].link, "socks://127.0.0.1:1080");
                assert_eq!(nodes[1].tag, "node_b");
                assert_eq!(nodes[1].link, "socks://127.0.0.1:1081");
            }
            GroupNodeSelection::NoCandidate { .. } => panic!("expected selected node"),
        }
        let plan = build_resident_dataplane_plan(&config).unwrap();
        let proxy = plan.default_proxy_snapshot().unwrap();
        assert_eq!(proxy.node_tag, "node_b");
        assert_eq!(plan.default_proxy_group().unwrap().candidate_count(), 2);
    }

    #[test]
    fn group_node_selection_supports_generic_name_filters() {
        let config = parse_config(
            r#"
        global {
        lan_interface: daerust0
        }
        node {
        node_a: 'socks://127.0.0.1:1080'
        node_b: 'socks://127.0.0.1:1081'
        node_c: 'socks://127.0.0.1:1082'
        }
        group {
        proxy {
            filter: name(regex: "^node_[ab]$") && !name(node_b)
            policy: random
        }
        }
        routing {
        l4proto(tcp) -> proxy
        fallback: direct
        }
        "#,
        );
        let links = tagged_node_links(&config);
        let selected = select_group_nodes(&config.group[0], &links).unwrap();
        match selected {
            GroupNodeSelection::Selected(nodes) => {
                assert_eq!(nodes.len(), 1);
                assert_eq!(nodes[0].tag, "node_a");
            }
            GroupNodeSelection::NoCandidate { .. } => panic!("expected selected node"),
        }
    }

    #[test]
    fn resident_dataplane_plan_keeps_non_fixed_group_candidates() {
        let config = parse_config(
            r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        }
        node {
        node_a: 'socks://127.0.0.1:1080'
        node_b: 'socks://127.0.0.1:1081'
        }
        group {
        proxy {
            filter: name(node_a, node_b)
            policy: random
        }
        }
        routing {
        l4proto(tcp) -> proxy
        fallback: direct
        }
        "#,
        );
        let plan = build_resident_dataplane_plan(&config).unwrap();
        let group = plan.default_proxy_group().unwrap();
        assert_eq!(group.group_policy, ResidentGroupPolicyPlan::Random);
        assert_eq!(group.candidate_count(), 2);
        assert_eq!(group.admitted_candidate_count(), 2);
        assert!(group.alive_state_wired());
        let selected = group.select_proxy_for_tcp().unwrap();
        assert!(matches!(selected.node_tag.as_str(), "node_a" | "node_b"));
    }

    #[test]
    fn resident_dataplane_plan_wires_min_policy_latency_state() {
        let config = parse_config(
            r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        }
        node {
        node_a: 'socks://127.0.0.1:1080'
        node_b: 'socks://127.0.0.1:1081'
        }
        group {
        proxy {
            filter: name(node_a, node_b)
            policy: min_moving_avg
        }
        }
        routing {
        l4proto(tcp) -> proxy
        fallback: direct
        }
        "#,
        );
        let plan = build_resident_dataplane_plan(&config).unwrap();
        let group = plan.default_proxy_group().unwrap();
        assert_eq!(
            group.group_policy,
            ResidentGroupPolicyPlan::MinMovingAverage
        );
        assert_eq!(group.candidate_count(), 2);
        assert_eq!(group.admitted_candidate_count(), 2);
        assert!(group.alive_state_wired());
        assert!(group.latency_state_wired());
        assert_eq!(group.select_proxy_for_tcp().unwrap().node_tag, "node_a");
    }

    #[test]
    fn resident_dataplane_group_tcp_check_uses_group_override() {
        let config = parse_config(
            r#"
        global {
        lan_interface: daerust0
        tcp_check_url: 'http://global.example/generate_204'
        tcp_check_http_method: GET
        }
        node {
        node_a: 'socks://127.0.0.1:1080'
        node_b: 'socks://127.0.0.1:1081'
        }
        group {
        proxy {
            filter: name(node_a, node_b)
            policy: min
            tcp_check_url: 'http://group.example/check?q=1'
            tcp_check_http_method: HEAD
        }
        }
        routing {
        l4proto(tcp) -> proxy
        fallback: direct
        }
        "#,
        );
        let plan = build_resident_dataplane_plan(&config).unwrap();
        let group = plan.default_proxy_group().unwrap();
        let probes = group.probe_candidates();
        assert_eq!(probes[0].tcp_check.scheme, "http");
        assert_eq!(probes[0].tcp_check.target, "group.example:80");
        assert_eq!(probes[0].tcp_check.host, "group.example");
        assert_eq!(probes[0].tcp_check.path, "/check?q=1");
        assert_eq!(probes[0].tcp_check.method, "HEAD");
    }

    #[test]
    fn resident_dataplane_group_tcp_check_accepts_https() {
        let config = parse_config(
            r#"
        global {
        lan_interface: daerust0
        }
        node {
        node_a: 'socks://127.0.0.1:1080'
        }
        group {
        proxy {
            filter: name(node_a)
            policy: min
            tcp_check_url: 'https://check.example/generate_204,203.0.113.7'
        }
        }
        routing {
        l4proto(tcp) -> proxy
        fallback: direct
        }
        "#,
        );
        let plan = build_resident_dataplane_plan(&config).unwrap();
        let probes = plan.default_proxy_group().unwrap().probe_candidates();
        assert_eq!(probes[0].tcp_check.scheme, "https");
        assert_eq!(probes[0].tcp_check.target, "203.0.113.7:443");
        assert_eq!(probes[0].tcp_check.host, "check.example");
        assert_eq!(probes[0].tcp_check.path, "/generate_204");
    }

    #[test]
    fn resident_manual_probe_plans_cover_all_admitted_config_nodes() {
        let config = parse_config(
            r#"
        global {
        lan_interface: daerust0
        tcp_check_url: 'http://check.example/generate_204,203.0.113.7'
        tcp_check_http_method: GET
        }
        node {
        grouped: 'socks://127.0.0.1:1080'
        orphan: 'socks://127.0.0.1:1081'
        unsupported: 'wireguard://198.51.100.2:51820'
        }
        group {
        proxy {
            filter: name(grouped)
            policy: fixed
        }
        }
        routing {
        l4proto(tcp) -> proxy
        fallback: direct
        }
        "#,
        );
        let plans = build_resident_manual_probe_plans(&config);
        let orphan = plans
            .get("socks://127.0.0.1:1081")
            .expect("orphan node should be indexed")
            .as_ref()
            .expect("orphan socks node should be admitted");
        assert_eq!(orphan.node_tag, "orphan");
        assert_eq!(orphan.tcp_check.method, "GET");
        assert_eq!(orphan.tcp_check.target, "203.0.113.7:80");
        assert_eq!(orphan.tcp_check.host, "check.example");
        assert!(
            plans
                .get("wireguard://198.51.100.2:51820")
                .expect("unsupported node should be indexed")
                .is_err()
        );
    }

    #[test]
    fn resident_dataplane_group_udp_check_uses_group_override_ipv4() {
        let config = parse_config(
            r#"
        global {
        lan_interface: daerust0
        udp_check_dns: 'dns.global:53,8.8.8.8'
        }
        node {
        node_a: 'socks://127.0.0.1:1080'
        }
        group {
        proxy {
            filter: name(node_a)
            policy: min
            udp_check_dns: 'dns.group:5353,8.8.4.4'
        }
        }
        routing {
        l4proto(udp) -> proxy
        fallback: direct
        }
        "#,
        );
        let plan = build_resident_dataplane_plan(&config).unwrap();
        let probes = plan.default_proxy_group().unwrap().probe_candidates();
        assert_eq!(
            probes[0].udp_check.target,
            SocketAddrV4::new(Ipv4Addr::new(8, 8, 4, 4), 5353)
        );
        assert_eq!(probes[0].udp_check.host, "dns.group");
        assert_eq!(
            probes[0].udp_check.lookup_host,
            "connectivitycheck.gstatic.com."
        );
    }

    #[test]
    fn resident_dataplane_min_policy_selects_checked_lowest_last_latency() {
        let config = parse_config(
            r#"
        global {
        lan_interface: daerust0
        }
        node {
        node_a: 'socks://127.0.0.1:1080'
        node_b: 'socks://127.0.0.1:1081'
        }
        group {
        proxy {
            filter: name(node_a, node_b)
            policy: min
        }
        }
        routing {
        l4proto(tcp) -> proxy
        fallback: direct
        }
        "#,
        );
        let plan = build_resident_dataplane_plan(&config).unwrap();
        let group = plan.default_proxy_group().unwrap();
        group
            .record_check_result("node_a", NetworkType::TCP4, Some(200), 1)
            .unwrap();
        group
            .record_check_result("node_b", NetworkType::TCP4, Some(50), 2)
            .unwrap();
        assert_eq!(group.select_proxy_for_tcp().unwrap().node_tag, "node_b");
    }

    #[test]
    fn resident_dataplane_min_avg10_policy_uses_latency_history() {
        let config = parse_config(
            r#"
        global {
        lan_interface: daerust0
        }
        node {
        node_a: 'socks://127.0.0.1:1080'
        node_b: 'socks://127.0.0.1:1081'
        }
        group {
        proxy {
            filter: name(node_a, node_b)
            policy: min_avg10
        }
        }
        routing {
        l4proto(tcp) -> proxy
        fallback: direct
        }
        "#,
        );
        let plan = build_resident_dataplane_plan(&config).unwrap();
        let group = plan.default_proxy_group().unwrap();
        for latency in [300, 300, 300] {
            group
                .record_check_result("node_a", NetworkType::TCP4, Some(latency), 1)
                .unwrap();
        }
        for latency in [120, 120, 120] {
            group
                .record_check_result("node_b", NetworkType::TCP4, Some(latency), 2)
                .unwrap();
        }
        assert_eq!(group.select_proxy_for_tcp().unwrap().node_tag, "node_b");
    }

    #[test]
    fn resident_dataplane_min_moving_avg_policy_uses_moving_average() {
        let config = parse_config(
            r#"
        global {
        lan_interface: daerust0
        }
        node {
        node_a: 'socks://127.0.0.1:1080'
        node_b: 'socks://127.0.0.1:1081'
        }
        group {
        proxy {
            filter: name(node_a, node_b)
            policy: min_moving_avg
        }
        }
        routing {
        l4proto(tcp) -> proxy
        fallback: direct
        }
        "#,
        );
        let plan = build_resident_dataplane_plan(&config).unwrap();
        let group = plan.default_proxy_group().unwrap();
        group
            .record_check_result("node_a", NetworkType::TCP4, Some(240), 1)
            .unwrap();
        group
            .record_check_result("node_b", NetworkType::TCP4, Some(80), 2)
            .unwrap();
        assert_eq!(group.select_proxy_for_tcp().unwrap().node_tag, "node_b");
    }

    #[test]
    fn resident_dataplane_min_policy_honors_group_check_tolerance() {
        let config = parse_config(
            r#"
        global {
        lan_interface: daerust0
        check_tolerance: 10ms
        }
        node {
        node_a: 'socks://127.0.0.1:1080'
        node_b: 'socks://127.0.0.1:1081'
        }
        group {
        proxy {
            filter: name(node_a, node_b)
            policy: min
            check_tolerance: 50ms
        }
        }
        routing {
        l4proto(tcp) -> proxy
        fallback: direct
        }
        "#,
        );
        let plan = build_resident_dataplane_plan(&config).unwrap();
        let group = plan.default_proxy_group().unwrap();
        group
            .record_check_result("node_a", NetworkType::TCP4, Some(100), 1)
            .unwrap();
        group
            .record_check_result("node_b", NetworkType::TCP4, Some(80), 2)
            .unwrap();
        assert_eq!(group.select_proxy_for_tcp().unwrap().node_tag, "node_a");
        group
            .record_check_result("node_b", NetworkType::TCP4, Some(40), 3)
            .unwrap();
        assert_eq!(group.select_proxy_for_tcp().unwrap().node_tag, "node_b");
    }

    #[test]
    fn resident_dataplane_min_policy_applies_add_latency_to_sorting_only() {
        let config = parse_config(
            r#"
        global {
        lan_interface: daerust0
        }
        node {
        node_a: 'socks://127.0.0.1:1080'
        node_b: 'socks://127.0.0.1:1081'
        }
        group {
        proxy {
            filter: name(node_a) [add_latency: 100ms]
            filter: name(node_b)
            policy: min
        }
        }
        routing {
        l4proto(tcp) -> proxy
        fallback: direct
        }
        "#,
        );
        let plan = build_resident_dataplane_plan(&config).unwrap();
        let group = plan.default_proxy_group().unwrap();
        assert_eq!(group.annotation_latency_offset_count(), 1);
        group
            .record_check_result("node_a", NetworkType::TCP4, Some(50), 1)
            .unwrap();
        group
            .record_check_result("node_b", NetworkType::TCP4, Some(90), 2)
            .unwrap();
        assert_eq!(group.select_proxy_for_tcp().unwrap().node_tag, "node_b");
    }

    #[test]
    fn resident_dataplane_plan_keeps_fixed_from_building_unselected_candidate() {
        let unsupported = vless_xhttp_parser_fixture_url("packet-up", "h3", "");
        let config_text = r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        }
        node {
        node_a: 'socks://127.0.0.1:1080'
        unsupported: '__UNSUPPORTED_SOURCE__'
        }
        group {
        proxy {
            filter: name(node_a, unsupported)
            policy: fixed(0)
        }
        }
        routing {
        l4proto(tcp) -> proxy
        fallback: direct
        }
        "#
        .replace("__UNSUPPORTED_SOURCE__", &unsupported);
        let config = parse_config(&config_text);
        let plan = build_resident_dataplane_plan(&config).unwrap();
        let group = plan.default_proxy_group().unwrap();
        assert_eq!(group.candidate_count(), 2);
        assert_eq!(group.admitted_candidate_count(), 1);
        assert_eq!(group.select_proxy_for_tcp().unwrap().node_tag, "node_a");
    }

    #[test]
    fn resident_dataplane_plan_does_not_fallback_unresolved_name_filter_to_static_ss_node() {
        let candidate = vless_xhttp_parser_fixture_url("packet-up", "h3", "");
        let config_text = r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        }
        node {
        _022: 'ss://2022-blake3-aes-128-gcm:MTIzNDU2Nzg5MDEyMzQ1Ng==@217.116.171.227:25868'
        candidate: '__CANDIDATE_SOURCE__'
        }
        group {
        proxy {
            filter: name(node_17)
            policy: fixed
        }
        }
        routing {
        l4proto(tcp) && dport(443) -> proxy
        fallback: direct
        }
        "#
        .replace("__CANDIDATE_SOURCE__", &candidate);
        let config = parse_config(&config_text);
        let err = build_resident_dataplane_plan(&config).unwrap_err();
        assert!(err.contains("cannot resolve group proxy name filter node(s): node_17"));
        assert!(!err.contains("parse VLESS node _022"));
    }

    #[test]
    fn resident_dataplane_plan_admits_shadowsocks_2022_cipher_family() {
        let config = parse_config(
            r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        }
        node {
        ss_live: 'ss://2022-blake3-aes-128-gcm:MTIzNDU2Nzg5MDEyMzQ1Ng==@217.116.171.227:25868'
        }
        group {
        proxy {
            filter: name(ss_live)
            policy: fixed(0)
        }
        }
        routing {
        l4proto(tcp) && dport(443) -> proxy
        fallback: direct
        }
        "#,
        );
        let plan = build_resident_dataplane_plan(&config).unwrap();
        let proxy = plan
            .default_proxy_group()
            .unwrap()
            .select_proxy_for_tcp()
            .unwrap();
        assert_eq!(proxy.node_tag, "ss_live");
        assert_eq!(proxy.protocol, "shadowsocks");
        assert_eq!(proxy.tls, "aead-2022");
        assert_eq!(
            proxy.executable_graph_value()["packetSemantics"],
            "datagram-aead-2022"
        );
        assert!(matches!(
            proxy.handler,
            ResidentProxyProtocolPlan::Shadowsocks2022Tcp {
                salt_len: 16,
                packet_nonce_len: 0,
                ..
            }
        ));
    }

    #[test]
    fn resident_dataplane_plan_admits_resident_tcp_handlers() {
        let config = parse_config(
            r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        }
        routing {
        fallback: direct
        }
        "#,
        );
        let socks = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "socks_live".to_owned(),
            "socks5://user:password@proxy.example.net:1080".to_owned(),
        )
        .unwrap();
        assert_eq!(socks.protocol, "socks5");
        assert_eq!(socks.server_host, "proxy.example.net");
        assert_eq!(socks.server_port, 1080);
        assert!(matches!(
            socks.handler,
            ResidentProxyProtocolPlan::Socks5Tcp { .. }
        ));

        let http = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "http_live".to_owned(),
            "http://user:password@proxy.example.net:80".to_owned(),
        )
        .unwrap();
        assert_eq!(http.protocol, "http-proxy");
        assert_eq!(http.server_host, "proxy.example.net");
        assert_eq!(http.server_port, 80);
        assert_eq!(http.tls, "none");
        assert!(matches!(
            http.handler,
            ResidentProxyProtocolPlan::HttpProxyTcp { .. }
        ));

        let https = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "https_live".to_owned(),
            "https://user:password@secure-proxy.example.net:443".to_owned(),
        )
        .unwrap();
        assert_eq!(https.protocol, "http-proxy");
        assert_eq!(https.server_host, "secure-proxy.example.net");
        assert_eq!(https.server_port, 443);
        assert_eq!(https.server_name, "secure-proxy.example.net");
        assert_eq!(https.tls, "tls");
        assert_eq!(https.alpn, vec!["h2".to_owned(), "http/1.1".to_owned()]);
        assert!(matches!(
            https.handler,
            ResidentProxyProtocolPlan::HttpProxyTcp { .. }
        ));
        let https_graph = https.executable_graph_value();
        assert_eq!(https_graph["protocolFraming"], "http-proxy");
        assert_eq!(https_graph["securityUnderlay"], "standard-tls");
        assert_eq!(https_graph["packetSemantics"], "protocol-closed");
        assert_eq!(
            https_graph["runtimeComponents"]["underlayFactory"]["provider"],
            "rustls"
        );

        let http_transport = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "http_transport_live".to_owned(),
            "http://user:password@proxy.example.net:80/relay?transport=1&host=front.example"
                .to_owned(),
        )
        .unwrap();
        assert_eq!(http_transport.protocol, "http-proxy");
        assert_eq!(http_transport.net, "http-transport");
        assert_eq!(http_transport.stream_host, "front.example");
        assert_eq!(http_transport.stream_path, "/relay");
        assert!(matches!(
            http_transport.handler,
            ResidentProxyProtocolPlan::HttpProxyTcp {
                transport: true,
                ref transport_host,
                ref transport_path,
                ..
            } if transport_host == "front.example" && transport_path == "/relay"
        ));

        let shadowsocks = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "ss_live".to_owned(),
            shadowsocks_fixture_url("ss", "203.0.113.10", 28446),
        )
        .unwrap();
        assert_eq!(shadowsocks.protocol, "shadowsocks");
        assert_eq!(shadowsocks.tls, "aead");
        assert!(matches!(
            shadowsocks.handler,
            ResidentProxyProtocolPlan::ShadowsocksAeadTcp { salt_len: 16, .. }
        ));

        let shadowsocks_2022 = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "ss2022_live".to_owned(),
            "ss://2022-blake3-aes-128-gcm:MTIzNDU2Nzg5MDEyMzQ1Ng==@203.0.113.10:28448".to_owned(),
        )
        .unwrap();
        assert_eq!(shadowsocks_2022.protocol, "shadowsocks");
        assert_eq!(shadowsocks_2022.tls, "aead-2022");
        assert_eq!(
            shadowsocks_2022.executable_graph_value()["packetSemantics"],
            "datagram-aead-2022"
        );
        assert!(matches!(
            shadowsocks_2022.handler,
            ResidentProxyProtocolPlan::Shadowsocks2022Tcp {
                salt_len: 16,
                packet_nonce_len: 0,
                ..
            }
        ));

        let shadowsocks_plugin = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "ss_plugin_live".to_owned(),
            shadowsocks_plugin_fixture_url("ss-plugin", "203.0.113.10", 28447),
        )
        .unwrap();
        assert_eq!(shadowsocks_plugin.protocol, "shadowsocks");
        assert_eq!(shadowsocks_plugin.net, "simple-obfs-http");
        assert!(matches!(
            shadowsocks_plugin.handler,
            ResidentProxyProtocolPlan::ShadowsocksSimpleObfsHttpTcp { .. }
        ));

        let shadowsocks_obfs_tls = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "ss_obfs_tls_live".to_owned(),
            shadowsocks_simple_obfs_tls_fixture_url("ss-plugin-tls", "203.0.113.10", 28448),
        )
        .unwrap();
        assert_eq!(shadowsocks_obfs_tls.protocol, "shadowsocks");
        assert_eq!(shadowsocks_obfs_tls.net, "simple-obfs-tls");
        assert_eq!(
            shadowsocks_obfs_tls.executable_graph_value()["streamWrapper"],
            "simple-obfs-tls"
        );
        assert!(matches!(
            shadowsocks_obfs_tls.handler,
            ResidentProxyProtocolPlan::ShadowsocksSimpleObfsTlsTcp { .. }
        ));

        let shadowsocks_v2ray_plugin = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "ss_v2ray_plugin_live".to_owned(),
            shadowsocks_v2ray_plugin_tls_fixture_url("ss-plugin-v2ray", "203.0.113.10", 28449),
        )
        .unwrap();
        assert_eq!(shadowsocks_v2ray_plugin.protocol, "shadowsocks");
        assert_eq!(shadowsocks_v2ray_plugin.net, "v2ray-plugin-tls-websocket");
        assert_eq!(shadowsocks_v2ray_plugin.tls, "tls");
        assert_eq!(shadowsocks_v2ray_plugin.server_name, "front.example");
        assert_eq!(shadowsocks_v2ray_plugin.alpn, vec!["http/1.1".to_owned()]);
        assert!(matches!(
            shadowsocks_v2ray_plugin.handler,
            ResidentProxyProtocolPlan::ShadowsocksV2rayPluginTlsWsTcp { .. }
        ));

        let shadowsocks_2022_plugin = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "ss2022_plugin_live".to_owned(),
            shadowsocks_2022_simple_obfs_http_fixture_url("ss2022-plugin", "203.0.113.10", 28450),
        )
        .unwrap();
        assert_eq!(shadowsocks_2022_plugin.protocol, "shadowsocks");
        assert_eq!(shadowsocks_2022_plugin.net, "simple-obfs-http");
        assert_eq!(shadowsocks_2022_plugin.tls, "aead-2022");
        assert!(matches!(
            shadowsocks_2022_plugin.handler,
            ResidentProxyProtocolPlan::Shadowsocks2022SimpleObfsHttpTcp { .. }
        ));

        let trojan = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "trojan_live".to_owned(),
            trojan_fixture_url("trojan", "203.0.113.10", 28444),
        )
        .unwrap();
        assert_eq!(trojan.protocol, "trojan");
        assert_eq!(trojan.server_host, "203.0.113.10");
        assert_eq!(trojan.server_port, 28444);
        assert_eq!(trojan.server_name, "office.example");
        assert_eq!(trojan.tls, "tls");
        assert!(matches!(
            trojan.handler,
            ResidentProxyProtocolPlan::TrojanTcpTls { .. }
        ));

        let trojan_websocket = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "trojan_ws_live".to_owned(),
            trojan_websocket_fixture_url("trojan-ws", "203.0.113.10", 28456),
        )
        .unwrap();
        assert_eq!(trojan_websocket.protocol, "trojan");
        assert_eq!(trojan_websocket.server_host, "203.0.113.10");
        assert_eq!(trojan_websocket.server_port, 28456);
        assert_eq!(trojan_websocket.server_name, "office.example");
        assert_eq!(trojan_websocket.net, "websocket");
        assert_eq!(trojan_websocket.stream_host, "front.example");
        assert_eq!(trojan_websocket.stream_path, "/trojan");
        assert_eq!(trojan_websocket.tls, "tls");
        assert!(matches!(
            trojan_websocket.handler,
            ResidentProxyProtocolPlan::TrojanTcpTls { .. }
        ));
        let trojan_websocket_graph = trojan_websocket.executable_graph_value();
        assert_eq!(trojan_websocket_graph["protocolFraming"], "trojan");
        assert_eq!(trojan_websocket_graph["streamWrapper"], "websocket");
        assert_eq!(
            trojan_websocket_graph["runtimeComponents"]["streamWrapperFactory"]["provider"],
            "resident-websocket-binary-frame"
        );
        assert!(
            trojan_websocket_graph["streamWrapperEndpoint"]["hostHash"]
                .as_str()
                .unwrap()
                .starts_with("sha256:")
        );
        assert_eq!(
            trojan_websocket_graph["streamWrapperEndpoint"]["path"],
            "/trojan"
        );
        assert!(!trojan_websocket_graph.to_string().contains("front.example"));

        let trojan_httpupgrade = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "trojan_httpupgrade_live".to_owned(),
            trojan_httpupgrade_fixture_url("trojan-httpupgrade", "203.0.113.10", 28459),
        )
        .unwrap();
        assert_eq!(trojan_httpupgrade.protocol, "trojan");
        assert_eq!(trojan_httpupgrade.server_host, "203.0.113.10");
        assert_eq!(trojan_httpupgrade.server_port, 28459);
        assert_eq!(trojan_httpupgrade.server_name, "office.example");
        assert_eq!(trojan_httpupgrade.net, "httpupgrade");
        assert_eq!(trojan_httpupgrade.stream_host, "front.example");
        assert_eq!(trojan_httpupgrade.stream_path, "/trojan-upgrade");
        assert_eq!(trojan_httpupgrade.tls, "tls");
        assert!(matches!(
            trojan_httpupgrade.handler,
            ResidentProxyProtocolPlan::TrojanTcpTls { .. }
        ));
        let trojan_httpupgrade_graph = trojan_httpupgrade.executable_graph_value();
        assert_eq!(trojan_httpupgrade_graph["protocolFraming"], "trojan");
        assert_eq!(trojan_httpupgrade_graph["streamWrapper"], "httpupgrade");
        assert_eq!(
            trojan_httpupgrade_graph["runtimeComponents"]["streamWrapperFactory"]["provider"],
            "resident-http-upgrade-stream"
        );
        assert!(
            trojan_httpupgrade_graph["streamWrapperEndpoint"]["hostHash"]
                .as_str()
                .unwrap()
                .starts_with("sha256:")
        );
        assert_eq!(
            trojan_httpupgrade_graph["streamWrapperEndpoint"]["path"],
            "/trojan-upgrade"
        );
        assert!(
            !trojan_httpupgrade_graph
                .to_string()
                .contains("front.example")
        );

        let trojan_grpc = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "trojan_grpc_live".to_owned(),
            trojan_grpc_fixture_url("trojan-grpc", "203.0.113.10", 28461),
        )
        .unwrap();
        assert_eq!(trojan_grpc.protocol, "trojan");
        assert_eq!(trojan_grpc.server_host, "203.0.113.10");
        assert_eq!(trojan_grpc.server_port, 28461);
        assert_eq!(trojan_grpc.server_name, "office.example");
        assert_eq!(trojan_grpc.net, "grpc");
        assert_eq!(trojan_grpc.stream_host, "front.example");
        assert_eq!(trojan_grpc.stream_path, "TrojanGunService");
        assert_eq!(trojan_grpc.alpn, vec!["h2".to_owned()]);
        assert!(matches!(
            trojan_grpc.handler,
            ResidentProxyProtocolPlan::TrojanTcpTls { .. }
        ));
        let trojan_grpc_graph = trojan_grpc.executable_graph_value();
        assert_eq!(trojan_grpc_graph["protocolFraming"], "trojan");
        assert_eq!(trojan_grpc_graph["streamWrapper"], "grpc");
        assert_eq!(
            trojan_grpc_graph["runtimeComponents"]["streamWrapperFactory"]["provider"],
            "resident-grpc-h2-stream"
        );
        assert!(
            trojan_grpc_graph["streamWrapperEndpoint"]["hostHash"]
                .as_str()
                .unwrap()
                .starts_with("sha256:")
        );
        assert_eq!(
            trojan_grpc_graph["streamWrapperEndpoint"]["path"],
            "TrojanGunService"
        );
        assert!(!trojan_grpc_graph.to_string().contains("front.example"));

        let anytls = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "anytls_live".to_owned(),
            "anytls://password@secure-stream.example.net:443?sni=secure-stream.example.net"
                .to_owned(),
        )
        .unwrap();
        assert_eq!(anytls.protocol, "anytls");
        assert_eq!(anytls.server_host, "secure-stream.example.net");
        assert_eq!(anytls.server_port, 443);
        assert_eq!(anytls.server_name, "secure-stream.example.net");
        assert_eq!(anytls.tls, "tls");
        assert!(matches!(
            anytls.handler,
            ResidentProxyProtocolPlan::AnyTlsTcpTls { .. }
        ));

        let vmess = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "vmess_live".to_owned(),
            vmess_fixture_url("vmess", "203.0.113.10", 28452, "tcp", "", "", ""),
        )
        .unwrap();
        assert_eq!(vmess.protocol, "vmess");
        assert_eq!(vmess.server_host, "203.0.113.10");
        assert_eq!(vmess.server_port, 28452);
        assert_eq!(vmess.tls, "none");
        assert!(matches!(
            vmess.handler,
            ResidentProxyProtocolPlan::VmessAeadTcp { .. }
        ));

        let vmess_websocket = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "vmess_ws_live".to_owned(),
            vmess_fixture_url(
                "vmess-ws",
                "203.0.113.10",
                28454,
                "ws",
                "front.example",
                "/vmess",
                "",
            ),
        )
        .unwrap();
        assert_eq!(vmess_websocket.protocol, "vmess");
        assert_eq!(vmess_websocket.net, "websocket");
        assert_eq!(vmess_websocket.stream_host, "front.example");
        assert_eq!(vmess_websocket.stream_path, "/vmess");
        assert_eq!(vmess_websocket.tls, "none");
        assert!(matches!(
            vmess_websocket.handler,
            ResidentProxyProtocolPlan::VmessAeadTcp { .. }
        ));
        let vmess_websocket_graph = vmess_websocket.executable_graph_value();
        assert_eq!(vmess_websocket_graph["streamWrapper"], "websocket");
        assert_eq!(vmess_websocket_graph["securityUnderlay"], "none");
        assert_eq!(
            vmess_websocket_graph["runtimeComponents"]["streamWrapperFactory"]["provider"],
            "resident-websocket-binary-frame"
        );
        assert!(
            vmess_websocket_graph["streamWrapperEndpoint"]["hostHash"]
                .as_str()
                .unwrap()
                .starts_with("sha256:")
        );
        assert!(!vmess_websocket_graph.to_string().contains("front.example"));

        let vmess_websocket_tls = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "vmess_ws_tls_live".to_owned(),
            vmess_fixture_url_with_sni(
                "203.0.113.10",
                28454,
                "ws",
                "front.example",
                "/vmess",
                "tls",
                "office.example",
            ),
        )
        .unwrap();
        assert_eq!(vmess_websocket_tls.protocol, "vmess");
        assert_eq!(vmess_websocket_tls.net, "websocket");
        assert_eq!(vmess_websocket_tls.server_name, "office.example");
        assert_eq!(vmess_websocket_tls.stream_host, "front.example");
        assert_eq!(vmess_websocket_tls.stream_path, "/vmess");
        assert_eq!(vmess_websocket_tls.tls, "tls");
        assert!(matches!(
            vmess_websocket_tls.handler,
            ResidentProxyProtocolPlan::VmessAeadTcp { .. }
        ));
        let vmess_websocket_tls_graph = vmess_websocket_tls.executable_graph_value();
        assert_eq!(vmess_websocket_tls_graph["streamWrapper"], "websocket");
        assert_eq!(
            vmess_websocket_tls_graph["securityUnderlay"],
            "standard-tls"
        );
        assert_eq!(
            vmess_websocket_tls_graph["runtimeComponents"]["streamWrapperFactory"]["provider"],
            "resident-websocket-binary-frame"
        );
        assert_eq!(
            vmess_websocket_tls_graph["runtimeComponents"]["underlayFactory"]["provider"],
            "rustls"
        );

        let vmess_httpupgrade = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "vmess_httpupgrade_live".to_owned(),
            vmess_fixture_url(
                "vmess-httpupgrade",
                "203.0.113.10",
                28460,
                "httpupgrade",
                "front.example",
                "/vmess-upgrade",
                "",
            ),
        )
        .unwrap();
        assert_eq!(vmess_httpupgrade.protocol, "vmess");
        assert_eq!(vmess_httpupgrade.net, "httpupgrade");
        assert_eq!(vmess_httpupgrade.stream_host, "front.example");
        assert_eq!(vmess_httpupgrade.stream_path, "/vmess-upgrade");
        assert_eq!(vmess_httpupgrade.tls, "none");
        assert!(matches!(
            vmess_httpupgrade.handler,
            ResidentProxyProtocolPlan::VmessAeadTcp { .. }
        ));
        let vmess_httpupgrade_graph = vmess_httpupgrade.executable_graph_value();
        assert_eq!(vmess_httpupgrade_graph["streamWrapper"], "httpupgrade");
        assert_eq!(vmess_httpupgrade_graph["securityUnderlay"], "none");
        assert_eq!(
            vmess_httpupgrade_graph["runtimeComponents"]["streamWrapperFactory"]["provider"],
            "resident-http-upgrade-stream"
        );
        assert!(
            vmess_httpupgrade_graph["streamWrapperEndpoint"]["hostHash"]
                .as_str()
                .unwrap()
                .starts_with("sha256:")
        );
        assert!(
            !vmess_httpupgrade_graph
                .to_string()
                .contains("front.example")
        );

        let vmess_httpupgrade_tls = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "vmess_httpupgrade_tls_live".to_owned(),
            vmess_fixture_url_with_sni(
                "203.0.113.10",
                28460,
                "httpupgrade",
                "front.example",
                "/vmess-upgrade",
                "tls",
                "office.example",
            ),
        )
        .unwrap();
        assert_eq!(vmess_httpupgrade_tls.protocol, "vmess");
        assert_eq!(vmess_httpupgrade_tls.net, "httpupgrade");
        assert_eq!(vmess_httpupgrade_tls.server_name, "office.example");
        assert_eq!(vmess_httpupgrade_tls.stream_host, "front.example");
        assert_eq!(vmess_httpupgrade_tls.stream_path, "/vmess-upgrade");
        assert_eq!(vmess_httpupgrade_tls.tls, "tls");
        assert!(matches!(
            vmess_httpupgrade_tls.handler,
            ResidentProxyProtocolPlan::VmessAeadTcp { .. }
        ));
        let vmess_httpupgrade_tls_graph = vmess_httpupgrade_tls.executable_graph_value();
        assert_eq!(vmess_httpupgrade_tls_graph["streamWrapper"], "httpupgrade");
        assert_eq!(
            vmess_httpupgrade_tls_graph["securityUnderlay"],
            "standard-tls"
        );
        assert_eq!(
            vmess_httpupgrade_tls_graph["runtimeComponents"]["streamWrapperFactory"]["provider"],
            "resident-http-upgrade-stream"
        );
        assert_eq!(
            vmess_httpupgrade_tls_graph["runtimeComponents"]["underlayFactory"]["provider"],
            "rustls"
        );

        let vmess_grpc = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "vmess_grpc_live".to_owned(),
            vmess_fixture_url(
                "vmess-grpc",
                "203.0.113.10",
                28462,
                "grpc",
                "front.example",
                "GunService",
                "tls",
            ),
        )
        .unwrap();
        assert_eq!(vmess_grpc.protocol, "vmess");
        assert_eq!(vmess_grpc.net, "grpc");
        assert_eq!(vmess_grpc.server_host, "203.0.113.10");
        assert_eq!(vmess_grpc.server_port, 28462);
        assert_eq!(vmess_grpc.server_name, "203.0.113.10");
        assert_eq!(vmess_grpc.stream_host, "front.example");
        assert_eq!(vmess_grpc.stream_path, "GunService");
        assert_eq!(vmess_grpc.tls, "tls");
        assert_eq!(vmess_grpc.alpn, vec!["h2".to_owned()]);
        assert!(matches!(
            vmess_grpc.handler,
            ResidentProxyProtocolPlan::VmessAeadTcp { .. }
        ));
        let vmess_grpc_graph = vmess_grpc.executable_graph_value();
        assert_eq!(vmess_grpc_graph["streamWrapper"], "grpc");
        assert_eq!(vmess_grpc_graph["securityUnderlay"], "standard-tls");
        assert_eq!(
            vmess_grpc_graph["runtimeComponents"]["streamWrapperFactory"]["provider"],
            "resident-grpc-h2-stream"
        );
        assert!(
            vmess_grpc_graph["streamWrapperEndpoint"]["hostHash"]
                .as_str()
                .unwrap()
                .starts_with("sha256:")
        );
        assert!(!vmess_grpc_graph.to_string().contains("front.example"));

        let vless_websocket = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "vless_ws_live".to_owned(),
            vless_fixture_url(
                "vless-ws",
                "203.0.113.10",
                28443,
                "ws",
                "front.example",
                "/ws",
                "office.example",
                "",
                "",
            ),
        )
        .unwrap();
        assert_eq!(vless_websocket.protocol, "vless");
        assert_eq!(vless_websocket.server_host, "203.0.113.10");
        assert_eq!(vless_websocket.server_port, 28443);
        assert_eq!(vless_websocket.server_name, "office.example");
        assert_eq!(vless_websocket.net, "websocket");
        assert_eq!(vless_websocket.stream_host, "front.example");
        assert_eq!(vless_websocket.stream_path, "/ws");
        assert_eq!(vless_websocket.flow, "");
        assert!(matches!(
            vless_websocket.handler,
            ResidentProxyProtocolPlan::VlessVisionTcpTls { .. }
        ));
        let vless_websocket_graph = vless_websocket.executable_graph_value();
        assert_eq!(vless_websocket_graph["streamWrapper"], "websocket");
        assert_eq!(
            vless_websocket_graph["runtimeComponents"]["streamWrapperFactory"]["provider"],
            "resident-websocket-binary-frame"
        );
        assert!(
            vless_websocket_graph["streamWrapperEndpoint"]["hostHash"]
                .as_str()
                .unwrap()
                .starts_with("sha256:")
        );
        assert_eq!(
            vless_websocket_graph["streamWrapperEndpoint"]["path"],
            "/ws"
        );
        assert!(!vless_websocket_graph.to_string().contains("front.example"));

        let vless_httpupgrade = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "vless_httpupgrade_live".to_owned(),
            vless_fixture_url(
                "vless-httpupgrade",
                "203.0.113.10",
                28461,
                "httpupgrade",
                "front.example",
                "/vless-upgrade",
                "office.example",
                "",
                "",
            ),
        )
        .unwrap();
        assert_eq!(vless_httpupgrade.protocol, "vless");
        assert_eq!(vless_httpupgrade.server_host, "203.0.113.10");
        assert_eq!(vless_httpupgrade.server_port, 28461);
        assert_eq!(vless_httpupgrade.server_name, "office.example");
        assert_eq!(vless_httpupgrade.net, "httpupgrade");
        assert_eq!(vless_httpupgrade.stream_host, "front.example");
        assert_eq!(vless_httpupgrade.stream_path, "/vless-upgrade");
        assert_eq!(vless_httpupgrade.flow, "");
        assert!(matches!(
            vless_httpupgrade.handler,
            ResidentProxyProtocolPlan::VlessVisionTcpTls { .. }
        ));
        let vless_httpupgrade_graph = vless_httpupgrade.executable_graph_value();
        assert_eq!(vless_httpupgrade_graph["streamWrapper"], "httpupgrade");
        assert_eq!(
            vless_httpupgrade_graph["runtimeComponents"]["streamWrapperFactory"]["provider"],
            "resident-http-upgrade-stream"
        );
        assert!(
            vless_httpupgrade_graph["streamWrapperEndpoint"]["hostHash"]
                .as_str()
                .unwrap()
                .starts_with("sha256:")
        );
        assert_eq!(
            vless_httpupgrade_graph["streamWrapperEndpoint"]["path"],
            "/vless-upgrade"
        );
        assert!(
            !vless_httpupgrade_graph
                .to_string()
                .contains("front.example")
        );

        let hysteria2 = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "hy2_live".to_owned(),
            hysteria2_fixture_url("hy2", "203.0.113.10", 28453),
        )
        .unwrap();
        assert_eq!(hysteria2.protocol, "hysteria2");
        assert_eq!(hysteria2.server_host, "203.0.113.10");
        assert_eq!(hysteria2.server_port, 28453);
        assert_eq!(hysteria2.server_name, "office.example");
        assert_eq!(hysteria2.net, "udp");
        assert_eq!(hysteria2.tls, "quic");
        assert!(matches!(
            hysteria2.handler,
            ResidentProxyProtocolPlan::Hysteria2QuicTcp { .. }
        ));

        let hysteria2_hopping = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "hy2_hopping_live".to_owned(),
            hysteria2_fixture_url_with_pin("hy2", "203.0.113.10:28453,28454-28455", "AA-BB-CC"),
        )
        .unwrap();
        assert_eq!(hysteria2_hopping.protocol, "hysteria2");
        assert_eq!(hysteria2_hopping.server_host, "203.0.113.10");
        assert_eq!(hysteria2_hopping.server_port, 28453);
        assert!(matches!(
            hysteria2_hopping.handler,
            ResidentProxyProtocolPlan::Hysteria2QuicTcp {
                ref port_hop_ports,
                ..
            } if port_hop_ports == &vec![28453, 28454, 28455]
        ));

        let tuic = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "tuic_live".to_owned(),
            tuic_fixture_url("tuic", "203.0.113.10", 28454, true),
        )
        .unwrap();
        assert_eq!(tuic.protocol, "tuic");
        assert_eq!(tuic.server_host, "203.0.113.10");
        assert_eq!(tuic.server_port, 28454);
        assert_eq!(tuic.server_name, "office.example");
        assert_eq!(tuic.net, "udp");
        assert_eq!(tuic.tls, "quic");
        assert!(tuic.allow_insecure);
        assert!(matches!(
            tuic.handler,
            ResidentProxyProtocolPlan::TuicQuicTcp {
                allow_insecure: true,
                ..
            }
        ));

        let tuic_verified = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "tuic_verified_live".to_owned(),
            tuic_fixture_url("tuic", "203.0.113.10", 28454, false),
        )
        .unwrap();
        assert_eq!(tuic_verified.protocol, "tuic");
        assert_eq!(tuic_verified.server_name, "office.example");
        assert_eq!(tuic_verified.tls, "quic");
        assert!(!tuic_verified.allow_insecure);
        assert!(matches!(
            tuic_verified.handler,
            ResidentProxyProtocolPlan::TuicQuicTcp {
                allow_insecure: false,
                ..
            }
        ));
        assert_eq!(
            tuic_verified.executable_graph_value()["runtimeComponents"]["underlayFactory"]["verificationPolicy"],
            "system-roots"
        );

        let juicity = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "juicity_live".to_owned(),
            juicity_fixture_url("juicity", "203.0.113.10", 28455, true),
        )
        .unwrap();
        assert_eq!(juicity.protocol, "juicity");
        assert_eq!(juicity.server_host, "203.0.113.10");
        assert_eq!(juicity.server_port, 28455);
        assert_eq!(juicity.server_name, "office.example");
        assert_eq!(juicity.net, "udp");
        assert_eq!(juicity.tls, "quic");
        assert!(matches!(
            juicity.handler,
            ResidentProxyProtocolPlan::JuicityQuicTcp { .. }
        ));

        for proxy in [
            &socks,
            &http,
            &https,
            &shadowsocks,
            &shadowsocks_plugin,
            &trojan,
            &trojan_websocket,
            &trojan_httpupgrade,
            &anytls,
            &vmess,
            &vmess_websocket,
            &vmess_httpupgrade,
            &vless_websocket,
            &vless_httpupgrade,
            &hysteria2,
            &tuic,
            &juicity,
        ] {
            let graph = proxy.executable_graph_value();
            assert_eq!(graph["schemaVersion"], 1);
            assert!(
                graph["graphId"]
                    .as_str()
                    .unwrap()
                    .starts_with("resident-graph:")
            );
            assert_eq!(graph["admission"]["status"], "admitted");
            assert_eq!(graph["chain"]["flattened"], false);
            assert_eq!(
                graph["runtimeComponents"]["underlayFactory"]["status"],
                "admitted"
            );
            assert_eq!(
                graph["runtimeComponents"]["streamWrapperFactory"]["status"],
                "admitted"
            );
            assert_eq!(
                graph["runtimeComponents"]["chainExecutor"]["executor"],
                "single-resident-graph"
            );
            assert_eq!(
                graph["runtimeComponents"]["generationCache"]["cacheScope"],
                "graph-and-reload-generation"
            );
            assert_eq!(
                graph["runtimeComponents"]["generationCache"]["materialized"],
                false
            );
            assert!(graph["runtimeComponents"]["generationCache"]["reloadGeneration"].is_null());
            let materialized = proxy.executable_graph_value_for_reload_generation(42);
            assert_eq!(
                materialized["runtimeComponents"]["generationCache"]["reloadGeneration"],
                42
            );
            assert_eq!(
                materialized["runtimeComponents"]["generationCache"]["materialized"],
                true
            );
            assert_eq!(
                materialized["runtimeComponents"]["probeExecutor"]["reloadGeneration"],
                42
            );
            assert_eq!(
                graph["runtimeComponents"]["packetSessionManager"]["manager"],
                "bounded-resident-packet-session"
            );
            assert_eq!(
                graph["runtimeComponents"]["probeExecutor"]["executor"],
                "resident-executable-graph"
            );
            assert!(
                graph["linkIdentity"]["linkHash"]
                    .as_str()
                    .unwrap()
                    .starts_with("sha256:")
            );
            let graph_text = graph.to_string();
            for secret in ["user:password", ":password@", "auth-token"] {
                assert!(
                    !graph_text.contains(secret),
                    "graph leaked raw credential-bearing link: {graph}"
                );
            }
        }
    }

    #[test]
    fn resident_dataplane_plan_admits_nested_chain_without_flattening() {
        let config = parse_config(
            r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        }
        routing {
        fallback: direct
        }
        "#,
        );
        let proxy = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "chained_live".to_owned(),
            "socks5://user:password@proxy-a.example.net:1080 -> http://user:password@proxy-b.example.net:80"
                .to_owned(),
        )
        .unwrap();
        assert!(proxy.chain_parent.is_some());
        assert_eq!(proxy.server_host, "proxy-b.example.net");
        let graph = proxy.executable_graph_value();
        assert_eq!(graph["chain"]["mode"], "parent-proxy");
        assert_eq!(graph["chain"]["parentCount"], 1);
        assert_eq!(graph["chain"]["flattened"], false);
        assert_eq!(
            graph["runtimeComponents"]["chainExecutor"]["executor"],
            "resident-parent-connect-chain"
        );

        let err = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "too_deep".to_owned(),
            "socks5://user:password@proxy-a.example.net:1080 -> http://user:password@proxy-b.example.net:80 -> http://user:password@proxy-c.example.net:80"
                .to_owned(),
        )
        .unwrap_err();
        assert!(err.contains("admits two-node chains only"));
    }

    #[test]
    fn resident_dataplane_plan_keeps_deferred_unsupported_shapes_blocked() {
        let config = parse_config(
            r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        }
        routing {
        fallback: direct
        }
        "#,
        );
        let https_insecure = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "https_insecure".to_owned(),
            "https://user:password@secure-proxy.example.net:443?allowInsecure=1".to_owned(),
        )
        .unwrap_err();
        assert!(https_insecure.contains("does not admit allow_insecure"));

        let https_utls = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "https_utls".to_owned(),
            "https://user:password@secure-proxy.example.net:443?utlsImitate=chrome".to_owned(),
        )
        .unwrap_err();
        assert!(https_utls.contains("does not admit fingerprint/utls imitation"));

        let plugin = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "ss_plugin".to_owned(),
            shadowsocks_unsupported_plugin_fixture_url("ss-plugin", "203.0.113.10", 28446),
        )
        .unwrap_err();
        assert!(plugin.contains("admits simple-obfs http/tls and v2ray-plugin tls websocket only"));

        let vmess_grpc = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "vmess_grpc".to_owned(),
            vmess_fixture_url(
                "vmess-grpc",
                "203.0.113.10",
                28458,
                "grpc",
                "",
                "grpc-service",
                "",
            ),
        )
        .unwrap_err();
        assert!(vmess_grpc.contains(
            "VMess grpc handler admits TLS HTTP/2 endpoints only for node vmess_grpc; got tls=none"
        ));

        let trojan_go_inner_encryption = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "trojan_go_inner_encryption".to_owned(),
            "trojan-go://password@secure-stream.example.net:443?type=ws&sni=secure-stream.example.net&encryption=ss%3Baes-128-gcm%3Apass".to_owned(),
        )
        .unwrap();
        assert_eq!(trojan_go_inner_encryption.protocol, "trojan");
        assert_eq!(trojan_go_inner_encryption.net, "websocket");
        assert!(matches!(
            trojan_go_inner_encryption.handler,
            ResidentProxyProtocolPlan::TrojanInnerShadowsocksTcpTls { .. }
        ));

        let anytls_insecure = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "anytls_insecure".to_owned(),
            "anytls://password@secure-stream.example.net:443?insecure=1&sni=secure-stream.example.net"
                .to_owned(),
        )
        .unwrap_err();
        assert!(anytls_insecure.contains("does not admit AnyTLS insecure mode"));

        let vmess_tls = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "vmess_tls".to_owned(),
            vmess_fixture_url("vmess-tls", "203.0.113.10", 28452, "tcp", "", "", "tls"),
        )
        .unwrap_err();
        assert!(vmess_tls.contains("admits only plain VMess TCP endpoints"));

        let hy2_no_pin = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "hy2_no_pin".to_owned(),
            hysteria2_fixture_url_with_pin("hy2", "203.0.113.10:28453", ""),
        )
        .unwrap_err();
        assert!(hy2_no_pin.contains("requires Hysteria2 pinSHA256"));

        let hy2_hopping = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "hy2_hopping".to_owned(),
            hysteria2_fixture_url_with_pin("hy2", "example.com:443,8443-8445", "AA-BB-CC"),
        )
        .unwrap();
        assert_eq!(hy2_hopping.server_port, 443);
        assert!(matches!(
            hy2_hopping.handler,
            ResidentProxyProtocolPlan::Hysteria2QuicTcp {
                ref port_hop_ports,
                ..
            } if port_hop_ports == &vec![443, 8443, 8444, 8445]
        ));

        let tuic_verified = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "tuic_verified".to_owned(),
            tuic_fixture_url("tuic", "203.0.113.10", 28454, false),
        )
        .unwrap();
        assert!(!tuic_verified.allow_insecure);

        let juicity_without_verification = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "juicity_without_verification".to_owned(),
            juicity_fixture_url("juicity", "203.0.113.10", 28455, false),
        )
        .unwrap_err();
        assert!(
            juicity_without_verification
                .contains("requires Juicity allow_insecure or pinned_certchain_sha256")
        );
    }

    #[test]
    fn resident_dataplane_plan_builds_proxy_by_outbound_index() {
        let config = parse_config(
            r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        dial_mode: domain++
        }
        node {
        hk: 'vless://01234567-89ab-cdef-0123-456789abcdef@156.246.90.2:443?security=tls&type=tcp&sni=hk.example&flow=xtls-rprx-vision&alpn=h2,http/1.1'
        us: 'vless://01234567-89ab-cdef-0123-456789abcdef@203.0.113.2:443?security=tls&type=tcp&sni=us.example&flow=xtls-rprx-vision&alpn=h2,http/1.1'
        }
        group {
        proxy {
            filter: name(hk)
            policy: fixed(0)
        }
        openai {
            filter: name(us)
            policy: fixed(0)
        }
        }
        routing {
        domain(suffix: googleapis.com) -> openai
        fallback: proxy
        }
        "#,
        );
        let plan = build_resident_dataplane_plan(&config).unwrap();
        assert!(plan.enabled);
        assert_eq!(plan.tcp_dial_mode, TcpDialMode::DomainPlusPlus);
        let proxy = plan
            .proxies
            .get(&2)
            .unwrap()
            .default_proxy_snapshot()
            .unwrap();
        let openai = plan
            .proxies
            .get(&3)
            .unwrap()
            .default_proxy_snapshot()
            .unwrap();
        assert_eq!(proxy.group_name, "proxy");
        assert_eq!(proxy.node_tag, "hk");
        assert_eq!(openai.group_name, "openai");
        assert_eq!(openai.node_tag, "us");
    }

    #[test]
    fn resident_dataplane_plan_rejects_vless_without_vision_flow() {
        let config = parse_config(
            r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        }
        node {
        vless_live: 'vless://01234567-89ab-cdef-0123-456789abcdef@156.246.90.2:443?security=tls&type=tcp&sni=office.example&alpn=h2,http/1.1'
        }
        group {
        proxy {
            filter: name(vless_live)
            policy: fixed(0)
        }
        }
        routing {
        l4proto(tcp) && dport(443) -> proxy
        fallback: direct
        }
        "#,
        );
        let err = build_resident_dataplane_plan(&config).unwrap_err();
        assert!(err.contains("admits tcp flow=xtls-rprx-vision"));
        assert!(err.contains("resident shape remains fail-closed"));
    }

    #[test]
    fn resident_dataplane_plan_admits_vless_xhttp_h2_packet_up() {
        let config = parse_config(
            r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        }
        routing {
        fallback: direct
        }
        "#,
        );
        let proxy = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "standard_import".to_owned(),
            vless_xhttp_parser_fixture_url("auto", "h2", ""),
        )
        .unwrap();

        assert_eq!(proxy.protocol, "vless");
        assert_eq!(proxy.net, "xhttp");
        assert_eq!(proxy.alpn, vec!["h2".to_owned()]);
        assert_eq!(proxy.stream_host, "edge.transport.invalid");
        assert_eq!(proxy.stream_path, "/resource/?ed=2048");
        let graph = proxy.executable_graph_value();
        assert_eq!(graph["streamWrapper"], "xhttp");
        assert_eq!(
            graph["runtimeComponents"]["streamWrapperFactory"]["provider"],
            "resident-xhttp-h2-packet-up"
        );
    }

    #[test]
    fn resident_dataplane_plan_rejects_unimplemented_vless_xhttp_shapes() {
        let config = parse_config(
            r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        }
        routing {
        fallback: direct
        }
        "#,
        );
        for (tag, link, expected) in [
            (
                "xhttp_h3",
                vless_xhttp_parser_fixture_url("packet-up", "h3", ""),
                "admits HTTP/2 packet-up only",
            ),
            (
                "xhttp_stream_up",
                vless_xhttp_parser_fixture_url("stream-up", "h2", ""),
                "admits packet-up mode only",
            ),
            (
                "xhttp_extra",
                vless_xhttp_parser_fixture_url(
                    "packet-up",
                    "h2",
                    r#"{"xmux":{"maxConnections":2}}"#,
                ),
                "admits default extra settings only",
            ),
        ] {
            let err = build_resident_proxy_plan_for_node(
                &config,
                "proxy".to_owned(),
                tag.to_owned(),
                link,
            )
            .unwrap_err();
            assert!(
                err.contains(expected),
                "{tag} rejected with unexpected error: {err}"
            );
        }
    }

    #[test]
    fn resident_dataplane_plan_resolves_link_fingerprint_before_wire_gate() {
        let config = parse_config(
            r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        tls_implementation: utls
        utls_imitate: safari
        }
        node {
        vless_live: 'vless://01234567-89ab-cdef-0123-456789abcdef@156.246.90.2:443?security=tls&type=tcp&sni=office.example&flow=xtls-rprx-vision&fp=firefox_105&alpn=h2,http/1.1'
        }
        group {
        proxy {
            filter: name(vless_live)
            policy: fixed(0)
        }
        }
        routing {
        l4proto(tcp) && dport(443) -> proxy
        fallback: direct
        }
        "#,
        );
        let plan = build_resident_dataplane_plan(&config).unwrap();
        let proxy = plan.default_proxy_snapshot().unwrap();
        let utls = proxy.utls_fingerprint.unwrap();
        assert_eq!(utls.source, "link fp");
        assert_eq!(utls.requested, "firefox_105");
        assert_eq!(utls.name, "firefox_105");
        assert_eq!(utls.family, "firefox");
    }

    #[test]
    fn resident_dataplane_plan_carries_generic_link_fingerprint() {
        let config = parse_config(
            r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        }
        node {
        vless_live: 'vless://01234567-89ab-cdef-0123-456789abcdef@156.246.90.2:443?security=tls&type=tcp&sni=office.example&flow=xtls-rprx-vision&fp=safari_16_0&alpn=h2,http/1.1'
        }
        group {
        proxy {
            filter: name(vless_live)
            policy: fixed(0)
        }
        }
        routing {
        l4proto(tcp) && dport(443) -> proxy
        fallback: direct
        }
        "#,
        );
        let plan = build_resident_dataplane_plan(&config).unwrap();
        let proxy = plan.default_proxy_snapshot().unwrap();
        assert!(plan.enabled);
        assert_eq!(proxy.node_tag, "vless_live");
        assert_eq!(proxy.flow, XTLS_RPRX_VISION);
        let utls = proxy.utls_fingerprint.unwrap();
        assert_eq!(utls.source, "link fp");
        assert_eq!(utls.requested, "safari_16_0");
        assert_eq!(utls.family, "safari");
    }

    #[test]
    fn resident_dataplane_plan_keeps_standard_tls_when_link_omits_fp_and_global_tls() {
        let config = parse_config(
            r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        }
        node {
        vless_live: 'vless://01234567-89ab-cdef-0123-456789abcdef@156.246.90.2:443?security=tls&type=tcp&sni=office.example&flow=xtls-rprx-vision&alpn=h2,http/1.1'
        }
        group {
        proxy {
            filter: name(vless_live)
            policy: fixed(0)
        }
        }
        routing {
        l4proto(tcp) && dport(443) -> proxy
        fallback: direct
        }
        "#,
        );
        let plan = build_resident_dataplane_plan(&config).unwrap();
        let proxy = plan.default_proxy_snapshot().unwrap();
        assert!(proxy.utls_fingerprint.is_none());
    }

    #[test]
    fn resident_dataplane_plan_keeps_standard_tls_when_link_fp_is_empty_and_global_tls() {
        let config = parse_config(
            r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        }
        node {
        vless_live: 'vless://01234567-89ab-cdef-0123-456789abcdef@156.246.90.2:443?security=tls&type=tcp&sni=office.example&flow=xtls-rprx-vision&fp=&alpn=h2,http/1.1'
        }
        group {
        proxy {
            filter: name(vless_live)
            policy: fixed(0)
        }
        }
        routing {
        l4proto(tcp) && dport(443) -> proxy
        fallback: direct
        }
        "#,
        );
        let plan = build_resident_dataplane_plan(&config).unwrap();
        let proxy = plan.default_proxy_snapshot().unwrap();
        assert!(proxy.utls_fingerprint.is_none());
    }

    #[test]
    fn resident_dataplane_plan_keeps_document_unsafe_auxiliary_rustls_path() {
        let config = parse_config(
            r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        }
        node {
        vless_live: 'vless://01234567-89ab-cdef-0123-456789abcdef@156.246.90.2:443?security=tls&type=tcp&sni=office.example&flow=xtls-rprx-vision&fp=unsafe&alpn=h2,http/1.1'
        }
        group {
        proxy {
            filter: name(vless_live)
            policy: fixed(0)
        }
        }
        routing {
        l4proto(tcp) && dport(443) -> proxy
        fallback: direct
        }
        "#,
        );
        let plan = build_resident_dataplane_plan(&config).unwrap();
        let proxy = plan.default_proxy_snapshot().unwrap();
        assert!(proxy.utls_fingerprint.is_none());
    }

    #[test]
    fn resident_dataplane_plan_uses_global_utls_when_link_does_not_set_fp() {
        let config = parse_config(
            r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        tls_implementation: utls
        utls_imitate: safari
        }
        node {
        vless_live: 'vless://01234567-89ab-cdef-0123-456789abcdef@156.246.90.2:443?security=tls&type=tcp&sni=office.example&flow=xtls-rprx-vision&alpn=h2,http/1.1'
        }
        group {
        proxy {
            filter: name(vless_live)
            policy: fixed(0)
        }
        }
        routing {
        l4proto(tcp) && dport(443) -> proxy
        fallback: direct
        }
        "#,
        );
        let plan = build_resident_dataplane_plan(&config).unwrap();
        let proxy = plan.default_proxy_snapshot().unwrap();
        let utls = proxy.utls_fingerprint.unwrap();
        assert_eq!(utls.source, "global utls_imitate");
        assert_eq!(utls.requested, "safari");
        assert_eq!(utls.canonical, "safari_auto");
        assert_eq!(utls.family, "safari");
    }

    #[test]
    fn resident_dataplane_plan_uses_global_utls_when_link_fp_is_empty() {
        let config = parse_config(
            r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        tls_implementation: utls
        utls_imitate: edge
        }
        node {
        vless_live: 'vless://01234567-89ab-cdef-0123-456789abcdef@156.246.90.2:443?security=tls&type=tcp&sni=office.example&flow=xtls-rprx-vision&fp=&alpn=h2,http/1.1'
        }
        group {
        proxy {
            filter: name(vless_live)
            policy: fixed(0)
        }
        }
        routing {
        l4proto(tcp) && dport(443) -> proxy
        fallback: direct
        }
        "#,
        );
        let plan = build_resident_dataplane_plan(&config).unwrap();
        let proxy = plan.default_proxy_snapshot().unwrap();
        let utls = proxy.utls_fingerprint.unwrap();
        assert_eq!(utls.source, "global utls_imitate");
        assert_eq!(utls.requested, "edge");
        assert_eq!(utls.canonical, "edge_auto");
        assert_eq!(utls.family, "edge");
    }

    #[test]
    fn resident_dataplane_plan_uses_document_default_when_global_utls_has_empty_imitate() {
        let config = parse_config(
            r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        tls_implementation: utls
        utls_imitate: ""
        }
        node {
        vless_live: 'vless://01234567-89ab-cdef-0123-456789abcdef@156.246.90.2:443?security=tls&type=tcp&sni=office.example&flow=xtls-rprx-vision&alpn=h2,http/1.1'
        }
        group {
        proxy {
            filter: name(vless_live)
            policy: fixed(0)
        }
        }
        routing {
        l4proto(tcp) && dport(443) -> proxy
        fallback: direct
        }
        "#,
        );
        let plan = build_resident_dataplane_plan(&config).unwrap();
        let proxy = plan.default_proxy_snapshot().unwrap();
        let utls = proxy.utls_fingerprint.unwrap();
        assert_eq!(utls.source, "default fingerprint");
        assert_eq!(utls.requested, "chrome");
        assert_eq!(utls.canonical, "chrome_auto");
        assert_eq!(utls.family, "chrome");
    }

    #[test]
    fn resident_dataplane_plan_rejects_unknown_utls_fingerprint() {
        let config = parse_config(
            r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        }
        node {
        vless_live: 'vless://01234567-89ab-cdef-0123-456789abcdef@156.246.90.2:443?security=tls&type=tcp&sni=office.example&flow=xtls-rprx-vision&fp=Chrome&alpn=h2,http/1.1'
        }
        group {
        proxy {
            filter: name(vless_live)
            policy: fixed(0)
        }
        }
        routing {
        l4proto(tcp) && dport(443) -> proxy
        fallback: direct
        }
        "#,
        );
        let err = build_resident_dataplane_plan(&config).unwrap_err();
        assert!(err.contains("unsupported link fp Chrome"));
        assert!(err.contains("unknown uTLS Client Hello ID: Chrome"));
    }

    #[test]
    fn resident_dataplane_plan_rejects_non_document_no_fingerprint_aliases() {
        for value in ["no", "none", "off", "false", "0"] {
            let config = parse_config(&format!(
                r#"
        global {{
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        }}
        node {{
        vless_live: 'vless://01234567-89ab-cdef-0123-456789abcdef@156.246.90.2:443?security=tls&type=tcp&sni=office.example&flow=xtls-rprx-vision&fp={value}&alpn=h2,http/1.1'
        }}
        group {{
        proxy {{
            filter: name(vless_live)
            policy: fixed(0)
        }}
        }}
        routing {{
        l4proto(tcp) && dport(443) -> proxy
        fallback: direct
        }}
        "#
            ));
            let err = build_resident_dataplane_plan(&config).unwrap_err();
            assert!(err.contains(&format!("unsupported link fp {value}")));
            assert!(err.contains(&format!("unknown uTLS Client Hello ID: {value}")));
        }
    }

    #[test]
    fn resident_utls_fingerprint_resolution_uses_generic_registry() {
        for (name, canonical, family) in [
            ("chrome", "chrome_auto", "chrome"),
            ("firefox_105", "firefox_105", "firefox"),
            ("safari_16_0", "safari_16_0", "safari"),
            ("ios_14", "ios_14", "ios"),
            ("edge_106", "edge_106", "edge"),
            ("android_11_okhttp", "android_11_okhttp", "android"),
            ("randomizednoalpn", "randomizednoalpn", "random"),
        ] {
            let plan = resolve_resident_utls_fingerprint("test", name).unwrap();
            assert_eq!(plan.name, name);
            assert_eq!(plan.canonical, canonical);
            assert_eq!(plan.family, family);
        }

        let randomized_no_alpn =
            resolve_resident_utls_fingerprint("test", "randomizednoalpn").unwrap();
        assert!(randomized_no_alpn.randomized);
        assert_eq!(randomized_no_alpn.alpn_policy, "force-no-alpn");
    }
}
