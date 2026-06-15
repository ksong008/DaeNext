use serde_json::{Value, json};

use super::super::{link_hash, redacted_link_source};
use super::{
    ResidentProxyPlan, ResidentProxyProtocolPlan, ResidentUtlsFingerprintPlan,
    ResidentXhttpHttpVersion, ResidentXhttpMode,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::production_runtime_owner::resident_dataplane) struct ResidentExecutableGraphDescriptor
{
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
    xhttp_mode: ResidentXhttpMode,
    flow: String,
    alpn: Vec<String>,
    allow_insecure: bool,
    verification_policy: String,
    utls_fingerprint: Option<ResidentUtlsFingerprintPlan>,
    chain_parent_count: usize,
    mark: u32,
    mptcp: bool,
}

impl ResidentExecutableGraphDescriptor {
    pub(super) fn from_proxy(proxy: &ResidentProxyPlan) -> Self {
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
            xhttp_mode: proxy.xhttp_mode,
            flow: proxy.flow.clone(),
            alpn: proxy.alpn.clone(),
            allow_insecure: proxy.allow_insecure,
            verification_policy: graph_verification_policy(proxy),
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
            "reality" => "rustls-reality",
            "insecure-tls" => "rustls",
            "tls-fragment" => "rustls",
            "standard-tls" => "rustls",
            "quic-tls" => "quinn-rustls",
            "aead" => "protocol-aead-codec",
            "aead-2022" => "protocol-aead-2022-codec",
            "legacy-cipher" => "protocol-legacy-stream-codec",
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
            "verificationPolicy": self.verification_policy,
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
            "mux" => ("admitted", "resident-shared-mux-stream", Value::Null),
            "xhttp" => (
                "admitted",
                self.xhttp_http_version().provider_for_mode(self.xhttp_mode),
                Value::Null,
            ),
            "simple-obfs-http" => ("admitted", "resident-simple-obfs-http", Value::Null),
            "simple-obfs-tls" => ("admitted", "resident-simple-obfs-tls", Value::Null),
            "legacy-obfs" => ("admitted", "resident-legacy-obfs-http-simple", Value::Null),
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
            "xhttpMode": if self.stream_wrapper == "xhttp" {
                json!(self.xhttp_mode.as_str())
            } else {
                Value::Null
            },
            "unsupportedReason": unsupported_reason,
        })
    }

    fn xhttp_http_version(&self) -> ResidentXhttpHttpVersion {
        if self.security_underlay == "reality" {
            ResidentXhttpHttpVersion::H2
        } else {
            ResidentXhttpHttpVersion::from_tls_alpn(&self.alpn)
        }
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
            "manager": "resident-udp-session-manager",
            "graphId": self.graph_id,
            "packetSemantics": self.packet_semantics,
            "keyFields": [
                "graphId",
                "outbound",
                "peer",
                "originalDestination",
                "packetSemantics"
            ],
            "limitSource": "resident-udp-session-limit",
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
pub(super) struct ResidentGraphIdentity {
    pub(super) graph_id: String,
    pub(super) link_hash: String,
    pub(super) redacted_link_source: String,
}

pub(super) fn resident_graph_identity(link: &str) -> ResidentGraphIdentity {
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
            "tls" if proxy.allow_insecure => "insecure-tls".to_owned(),
            "tls" if proxy.tls_fragment.is_some() => "tls-fragment".to_owned(),
            "tls" => "standard-tls".to_owned(),
            other => other.to_owned(),
        }
    }
}

fn graph_verification_policy(proxy: &ResidentProxyPlan) -> String {
    match &proxy.handler {
        ResidentProxyProtocolPlan::JuicityQuicTcp { allow_insecure, .. } if *allow_insecure => {
            "explicit-insecure".to_owned()
        }
        ResidentProxyProtocolPlan::JuicityQuicTcp {
            pinned_certchain_sha256,
            ..
        } if !pinned_certchain_sha256.is_empty() => "pinned-certchain-sha256".to_owned(),
        _ if matches!(proxy.tls.as_str(), "" | "none") => "none".to_owned(),
        _ if proxy.allow_insecure => "explicit-insecure".to_owned(),
        _ => "system-roots".to_owned(),
    }
}

fn graph_stream_wrapper(proxy: &ResidentProxyPlan) -> String {
    match proxy.handler {
        ResidentProxyProtocolPlan::AnyTlsTcpTls { .. } => return "frame-stream".to_owned(),
        ResidentProxyProtocolPlan::VlessMuxTcpTls { .. } => return "mux".to_owned(),
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
        ResidentProxyProtocolPlan::VlessVisionTcpTls { .. }
            if proxy.net == "xhttp" && proxy.flow.is_empty() =>
        {
            "udp-over-stream".to_owned()
        }
        ResidentProxyProtocolPlan::VlessVisionTcpTls { .. } => "xudp".to_owned(),
        ResidentProxyProtocolPlan::VlessMuxTcpTls { .. } => "multiplexed-stream".to_owned(),
        ResidentProxyProtocolPlan::ShadowsocksAeadTcp { .. } => "datagram-aead".to_owned(),
        ResidentProxyProtocolPlan::Shadowsocks2022Tcp { .. } => "datagram-aead-2022".to_owned(),
        ResidentProxyProtocolPlan::ShadowsocksSimpleObfsHttpTcp { .. }
        | ResidentProxyProtocolPlan::ShadowsocksSimpleObfsTlsTcp { .. }
        | ResidentProxyProtocolPlan::ShadowsocksV2rayPluginTlsWsTcp { .. }
        | ResidentProxyProtocolPlan::Shadowsocks2022SimpleObfsHttpTcp { .. }
        | ResidentProxyProtocolPlan::ShadowsocksRHttpSimpleTcp { .. } => {
            "plugin-wrapper-stream".to_owned()
        }
        ResidentProxyProtocolPlan::Hysteria2QuicTcp { .. }
        | ResidentProxyProtocolPlan::TuicQuicTcp { .. }
        | ResidentProxyProtocolPlan::JuicityQuicTcp { .. } => "quic-datagram-or-stream".to_owned(),
        _ => "udp-over-stream-or-datagram".to_owned(),
    }
}
