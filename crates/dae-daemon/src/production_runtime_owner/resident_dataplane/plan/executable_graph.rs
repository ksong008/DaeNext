use serde_json::{Value, json};

use super::super::{link_hash, redacted_link_source};
use super::{
    RESIDENT_UDP_CLEANUP_OWNER, RESIDENT_UDP_CLEANUP_POLICY, ResidentProxyPlan,
    ResidentProxyProtocolPlan, ResidentSecurityUnderlayPlan, ResidentTcpCarrierOwnership,
    ResidentUdpChainAdmission, ResidentUdpExecutionAgreement, ResidentUtlsFingerprintPlan,
    ResidentXhttpHttpVersion, ResidentXhttpMode, ResidentXhttpSettingsPlan,
    resident_udp_chain_admission,
};

mod runtime_limits;
use self::runtime_limits::*;
mod udp_effective;
use self::udp_effective::EffectiveUdpExecutionAgreement;

const EXECUTABLE_GRAPH_SCHEMA_VERSION: u64 = 2;
const RUNTIME_COMPONENT_EVIDENCE_SCHEMA_VERSION: u64 = 2;
const STREAM_WRAPPER_FACTORY_SCHEMA_VERSION: u64 = 2;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::production_runtime_owner::resident_dataplane) struct ResidentExecutableGraphDescriptor
{
    graph_id: String,
    link_hash: String,
    redacted_link_source: String,
    protocol_framing: &'static str,
    tcp_executor: &'static str,
    endpoint_host_hash: String,
    endpoint_port: u16,
    transport_underlay: String,
    security_underlay: String,
    stream_wrapper: String,
    stream_host_hash: Option<String>,
    stream_path_present: bool,
    stream_path_hash: Option<String>,
    udp_agreement: ResidentUdpExecutionAgreement,
    xhttp_mode: ResidentXhttpMode,
    xhttp_settings: ResidentXhttpSettingsPlan,
    xhttp_download_mode: Option<ResidentXhttpMode>,
    xhttp_download_settings: Option<ResidentXhttpSettingsPlan>,
    flow: String,
    alpn: Vec<String>,
    allow_insecure: bool,
    verification_policy: String,
    utls_fingerprint: Option<ResidentUtlsFingerprintPlan>,
    chain_parent_count: usize,
    udp_chain_admission: ResidentUdpChainAdmission,
    quic_lifecycle_scope: QuicLifecycleScope,
    tcp_carrier_ownership: ResidentTcpCarrierOwnership,
    mark: u32,
    mptcp: bool,
}

impl ResidentExecutableGraphDescriptor {
    pub(super) fn from_proxy(proxy: &ResidentProxyPlan) -> Self {
        let execution = proxy.execution_plan();
        let executor_contract = proxy.executor_contract();
        Self {
            graph_id: proxy.graph_id.clone(),
            link_hash: proxy.graph_link_hash.clone(),
            redacted_link_source: scheme_only_redacted_source(&proxy.redacted_link_source),
            protocol_framing: proxy.protocol,
            tcp_executor: executor_contract.tcp_executor,
            endpoint_host_hash: link_hash(&proxy.server_host),
            endpoint_port: proxy.server_port,
            transport_underlay: execution.security.transport_label().to_owned(),
            security_underlay: execution.security.graph_label().to_owned(),
            stream_wrapper: execution.wrapper.graph_label().to_owned(),
            stream_host_hash: if proxy.stream_host.is_empty() {
                None
            } else {
                Some(link_hash(&proxy.stream_host))
            },
            stream_path_present: !proxy.stream_path.is_empty(),
            stream_path_hash: if proxy.stream_path.is_empty() {
                None
            } else {
                Some(link_hash(&proxy.stream_path))
            },
            udp_agreement: execution.udp.agreement(),
            xhttp_mode: proxy.xhttp_mode,
            xhttp_settings: proxy.xhttp_settings.clone(),
            xhttp_download_mode: proxy.xhttp_download.as_ref().map(|download| download.mode),
            xhttp_download_settings: proxy
                .xhttp_download
                .as_ref()
                .map(|download| download.settings.clone()),
            flow: proxy.flow.clone(),
            alpn: proxy.alpn.clone(),
            allow_insecure: proxy.allow_insecure,
            verification_policy: graph_verification_policy(proxy),
            utls_fingerprint: proxy.utls_fingerprint.clone(),
            chain_parent_count: chain_parent_count(proxy),
            udp_chain_admission: resident_udp_chain_admission(proxy),
            quic_lifecycle_scope: quic_lifecycle_scope(&proxy.handler),
            tcp_carrier_ownership: execution.tcp_carrier_ownership(),
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
        let udp_execution_agreement = self.udp_execution_agreement_value();
        let packet_session_manager = self.packet_session_manager_value();
        let probe_executor = self.probe_executor_value(reload_generation);
        let admission_block_reason = underlay_factory
            .get("unsupportedReason")
            .cloned()
            .unwrap_or(Value::Null);
        let admission_status = if admission_block_reason.is_null() {
            "admitted"
        } else {
            "fail-closed"
        };
        let effective_udp =
            EffectiveUdpExecutionAgreement::new(self.udp_agreement, self.udp_chain_admission);
        json!({
            "schemaVersion": EXECUTABLE_GRAPH_SCHEMA_VERSION,
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
                "pathEvidence": self.stream_path_evidence_value(),
            },
            "protocolFraming": self.protocol_framing,
            "tcpExecutor": self.tcp_executor,
            "tcpCarrierContract": self.tcp_carrier_ownership.json(),
            "packetSemantics": effective_udp.packet_semantics().as_str(),
            "rawChildPacketSemantics": self.udp_agreement.packet_semantics().as_str(),
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
                "status": admission_status,
                "source": "resident-plan",
                "unsupportedReason": admission_block_reason,
            },
            "runtimeComponents": {
                "underlayFactory": underlay_factory,
                "streamWrapperFactory": stream_wrapper_factory,
                "chainExecutor": chain_executor,
                "generationCache": generation_cache,
                "udpExecutionAgreement": udp_execution_agreement,
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
            "schemaVersion": RUNTIME_COMPONENT_EVIDENCE_SCHEMA_VERSION,
            "graphId": self.graph_id,
            "underlayFactory": self.underlay_factory_value(),
            "streamWrapperFactory": self.stream_wrapper_factory_value(),
            "chainExecutor": self.chain_executor_value(),
            "generationCache": self.generation_cache_value(reload_generation),
            "udpExecutionAgreement": self.udp_execution_agreement_value(),
            "packetSessionManager": self.packet_session_manager_value(),
            "probeExecutor": self.probe_executor_value(reload_generation),
            "tcpCarrierContract": self.tcp_carrier_ownership.json(),
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
                "defaultAlpn": &fingerprint.default_alpn,
                "templateMode": fingerprint_template_mode_label(fingerprint),
                "fullUtlsParityDeclared": false,
            })
        });
        let reality_with_fingerprint =
            self.security_underlay == "reality" && self.utls_fingerprint.is_some();
        let provider = if reality_with_fingerprint {
            "reality-boringssl"
        } else {
            match self.security_underlay.as_str() {
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
            }
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
            "quicLifecycle": quic_lifecycle_value(self.quic_lifecycle_scope),
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
            "http-transport" => ("admitted", "resident-http-connect-transport", Value::Null),
            "grpc" => ("admitted", "resident-grpc-h2-stream", Value::Null),
            "h2" => ("admitted", "resident-http2-body-stream", Value::Null),
            "connect-udp-h2" => (
                "admitted",
                "resident-connect-udp-h2-capsule-session",
                Value::Null,
            ),
            "connect-udp-h3" => (
                "admitted",
                "resident-connect-udp-h3-datagram-session",
                Value::Null,
            ),
            "meek" => ("admitted", "resident-meek-polling", Value::Null),
            "mux" => ("admitted", "resident-vless-mux-framing", Value::Null),
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
            "schemaVersion": STREAM_WRAPPER_FACTORY_SCHEMA_VERSION,
            "status": status,
            "wrapper": self.stream_wrapper,
            "provider": provider,
            "endpoint": {
                "hostHash": self.stream_host_hash,
                "pathEvidence": self.stream_path_evidence_value(),
            },
            "protocolFraming": self.protocol_framing,
            "runtimeLimits": stream_wrapper_runtime_limits_value(
                &self.stream_wrapper,
                self.quic_lifecycle_scope,
            ),
            "xhttpMode": if self.stream_wrapper == "xhttp" {
                json!(self.xhttp_mode.as_str())
            } else {
                Value::Null
            },
            "xhttpExtendedSettings": if self.stream_wrapper == "xhttp" {
                json!({
                    "primary": xhttp_settings_evidence_value(&self.xhttp_settings),
                    "download": self.xhttp_download_settings.as_ref().map(|settings| {
                        json!({
                            "mode": self
                                .xhttp_download_mode
                                .map(ResidentXhttpMode::as_str)
                                .unwrap_or("packet-up"),
                            "settings": xhttp_settings_evidence_value(settings),
                        })
                    }),
                })
            } else {
                Value::Null
            },
            "unsupportedReason": unsupported_reason,
        })
    }

    fn stream_path_evidence_value(&self) -> Value {
        json!({
            "present": self.stream_path_present,
            "hash": self.stream_path_hash,
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
            "sharedProviderCaches": shared_provider_cache_labels(
                &self.stream_wrapper,
                self.quic_lifecycle_scope,
            ),
            "perFlowProviders": per_flow_provider_labels(self.quic_lifecycle_scope),
        })
    }

    fn udp_execution_agreement_value(&self) -> Value {
        let agreement =
            EffectiveUdpExecutionAgreement::new(self.udp_agreement, self.udp_chain_admission);
        json!({
            "schemaVersion": 1,
            "disposition": agreement.disposition().as_str(),
            "executor": agreement.executor_label(),
            "packetSemantics": agreement.packet_semantics().as_str(),
            "policyClosed": agreement.policy_closed(),
            "negativePathReady": agreement.negative_path_ready(),
            "expectedPacketSessionStatus": agreement.component_status(),
            "expectedProbeStatus": agreement.component_status(),
            "unsupportedReason": agreement.unsupported_reason(),
            "generationOwned": true,
            "cleanupOwner": RESIDENT_UDP_CLEANUP_OWNER,
            "cleanupPolicy": RESIDENT_UDP_CLEANUP_POLICY,
            "sourceContract": agreement.source_contract().json(),
        })
    }

    fn packet_session_manager_value(&self) -> Value {
        let agreement =
            EffectiveUdpExecutionAgreement::new(self.udp_agreement, self.udp_chain_admission);
        let chain_unsupported_reason = self.udp_chain_admission.unsupported_reason();
        let unsupported_reason = agreement
            .unsupported_reason()
            .map_or(Value::Null, Value::from);
        json!({
            "schemaVersion": 1,
            "status": agreement.component_status(),
            "manager": "resident-udp-session-manager",
            "executor": agreement.executor_label(),
            "graphId": self.graph_id,
            "packetSemantics": agreement.packet_semantics().as_str(),
            "agreementDisposition": agreement.disposition().as_str(),
            "policyClosed": agreement.policy_closed(),
            "negativePathReady": agreement.negative_path_ready(),
            "chainCarrier": self.udp_chain_admission.carrier(),
            "chainUnsupportedReason": chain_unsupported_reason,
            "unsupportedReason": unsupported_reason,
            "generationOwned": true,
            "cleanupOwner": RESIDENT_UDP_CLEANUP_OWNER,
            "cleanupPolicy": RESIDENT_UDP_CLEANUP_POLICY,
            "keyFields": [
                "graphId",
                "outbound",
                "peer",
                "originalDestination",
                "packetSemantics"
            ],
            "limitSource": "resident-udp-session-limit",
            "transientExchangeCompatible": agreement.transient_exchange_compatible(),
            "sourceContract": agreement.source_contract().json(),
        })
    }

    fn probe_executor_value(&self, reload_generation: Option<u64>) -> Value {
        let agreement =
            EffectiveUdpExecutionAgreement::new(self.udp_agreement, self.udp_chain_admission);
        json!({
            "schemaVersion": 1,
            "status": "admitted",
            "executor": "resident-executable-graph",
            "trafficExecutor": self.tcp_executor,
            "graphId": self.graph_id,
            "reloadGeneration": reload_generation,
            "materialized": reload_generation.is_some(),
            "sharesTrafficExecutor": true,
            "latencyState": "group-selector",
            "udp": {
                "schemaVersion": 1,
                "status": agreement.component_status(),
                "executor": agreement.executor_label(),
                "packetSemantics": agreement.packet_semantics().as_str(),
                "agreementDisposition": agreement.disposition().as_str(),
                "policyClosed": agreement.policy_closed(),
                "negativePathReady": agreement.negative_path_ready(),
                "unsupportedReason": agreement.unsupported_reason(),
                "generationOwned": true,
                "cleanupOwner": RESIDENT_UDP_CLEANUP_OWNER,
                "cleanupPolicy": RESIDENT_UDP_CLEANUP_POLICY,
                "sourceContract": agreement.source_contract().json(),
            },
            "unsupportedReason": Value::Null,
        })
    }
}

fn scheme_only_redacted_source(redacted_source: &str) -> String {
    let scheme = redacted_source
        .split_once(':')
        .map(|(scheme, _)| scheme)
        .unwrap_or("link");
    format!("{scheme}:<redacted>")
}

fn xhttp_settings_evidence_value(settings: &ResidentXhttpSettingsPlan) -> Value {
    json!({
        "headers": {
            "names": settings.headers.keys().cloned().collect::<Vec<_>>(),
            "valuesRedacted": true,
        },
        "xPadding": {
            "bytes": settings.x_padding_bytes,
            "effectiveBytes": settings.normalized_x_padding_bytes(),
            "obfsMode": settings.x_padding_obfs_mode,
            "keyFieldName": &settings.x_padding_key,
            "headerFieldName": &settings.x_padding_header,
            "placement": settings.x_padding_placement.as_str(),
            "method": settings.x_padding_method.as_str(),
        },
        "uplink": {
            "httpMethod": &settings.uplink_http_method,
            "dataPlacement": settings.uplink_data_placement.as_str(),
            "dataFieldName": settings.normalized_uplink_data_key(),
            "chunkSize": settings.uplink_chunk_size,
            "effectiveChunkSize": settings.normalized_uplink_chunk_size(),
        },
        "metadata": {
            "sessionIDPlacement": settings.session_id_placement.as_str(),
            "sessionIDFieldName": settings.normalized_session_key(),
            "sessionIDTableLength": settings.session_id_table.len(),
            "sessionIDLength": settings.session_id_length,
            "seqPlacement": settings.seq_placement.as_str(),
            "seqFieldName": settings.normalized_seq_key(),
        },
        "headersPolicy": {
            "noGRPCHeader": settings.no_grpc_header,
            "noSSEHeader": settings.no_sse_header,
            "serverMaxHeaderBytes": settings.server_max_header_bytes,
            "effectiveServerMaxHeaderBytes": settings.normalized_server_max_header_bytes(),
        },
        "streamOne": {
            "scMaxEachPostBytes": settings.sc_max_each_post_bytes,
            "effectiveScMaxEachPostBytes": settings.normalized_sc_max_each_post_bytes(),
            "scMinPostsIntervalMs": settings.sc_min_posts_interval_ms,
            "effectiveScMinPostsIntervalMs": settings.normalized_sc_min_posts_interval_ms(),
            "scMaxBufferedPosts": settings.sc_max_buffered_posts,
            "effectiveScMaxBufferedPosts": settings.normalized_sc_max_buffered_posts(),
            "scStreamUpServerSecs": settings.sc_stream_up_server_secs,
            "effectiveScStreamUpServerSecs": settings.normalized_sc_stream_up_server_secs(),
        },
    })
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

fn chain_parent_count(proxy: &ResidentProxyPlan) -> usize {
    let mut count = 0;
    let mut current = proxy.chain_parent.as_deref();
    while let Some(parent) = current {
        count += 1;
        current = parent.chain_parent.as_deref();
    }
    count
}

fn graph_verification_policy(proxy: &ResidentProxyPlan) -> String {
    match &proxy.handler {
        ResidentProxyProtocolPlan::Hysteria2QuicTcp { tls_identity, .. } => {
            tls_identity.verification_label().to_owned()
        }
        ResidentProxyProtocolPlan::JuicityQuicTcp { allow_insecure, .. } if *allow_insecure => {
            "explicit-insecure".to_owned()
        }
        ResidentProxyProtocolPlan::JuicityQuicTcp {
            pinned_certchain_sha256,
            ..
        } if !pinned_certchain_sha256.is_empty() => "pinned-certchain-sha256".to_owned(),
        _ if matches!(
            proxy.execution_plan().security,
            ResidentSecurityUnderlayPlan::None
                | ResidentSecurityUnderlayPlan::Aead
                | ResidentSecurityUnderlayPlan::Aead2022
                | ResidentSecurityUnderlayPlan::LegacyCipher
        ) =>
        {
            "none".to_owned()
        }
        _ if proxy.allow_insecure => "explicit-insecure".to_owned(),
        _ => "system-roots".to_owned(),
    }
}
