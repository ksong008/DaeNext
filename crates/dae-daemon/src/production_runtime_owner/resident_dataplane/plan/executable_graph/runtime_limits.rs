use super::*;

pub(super) fn fingerprint_template_mode_label(
    fingerprint: &ResidentUtlsFingerprintPlan,
) -> &'static str {
    dae_outbound::shared_transport::resolve_utls_template_mode(&fingerprint.name)
        .map(dae_outbound::shared_transport::utls_template_mode_label)
        .unwrap_or("Unresolved")
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum QuicLifecycleScope {
    None,
    PerFlow,
    GenerationOwned,
}

pub(super) fn quic_lifecycle_value(scope: QuicLifecycleScope) -> Value {
    match scope {
        QuicLifecycleScope::None => Value::Null,
        QuicLifecycleScope::PerFlow => json!({
            "endpointScope": "per-flow",
            "connectionScope": "per-flow",
            "clientConfigScope": "per-flow",
            "crossFlowConnectionReuse": false,
            "pooling": "not-implemented",
        }),
        QuicLifecycleScope::GenerationOwned => json!({
            "endpointScope": "generation-graph-transport-owner",
            "connectionScope": "generation-graph-transport-owner",
            "clientConfigScope": "generation-graph-transport-owner",
            "crossFlowConnectionReuse": true,
            "pooling": "single-flight-physical-owner",
        }),
    }
}

pub(super) fn stream_wrapper_runtime_limits_value(
    stream_wrapper: &str,
    quic_scope: QuicLifecycleScope,
) -> Value {
    match stream_wrapper {
        "grpc" => json!({
            "messageCompression": "identity-only",
            "compressedInboundHunk": "fail-closed",
            "carrierScope": "per-flow-h2-connection",
            "crossFlowCarrierReuse": false,
        }),
        "mux" => json!({
            "wireMultiplexing": true,
            "carrierScope": "per-flow-tls-carrier",
            "logicalStreamsPerCarrier": 1,
            "crossFlowCarrierReuse": false,
        }),
        "quic-stream" if quic_scope == QuicLifecycleScope::GenerationOwned => json!({
            "carrierScope": "generation-graph-transport-owner",
            "logicalStreamsPerCarrier": "bounded-by-runtime-profile",
            "crossFlowCarrierReuse": true,
        }),
        "quic-stream" => json!({
            "carrierScope": "per-flow-quic-connection",
            "logicalStreamsPerCarrier": 1,
            "crossFlowCarrierReuse": false,
        }),
        "xhttp" => json!({
            "carrierScope": "configuration-dependent-xmux",
            "crossFlowCarrierReuse": "configuration-dependent",
        }),
        "connect-udp-h2" => json!({
            "carrierScope": "generation-owned-h2-connection-pool",
            "sessionScope": "per-target-extended-connect-stream",
            "crossFlowCarrierReuse": true,
            "crossTargetSessionReuse": false,
        }),
        "connect-udp-h3" => json!({
            "carrierScope": "generation-owned-h3-actor-pool",
            "sessionScope": "per-target-extended-connect-stream",
            "crossFlowCarrierReuse": true,
            "crossTargetSessionReuse": false,
        }),
        _ => json!({
            "carrierScope": "per-flow",
            "crossFlowCarrierReuse": false,
        }),
    }
}

pub(super) fn shared_provider_cache_labels(
    stream_wrapper: &str,
    quic_scope: QuicLifecycleScope,
) -> &'static [&'static str] {
    if quic_scope == QuicLifecycleScope::GenerationOwned {
        return &[
            "quic-client-config",
            "quic-endpoint",
            "quic-connection",
            "protocol-transport-owner",
        ];
    }
    match stream_wrapper {
        "connect-udp-h2" => &[
            "tls-client-config",
            "connect-udp-h2-connection-pool",
            "connect-udp-h2-session-capacity",
        ],
        "connect-udp-h3" => &[
            "quic-client-config",
            "connect-udp-h3-actor-pool",
            "connect-udp-h3-session-capacity",
        ],
        _ => &["tls-client-config", "fingerprint-aware-tls-connector"],
    }
}

pub(super) fn per_flow_provider_labels(scope: QuicLifecycleScope) -> &'static [&'static str] {
    if scope == QuicLifecycleScope::PerFlow {
        &["quic-client-config", "quic-endpoint", "quic-connection"]
    } else {
        &[]
    }
}

pub(super) fn quic_lifecycle_scope(handler: &ResidentProxyProtocolPlan) -> QuicLifecycleScope {
    match handler {
        ResidentProxyProtocolPlan::Hysteria2QuicTcp { .. }
        | ResidentProxyProtocolPlan::TuicQuicTcp { .. } => QuicLifecycleScope::GenerationOwned,
        ResidentProxyProtocolPlan::JuicityQuicTcp { .. } => QuicLifecycleScope::PerFlow,
        _ => QuicLifecycleScope::None,
    }
}
