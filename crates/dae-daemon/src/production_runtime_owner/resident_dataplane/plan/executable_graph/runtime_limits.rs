use super::*;

pub(super) fn fingerprint_template_mode_label(
    fingerprint: &ResidentUtlsFingerprintPlan,
) -> &'static str {
    dae_outbound::shared_transport::resolve_utls_template_mode(&fingerprint.name)
        .map(dae_outbound::shared_transport::utls_template_mode_label)
        .unwrap_or("Unresolved")
}

pub(super) fn quic_lifecycle_value(quic_per_flow: bool) -> Value {
    if !quic_per_flow {
        return Value::Null;
    }
    json!({
        "endpointScope": "per-flow",
        "connectionScope": "per-flow",
        "clientConfigScope": "per-flow",
        "crossFlowConnectionReuse": false,
        "pooling": "not-implemented",
    })
}

pub(super) fn stream_wrapper_runtime_limits_value(stream_wrapper: &str) -> Value {
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

pub(super) fn shared_provider_cache_labels(stream_wrapper: &str) -> &'static [&'static str] {
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

pub(super) fn per_flow_provider_labels(quic_per_flow: bool) -> &'static [&'static str] {
    if quic_per_flow {
        &["quic-client-config", "quic-endpoint", "quic-connection"]
    } else {
        &[]
    }
}

pub(super) fn is_quic_handler(handler: &ResidentProxyProtocolPlan) -> bool {
    matches!(
        handler,
        ResidentProxyProtocolPlan::Hysteria2QuicTcp { .. }
            | ResidentProxyProtocolPlan::TuicQuicTcp { .. }
            | ResidentProxyProtocolPlan::JuicityQuicTcp { .. }
    )
}
