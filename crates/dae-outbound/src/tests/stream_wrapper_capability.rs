use super::*;

#[test]
fn stream_wrapper_capability_records_closed_matrix_state() {
    let contract = stream_wrapper_capability_contract();
    let rendered = contract.to_value();

    assert_eq!(contract.schema, "stream-wrapper-capability");
    assert_eq!(contract.schema_version, 2);
    assert!(contract.websocket_wss_loopback_ready);
    assert!(contract.resident_source_admission_ready);
    assert!(contract.expanded_stream_wrapper_complete);
    assert!(!contract.full_fidelity_and_pooling_complete);
    assert_eq!(rendered["runtimeLimitsVisible"], true);

    let rows = rendered["rows"].as_array().unwrap();
    let grpc = rows
        .iter()
        .find(|row| row["wrapperId"] == "grpc-wrapper")
        .unwrap();
    assert_eq!(grpc["messageCompression"], "identity-only");
    assert_eq!(grpc["carrierScope"], "per-flow-h2-connection");
    assert_eq!(grpc["crossFlowReuse"], "none");
    assert_eq!(
        grpc["unsupportedFeatures"],
        serde_json::json!(["compressed-grpc-hunk"])
    );

    let mux = rows
        .iter()
        .find(|row| row["wrapperId"] == "mux-wrapper")
        .unwrap();
    assert_eq!(mux["provider"], "resident-vless-mux-framing");
    assert_eq!(mux["carrierScope"], "per-flow-tls-carrier");
    assert_eq!(mux["logicalStreamsPerCarrier"], "one");
    assert_eq!(mux["crossFlowReuse"], "none");

    let quic = rows
        .iter()
        .find(|row| row["wrapperId"] == "quic-stream-wrapper")
        .unwrap();
    assert_eq!(quic["carrierScope"], "per-flow-quic-connection");
    assert_eq!(quic["crossFlowReuse"], "none");
}

#[test]
fn stream_wrapper_capability_rows_follow_matrix_contract() {
    for row in stream_wrapper_capability_rows() {
        match row.source_admission {
            "admitted" => {
                assert!(
                    matches!(row.status, "resident-live-final" | "resident-live-scoped"),
                    "{}",
                    row.wrapper_id
                );
                if row.status == "resident-live-scoped" {
                    assert!(!row.unsupported_features.is_empty(), "{}", row.wrapper_id);
                }
                assert_eq!(row.blocker_id, None, "{}", row.wrapper_id);
                assert_eq!(
                    row.reload_cleanup, "drop-on-graph-diff-or-runtime-stop",
                    "{}",
                    row.wrapper_id
                );
                assert_ne!(row.provider, "pending", "{}", row.wrapper_id);
                assert_ne!(row.security_underlay, "pending", "{}", row.wrapper_id);
                assert_ne!(row.packet_semantics, "pending", "{}", row.wrapper_id);
                assert_ne!(row.carrier_scope, "pending", "{}", row.wrapper_id);
                assert_ne!(row.cross_flow_reuse, "pending", "{}", row.wrapper_id);
                assert_eq!(
                    row.evidence_requirements,
                    &["large-page-live", "benchmark", "cleanup"],
                    "{}",
                    row.wrapper_id
                );
            }
            "blocked" => {
                assert_eq!(row.status, "blocked", "{}", row.wrapper_id);
                assert!(row.blocker_id.is_some(), "{}", row.wrapper_id);
                assert_eq!(row.reload_cleanup, "pending", "{}", row.wrapper_id);
            }
            other => panic!("unexpected stream wrapper admission {other}"),
        }
    }
}

#[test]
fn stream_wrapper_capability_contains_no_runtime_version_suffix_labels() {
    let rendered = stream_wrapper_capability_contract().to_value().to_string();
    let forbidden = ["-", "v", "1"].concat();

    assert!(
        !rendered.contains(&forbidden),
        "stream wrapper capability must not expose runtime version suffix labels"
    );
}
