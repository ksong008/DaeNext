use super::*;
pub(crate) fn insert_outbound_matrix_and_source_contract(
    report: &mut serde_json::Map<String, Value>,
) {
    for key in [
        "outbound_production_matrix_contract_ready",
        "outbound_production_matrix_runtime_state_ready",
        "outbound_matrix_entries_ready",
        "parser_export_metadata_matrix_ready",
        "tcp_udp_dataplane_matrix_ready",
        "transport_underlay_matrix_ready",
        "route_group_connectivity_matrix_ready",
        "reload_behavior_matrix_ready",
        "live_smoke_matrix_ready",
        "go_outbound_fallback_retirement_matrix_ready",
        "outbound_production_matrix_typed_report_ready",
        "go_outbound_fallback_retired_candidate",
        "source_shape_registry_contract_ready",
        "source_shape_registry_open",
        "expanded_source_matrix_open",
        "expanded_source_matrix_blocked_rows_visible",
        "excluded_stream_wrapper_source_matrix_open",
        "excluded_stream_wrapper_source_matrix_complete",
        "excluded_stream_wrapper_source_matrix_release_gate_ready",
        "scoped_expanded_source_matrix_complete",
        "scoped_expanded_source_matrix_release_gate_ready",
        "stream_wrapper_capability_contract_ready",
        "websocket_wss_loopback_ready",
        "stream_wrapper_resident_source_admission_ready",
        "expanded_stream_wrapper_complete",
    ] {
        report.insert(key.to_owned(), json!(true));
    }
    for key in [
        "expanded_source_matrix_complete",
        "expanded_source_matrix_release_gate_ready",
        "expanded_source_matrix_c10_ready",
    ] {
        report.insert(key.to_owned(), json!(false));
    }
    report.insert(
        "outbound_production_matrix_report_schema".to_owned(),
        json!("outbound-production-matrix"),
    );
    report.insert(
        "outbound_production_matrix_entries".to_owned(),
        json!([
            {
                "handler": "vless",
                "parser_export_metadata": true,
                "tcp_dataplane": true,
                "udp_dataplane": true,
                "transport_underlay": true,
                "route_group_connectivity": true,
                "reload_behavior": true,
                "live_smoke": true,
                "go_fallback_retired": true,
            }
        ]),
    );
    report.insert(
        "outbound_production_matrix_typed_report".to_owned(),
        json!({
            "schema": "outbound-production-matrix-typed-report",
            "status": "pass",
            "stage_report_schema": false,
        }),
    );
    report.insert(
        "source_shape_registry_report_schema".to_owned(),
        json!("outbound-source-shape-registry"),
    );
    report.insert("source_shape_registry_schema_version".to_owned(), json!(1));
    report.insert("source_shape_registry_row_count".to_owned(), json!(3));
    report.insert(
        "source_shape_registry_rows".to_owned(),
        json!([
            {"shapeId": "baseline-tls-vision-endpoint", "residentStatus": "admitted-baseline"},
            {"shapeId": "stream-wrapper-websocket", "residentStatus": "admitted-baseline", "blockerId": null},
            {"shapeId": "foreign-abi-outbound-shape", "residentStatus": "not-source-supported", "blockerId": "unsupported-source-policy"}
        ]),
    );
    report.insert(
        "expanded_source_matrix_status_counts".to_owned(),
        json!({
            "admitted": 2,
            "blocked": 1,
            "not-source-supported": 1,
        }),
    );
    report.insert(
        "expanded_source_matrix_completion_blocker".to_owned(),
        json!(
            "expanded source matrix has fail-closed rows and requires live host, benchmark, and rollback evidence"
        ),
    );
    report.insert(
        "expanded_source_matrix_typed_report".to_owned(),
        json!({
            "schema": "expanded-source-matrix-typed-report",
            "status": "blocked",
            "expanded_source_matrix_complete": false,
            "release_gate_ready": false,
            "c10_ready": false,
            "scoped_release_gate_ready": true,
            "excluded_stream_wrapper_source_matrix_release_gate_ready": true,
            "stage_report_schema": false,
        }),
    );
    report.insert(
        "excluded_stream_wrapper_source_matrix_report_schema".to_owned(),
        json!("excluded-stream-wrapper-source-report"),
    );
    report.insert(
        "excluded_stream_wrapper_source_matrix_typed_report".to_owned(),
        json!({
            "schema": "excluded-stream-wrapper-source-report",
            "status": "pass",
            "open": true,
            "complete": true,
            "release_gate_ready": true,
            "c10_ready": true,
            "source_scope": "source-supported-rows-excluding-stream-wrapper",
            "excluded_stream_wrappers": ["xhttp"],
            "excluded_shape_ids": ["stream-wrapper-xhttp"],
            "source_supported_row_count": 24,
            "admitted_row_count": 24,
            "explicit_fail_closed_row_count": 0,
            "all_source_supported_rows_admitted": true,
            "all_protocol_rows_open": true,
            "official_common_source_shape_total": 21,
            "admitted_official_common_source_shape_count": 19,
            "explicit_fail_closed_official_common_source_shape_count": 2,
            "absent_official_common_source_shape_count": 0,
            "absent_official_common_source_shape_ids": [],
            "official_common_source_shapes_fully_represented": true,
            "official_common_source_shapes_all_resolved": false,
            "protocol_variant_row_count": 24,
            "required_protocol_variant_shape_ids": [
                "baseline-aead-cipher-endpoint",
                "baseline-aead-2022-cipher-endpoint",
                "plugin-wrapper-layer",
                "reality-security-underlay"
            ],
            "all_required_protocol_variants_present": true,
            "missing_required_protocol_variant_shape_ids": [],
            "blocked_protocol_variant_count": 0,
            "blocked_protocol_variant_ids": [],
            "explicit_fail_closed_shape_ids": [],
            "policy_rejected_row_count": 3,
            "policy_rejected_shape_ids": [
                "foreign-abi-outbound-shape",
                "external-oracle-dependent-shape",
                "internal-fallback-dependent-shape"
            ],
            "policy_rejected_rows_fail_closed": true,
            "scoped_closure_evidence_ready": true,
            "full_expanded_source_matrix_complete": false,
            "stage_report_schema": false,
        }),
    );
    report.insert(
        "scoped_expanded_source_matrix_evidence_report_schema".to_owned(),
        json!("scoped-expanded-source-evidence"),
    );
    report.insert(
        "scoped_expanded_source_matrix_evidence".to_owned(),
        json!({
            "schema": "scoped-expanded-source-evidence",
            "schemaVersion": 1,
            "scopeId": "excluded-stream-wrapper-scope",
            "sourceScope": "remaining-expanded-source-closure-rows",
            "excludedStreamWrappers": ["xhttp"],
            "rowCount": 24,
            "passCount": 24,
            "allPass": true,
            "largePageAllPass": true,
            "proxyEvidenceAllPass": true,
            "benchmarkEvidenceReady": true,
            "rollbackArtifactReady": true,
            "rollbackArtifactExecuted": true,
            "cleanupEvidenceReady": true,
            "rawLinksRetained": false,
            "rawBodiesRetained": false,
            "rawStateRetained": false,
            "releaseGateReady": true,
        }),
    );
    report.insert(
        "scoped_expanded_source_matrix_typed_report".to_owned(),
        json!({
            "schema": "scoped-expanded-source-typed-report",
            "status": "pass",
            "scope_id": "excluded-stream-wrapper-scope",
            "source_scope": "remaining-expanded-source-closure-rows",
            "row_count": 24,
            "pass_count": 24,
            "all_pass": true,
            "large_page_all_pass": true,
            "proxy_evidence_all_pass": true,
            "benchmark_evidence_ready": true,
            "rollback_artifact_ready": true,
            "rollback_artifact_executed": true,
            "cleanup_evidence_ready": true,
            "raw_links_retained": false,
            "raw_bodies_retained": false,
            "raw_state_retained": false,
            "release_gate_ready": true,
            "c10_ready": true,
            "stage_report_schema": false,
        }),
    );
    report.insert(
        "stream_wrapper_capability_report_schema".to_owned(),
        json!("stream-wrapper-capability"),
    );
    report.insert("stream_wrapper_capability_row_count".to_owned(), json!(1));
    report.insert(
        "stream_wrapper_capability_rows".to_owned(),
        json!([
            {
                "wrapperId": "websocket-wss-first-row",
                "status": "resident-live-final",
                "sourceAdmission": "admitted",
                "blockerId": null
            }
        ]),
    );
    report.insert(
        "stream_wrapper_capability_typed_report".to_owned(),
        json!({
            "schema": "stream-wrapper-capability-typed-report",
            "status": "pass",
            "websocket_wss_loopback_ready": true,
            "resident_source_admission_ready": true,
            "expanded_stream_wrapper_complete": true,
            "stage_report_schema": false,
        }),
    );
}
