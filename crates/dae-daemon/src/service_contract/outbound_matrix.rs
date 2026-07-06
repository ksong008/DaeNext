use super::*;
pub(super) fn insert_outbound_production_matrix_service_contract_capabilities(report: &mut Value) {
    let matrix = dae_outbound::outbound_production_matrix_contract();
    let source_registry = dae_outbound::source_shape_registry_contract();
    let stream_wrapper = dae_outbound::stream_wrapper_capability_contract();
    let packet_semantics = dae_outbound::packet_semantics_capability_contract();
    let extension_layer = dae_outbound::extension_layer_capability_contract();
    let transport_option = dae_outbound::transport_option_capability_contract();
    let live_boundary = dae_outbound::expanded_live_matrix_validation_boundary_contract();
    let entries = matrix
        .entries
        .iter()
        .map(|entry| {
            json!({
                "handler": entry.handler,
                "source_shape_ids": entry.source_shape_ids,
                "parser_export_metadata": entry.parser_export_metadata,
                "tcp_dataplane": entry.tcp_dataplane,
                "udp_dataplane": entry.udp_dataplane,
                "transport_underlay": entry.transport_underlay,
                "route_group_connectivity": entry.route_group_connectivity,
                "reload_behavior": entry.reload_behavior,
                "live_smoke": entry.live_smoke,
                "native_executor_ready": entry.native_executor_ready,
                "evidence": entry.evidence,
            })
        })
        .collect::<Vec<_>>();
    let source_registry_rows = source_registry
        .rows
        .iter()
        .map(|row| (*row).to_value())
        .collect::<Vec<_>>();
    let source_registry_status_counts = source_shape_registry_status_counts(source_registry.rows);
    let runtime_blocked_source_shape_row_count =
        source_shape_registry_runtime_blocked_row_count(source_registry.rows);
    let policy_rejected_source_shape_row_count =
        source_shape_registry_policy_rejected_row_count(source_registry.rows);
    let expanded_source_matrix_release_evidence_incomplete =
        !source_registry.expanded_source_matrix_complete;
    let stream_wrapper_rows = stream_wrapper
        .rows
        .iter()
        .map(|row| (*row).to_value())
        .collect::<Vec<_>>();
    let packet_semantics_rows = packet_semantics
        .rows
        .iter()
        .map(|row| (*row).to_value())
        .collect::<Vec<_>>();
    let extension_layer_rows = extension_layer
        .rows
        .iter()
        .map(|row| (*row).to_value())
        .collect::<Vec<_>>();
    let transport_option_rows = transport_option
        .rows
        .iter()
        .map(|row| (*row).to_value())
        .collect::<Vec<_>>();
    let contract_ready = matrix.matrix_ready;
    let expanded_source_matrix_complete = source_registry.expanded_source_matrix_complete;
    let expanded_source_matrix_production_ready = expanded_source_matrix_complete;
    let expanded_source_matrix_final_state_ready = expanded_source_matrix_complete;
    let scoped_source_evidence = source_registry.scoped_expanded_source_matrix_evidence;
    let scoped_expanded_source_matrix_complete = scoped_source_evidence.production_ready
        && scoped_source_evidence.all_pass
        && scoped_source_evidence.large_page_all_pass
        && scoped_source_evidence.proxy_evidence_all_pass
        && scoped_source_evidence.benchmark_evidence_ready
        && scoped_source_evidence.cleanup_evidence_ready
        && !scoped_source_evidence.raw_links_retained
        && !scoped_source_evidence.raw_bodies_retained
        && !scoped_source_evidence.raw_state_retained;
    let scoped_expanded_source_matrix_production_ready = scoped_expanded_source_matrix_complete;
    let scoped_expanded_source_matrix_final_state_ready = scoped_expanded_source_matrix_complete;
    let excluded_stream_wrapper_source_matrix_typed_report =
        excluded_stream_wrapper_source_matrix_typed_report(
            source_registry.rows,
            scoped_source_evidence.excluded_stream_wrappers,
            scoped_expanded_source_matrix_production_ready,
        );
    let excluded_stream_wrapper_source_matrix_complete =
        excluded_stream_wrapper_source_matrix_typed_report["complete"]
            .as_bool()
            .unwrap_or(false);
    let excluded_stream_wrapper_source_matrix_production_ready =
        excluded_stream_wrapper_source_matrix_typed_report["production_ready"]
            .as_bool()
            .unwrap_or(false);
    let excluded_stream_wrapper_source_matrix_final_state_ready =
        excluded_stream_wrapper_source_matrix_typed_report["final_state_ready"]
            .as_bool()
            .unwrap_or(false);

    if let Value::Object(report) = report {
        report.insert(
            "outbound_production_matrix_contract_ready".to_owned(),
            json!(contract_ready),
        );
        report.insert(
            "outbound_production_matrix_runtime_state_ready".to_owned(),
            json!(contract_ready),
        );
        report.insert(
            "outbound_matrix_entries_ready".to_owned(),
            json!(!entries.is_empty() && matrix.matrix_ready),
        );
        report.insert(
            "parser_export_metadata_matrix_ready".to_owned(),
            json!(matrix.parser_export_metadata_ready),
        );
        report.insert(
            "tcp_udp_dataplane_matrix_ready".to_owned(),
            json!(matrix.tcp_udp_dataplane_ready),
        );
        report.insert(
            "transport_underlay_matrix_ready".to_owned(),
            json!(matrix.transport_underlay_ready),
        );
        report.insert(
            "route_group_connectivity_matrix_ready".to_owned(),
            json!(matrix.route_group_connectivity_ready),
        );
        report.insert(
            "reload_behavior_matrix_ready".to_owned(),
            json!(matrix.reload_behavior_ready),
        );
        report.insert(
            "live_smoke_matrix_ready".to_owned(),
            json!(matrix.live_smoke_ready),
        );
        report.insert(
            "outbound_native_executor_matrix_ready".to_owned(),
            json!(matrix.native_executor_matrix_ready),
        );
        report.insert(
            "outbound_production_matrix_source_registry_backed_ready".to_owned(),
            json!(matrix.source_registry_backed_ready),
        );
        report.insert(
            "outbound_production_matrix_typed_report_ready".to_owned(),
            json!(contract_ready),
        );
        report.insert(
            "outbound_native_executor_production_ready".to_owned(),
            json!(contract_ready),
        );
        report.insert(
            "outbound_native_executor_candidate".to_owned(),
            json!(contract_ready),
        );
        report.insert(
            "outbound_production_matrix_report_schema".to_owned(),
            json!(matrix.schema),
        );
        report.insert(
            "outbound_production_matrix_entries".to_owned(),
            json!(entries),
        );
        report.insert(
            "outbound_production_matrix_typed_report".to_owned(),
            json!({
                "schema": "outbound-production-matrix-typed-report",
                "status": if contract_ready { "pass" } else { "fail" },
                "entry_count": entries.len(),
                "parser_export_metadata_matrix_ready": matrix.parser_export_metadata_ready,
                "tcp_udp_dataplane_matrix_ready": matrix.tcp_udp_dataplane_ready,
                "transport_underlay_matrix_ready": matrix.transport_underlay_ready,
                "route_group_connectivity_matrix_ready": matrix.route_group_connectivity_ready,
                "reload_behavior_matrix_ready": matrix.reload_behavior_ready,
                "live_smoke_matrix_ready": matrix.live_smoke_ready,
                "outbound_native_executor_matrix_ready": matrix.native_executor_matrix_ready,
                "source_registry_backed_ready": matrix.source_registry_backed_ready,
                "current_report_schema": true,
            }),
        );
        report.insert(
            "source_shape_registry_contract_ready".to_owned(),
            json!(source_registry.source_shape_registry_open),
        );
        report.insert(
            "source_shape_registry_open".to_owned(),
            json!(source_registry.source_shape_registry_open),
        );
        report.insert(
            "source_shape_registry_report_schema".to_owned(),
            json!(source_registry.schema),
        );
        report.insert(
            "source_shape_registry_schema_version".to_owned(),
            json!(source_registry.schema_version),
        );
        report.insert(
            "source_shape_registry_row_count".to_owned(),
            json!(source_registry.rows.len()),
        );
        report.insert(
            "source_shape_registry_rows".to_owned(),
            json!(source_registry_rows),
        );
        report.insert(
            "expanded_source_matrix_open".to_owned(),
            json!(source_registry.expanded_source_matrix_open),
        );
        report.insert(
            "expanded_source_matrix_complete".to_owned(),
            json!(expanded_source_matrix_complete),
        );
        report.insert(
            "expanded_source_matrix_blocked_rows_visible".to_owned(),
            json!(runtime_blocked_source_shape_row_count > 0),
        );
        report.insert(
            "expanded_source_matrix_production_ready".to_owned(),
            json!(expanded_source_matrix_production_ready),
        );
        report.insert(
            "expanded_source_matrix_production_ready".to_owned(),
            json!(expanded_source_matrix_production_ready),
        );
        report.insert(
            "expanded_source_matrix_final_state_ready".to_owned(),
            json!(expanded_source_matrix_final_state_ready),
        );
        report.insert(
            "expanded_source_matrix_status_counts".to_owned(),
            source_registry_status_counts,
        );
        report.insert(
            "expanded_source_matrix_runtime_blocked_row_count".to_owned(),
            json!(runtime_blocked_source_shape_row_count),
        );
        report.insert(
            "expanded_source_matrix_policy_rejected_row_count".to_owned(),
            json!(policy_rejected_source_shape_row_count),
        );
        report.insert(
            "expanded_source_matrix_release_evidence_incomplete".to_owned(),
            json!(expanded_source_matrix_release_evidence_incomplete),
        );
        report.insert(
            "expanded_source_matrix_status_reason".to_owned(),
            json!(if expanded_source_matrix_release_evidence_incomplete {
                "release-evidence-incomplete"
            } else if runtime_blocked_source_shape_row_count > 0 {
                "runtime-fail-closed-rows"
            } else {
                "pass"
            }),
        );
        report.insert(
            "excluded_stream_wrapper_source_matrix_open".to_owned(),
            json!(source_registry.expanded_source_matrix_open),
        );
        report.insert(
            "excluded_stream_wrapper_source_matrix_complete".to_owned(),
            json!(excluded_stream_wrapper_source_matrix_complete),
        );
        report.insert(
            "excluded_stream_wrapper_source_matrix_production_ready".to_owned(),
            json!(excluded_stream_wrapper_source_matrix_production_ready),
        );
        report.insert(
            "excluded_stream_wrapper_source_matrix_production_ready".to_owned(),
            json!(excluded_stream_wrapper_source_matrix_production_ready),
        );
        report.insert(
            "excluded_stream_wrapper_source_matrix_final_state_ready".to_owned(),
            json!(excluded_stream_wrapper_source_matrix_final_state_ready),
        );
        report.insert(
            "excluded_stream_wrapper_source_matrix_report_schema".to_owned(),
            json!("excluded-stream-wrapper-source-report"),
        );
        report.insert(
            "excluded_stream_wrapper_source_matrix_typed_report".to_owned(),
            excluded_stream_wrapper_source_matrix_typed_report,
        );
        report.insert(
            "expanded_source_matrix_completion_blocker".to_owned(),
            json!(
                "full expanded source matrix is not complete until unscoped live evidence is aggregated and final policy boundaries remain fail-closed"
            ),
        );
        report.insert(
            "scoped_expanded_source_matrix_complete".to_owned(),
            json!(scoped_expanded_source_matrix_complete),
        );
        report.insert(
            "scoped_expanded_source_matrix_production_ready".to_owned(),
            json!(scoped_expanded_source_matrix_production_ready),
        );
        report.insert(
            "scoped_expanded_source_matrix_production_ready".to_owned(),
            json!(scoped_expanded_source_matrix_production_ready),
        );
        report.insert(
            "scoped_expanded_source_matrix_final_state_ready".to_owned(),
            json!(scoped_expanded_source_matrix_final_state_ready),
        );
        report.insert(
            "scoped_expanded_source_matrix_evidence_report_schema".to_owned(),
            json!(scoped_source_evidence.schema),
        );
        report.insert(
            "scoped_expanded_source_matrix_evidence".to_owned(),
            scoped_source_evidence.to_value(),
        );
        report.insert(
            "scoped_expanded_source_matrix_typed_report".to_owned(),
            json!({
                "schema": "scoped-expanded-source-typed-report",
                "status": if scoped_expanded_source_matrix_complete { "pass" } else { "blocked" },
                "scope_id": scoped_source_evidence.scope_id,
                "source_scope": scoped_source_evidence.source_scope,
                "excluded_stream_wrappers": scoped_source_evidence.excluded_stream_wrappers,
                "opened_rows": scoped_source_evidence.opened_rows,
                "source_formats": scoped_source_evidence.source_formats,
                "candidate_sha256": scoped_source_evidence.candidate_sha256,
                "validation_boundary": scoped_source_evidence.validation_boundary,
                "upstream_boundary": scoped_source_evidence.upstream_boundary,
                "row_count": scoped_source_evidence.row_count,
                "pass_count": scoped_source_evidence.pass_count,
                "all_pass": scoped_source_evidence.all_pass,
                "large_page_all_pass": scoped_source_evidence.large_page_all_pass,
                "proxy_evidence_all_pass": scoped_source_evidence.proxy_evidence_all_pass,
                "benchmark_evidence_ready": scoped_source_evidence.benchmark_evidence_ready,
                "benchmark_evidence_kind": scoped_source_evidence.benchmark_evidence_kind,
                "cleanup_evidence_ready": scoped_source_evidence.cleanup_evidence_ready,
                "raw_links_retained": scoped_source_evidence.raw_links_retained,
                "raw_bodies_retained": scoped_source_evidence.raw_bodies_retained,
                "raw_state_retained": scoped_source_evidence.raw_state_retained,
                "production_ready": scoped_expanded_source_matrix_production_ready,
                "production_ready": scoped_expanded_source_matrix_production_ready,
                "final_state_ready": scoped_expanded_source_matrix_final_state_ready,
                "current_report_schema": true,
            }),
        );
        report.insert(
            "expanded_source_matrix_typed_report".to_owned(),
            json!({
                "schema": "expanded-source-matrix-typed-report",
                "status": if expanded_source_matrix_complete { "pass" } else { "blocked" },
                "source_shape_registry_open": source_registry.source_shape_registry_open,
                "expanded_source_matrix_open": source_registry.expanded_source_matrix_open,
                "expanded_source_matrix_complete": expanded_source_matrix_complete,
                "production_ready": expanded_source_matrix_production_ready,
                "production_ready": expanded_source_matrix_production_ready,
                "final_state_ready": expanded_source_matrix_final_state_ready,
                "scoped_production_ready": scoped_expanded_source_matrix_production_ready,
                "scoped_production_ready": scoped_expanded_source_matrix_production_ready,
                "excluded_stream_wrapper_source_matrix_production_ready": excluded_stream_wrapper_source_matrix_production_ready,
                "excluded_stream_wrapper_source_matrix_production_ready": excluded_stream_wrapper_source_matrix_production_ready,
                "blocked_rows_visible": runtime_blocked_source_shape_row_count > 0,
                "runtime_blocked_row_count": runtime_blocked_source_shape_row_count,
                "policy_rejected_row_count": policy_rejected_source_shape_row_count,
                "release_evidence_incomplete": expanded_source_matrix_release_evidence_incomplete,
                "status_reason": if expanded_source_matrix_release_evidence_incomplete {
                    "release-evidence-incomplete"
                } else if runtime_blocked_source_shape_row_count > 0 {
                    "runtime-fail-closed-rows"
                } else {
                    "pass"
                },
                "status_counts": source_shape_registry_status_counts(source_registry.rows),
                "current_report_schema": true,
            }),
        );
        report.insert(
            "stream_wrapper_capability_contract_ready".to_owned(),
            json!(stream_wrapper.websocket_wss_loopback_ready),
        );
        report.insert(
            "websocket_wss_loopback_ready".to_owned(),
            json!(stream_wrapper.websocket_wss_loopback_ready),
        );
        report.insert(
            "stream_wrapper_resident_source_admission_ready".to_owned(),
            json!(stream_wrapper.resident_source_admission_ready),
        );
        report.insert(
            "expanded_stream_wrapper_complete".to_owned(),
            json!(stream_wrapper.expanded_stream_wrapper_complete),
        );
        report.insert(
            "stream_wrapper_capability_report_schema".to_owned(),
            json!(stream_wrapper.schema),
        );
        report.insert(
            "stream_wrapper_capability_row_count".to_owned(),
            json!(stream_wrapper.rows.len()),
        );
        report.insert(
            "stream_wrapper_capability_rows".to_owned(),
            json!(stream_wrapper_rows),
        );
        report.insert(
            "stream_wrapper_capability_typed_report".to_owned(),
            json!({
                "schema": "stream-wrapper-capability-typed-report",
                "status": if stream_wrapper.expanded_stream_wrapper_complete { "pass" } else { "blocked" },
                "websocket_wss_loopback_ready": stream_wrapper.websocket_wss_loopback_ready,
                "resident_source_admission_ready": stream_wrapper.resident_source_admission_ready,
                "expanded_stream_wrapper_complete": stream_wrapper.expanded_stream_wrapper_complete,
                "blocked_rows_visible": false,
                "current_report_schema": true,
            }),
        );
        report.insert(
            "packet_semantics_capability_contract_ready".to_owned(),
            json!(packet_semantics.common_packet_semantics_ready),
        );
        report.insert(
            "common_packet_semantics_ready".to_owned(),
            json!(packet_semantics.common_packet_semantics_ready),
        );
        report.insert(
            "packet_semantics_resident_source_admission_ready".to_owned(),
            json!(packet_semantics.resident_source_admission_ready),
        );
        report.insert(
            "expanded_packet_semantics_complete".to_owned(),
            json!(packet_semantics.expanded_packet_semantics_complete),
        );
        report.insert(
            "packet_semantics_capability_report_schema".to_owned(),
            json!(packet_semantics.schema),
        );
        report.insert(
            "packet_semantics_capability_row_count".to_owned(),
            json!(packet_semantics.rows.len()),
        );
        report.insert(
            "packet_semantics_capability_rows".to_owned(),
            json!(packet_semantics_rows),
        );
        report.insert(
            "packet_semantics_capability_typed_report".to_owned(),
            json!({
                "schema": "packet-semantics-capability-typed-report",
                "status": if packet_semantics.expanded_packet_semantics_complete { "pass" } else { "blocked" },
                "common_packet_semantics_ready": packet_semantics.common_packet_semantics_ready,
                "resident_source_admission_ready": packet_semantics.resident_source_admission_ready,
                "expanded_packet_semantics_complete": packet_semantics.expanded_packet_semantics_complete,
                "blocked_rows_visible": false,
                "current_report_schema": true,
            }),
        );
        report.insert(
            "extension_layer_capability_contract_ready".to_owned(),
            json!(extension_layer.no_plugin_baseline_ready),
        );
        report.insert(
            "no_plugin_baseline_ready".to_owned(),
            json!(extension_layer.no_plugin_baseline_ready),
        );
        report.insert(
            "plugin_wrapper_resident_source_admission_ready".to_owned(),
            json!(extension_layer.plugin_wrapper_resident_source_admission_ready),
        );
        report.insert(
            "legacy_layer_resident_source_admission_ready".to_owned(),
            json!(extension_layer.legacy_layer_resident_source_admission_ready),
        );
        report.insert(
            "expanded_extension_layer_complete".to_owned(),
            json!(extension_layer.expanded_extension_layer_complete),
        );
        report.insert(
            "extension_layer_capability_report_schema".to_owned(),
            json!(extension_layer.schema),
        );
        report.insert(
            "extension_layer_capability_row_count".to_owned(),
            json!(extension_layer.rows.len()),
        );
        report.insert(
            "extension_layer_capability_rows".to_owned(),
            json!(extension_layer_rows),
        );
        report.insert(
            "extension_layer_capability_typed_report".to_owned(),
            json!({
                "schema": "extension-layer-capability-typed-report",
                "status": if extension_layer.expanded_extension_layer_complete { "pass" } else { "blocked" },
                "no_plugin_baseline_ready": extension_layer.no_plugin_baseline_ready,
                "plugin_wrapper_resident_source_admission_ready": extension_layer.plugin_wrapper_resident_source_admission_ready,
                "legacy_layer_resident_source_admission_ready": extension_layer.legacy_layer_resident_source_admission_ready,
                "expanded_extension_layer_complete": extension_layer.expanded_extension_layer_complete,
                "blocked_rows_visible": false,
                "current_report_schema": true,
            }),
        );
        report.insert(
            "transport_option_capability_contract_ready".to_owned(),
            json!(transport_option.baseline_transport_options_ready),
        );
        report.insert(
            "baseline_transport_options_ready".to_owned(),
            json!(transport_option.baseline_transport_options_ready),
        );
        report.insert(
            "quic_option_resident_source_admission_ready".to_owned(),
            json!(transport_option.quic_option_resident_source_admission_ready),
        );
        report.insert(
            "secure_endpoint_resident_source_admission_ready".to_owned(),
            json!(transport_option.secure_endpoint_resident_source_admission_ready),
        );
        report.insert(
            "expanded_transport_option_complete".to_owned(),
            json!(transport_option.expanded_transport_option_complete),
        );
        report.insert(
            "transport_option_capability_report_schema".to_owned(),
            json!(transport_option.schema),
        );
        report.insert(
            "transport_option_capability_row_count".to_owned(),
            json!(transport_option.rows.len()),
        );
        report.insert(
            "transport_option_capability_rows".to_owned(),
            json!(transport_option_rows),
        );
        report.insert(
            "transport_option_capability_typed_report".to_owned(),
            json!({
                "schema": "transport-option-capability-typed-report",
                "status": if transport_option.expanded_transport_option_complete { "pass" } else { "blocked" },
                "baseline_transport_options_ready": transport_option.baseline_transport_options_ready,
                "quic_option_resident_source_admission_ready": transport_option.quic_option_resident_source_admission_ready,
                "secure_endpoint_resident_source_admission_ready": transport_option.secure_endpoint_resident_source_admission_ready,
                "expanded_transport_option_complete": transport_option.expanded_transport_option_complete,
                "blocked_rows_visible": false,
                "current_report_schema": true,
            }),
        );
        report.insert(
            "expanded_live_matrix_validation_boundary_ready".to_owned(),
            json!(true),
        );
        report.insert(
            "expanded_live_matrix_complete".to_owned(),
            json!(live_boundary.expanded_live_matrix_complete),
        );
        report.insert(
            "expanded_live_matrix_proxy_path_required".to_owned(),
            json!(live_boundary.proxy_path_required),
        );
        report.insert(
            "expanded_live_matrix_direct_control_excluded".to_owned(),
            json!(live_boundary.direct_control_excluded),
        );
        report.insert(
            "expanded_live_matrix_benchmark_required".to_owned(),
            json!(live_boundary.benchmark_required),
        );
        report.insert(
            "expanded_live_matrix_cleanup_artifact_required".to_owned(),
            json!(live_boundary.cleanup_artifact_required),
        );
        report.insert(
            "expanded_live_matrix_blocked_rows_reduce_pass_threshold".to_owned(),
            json!(live_boundary.blocked_rows_reduce_pass_threshold),
        );
        report.insert(
            "expanded_live_matrix_validation_boundary_report_schema".to_owned(),
            json!(live_boundary.schema),
        );
        report.insert(
            "expanded_live_matrix_validation_boundary_typed_report".to_owned(),
            json!({
                "schema": "expanded-live-matrix-validation-boundary-typed-report",
                "status": if live_boundary.expanded_live_matrix_complete { "pass" } else { "blocked" },
                "validation_boundary": live_boundary.validation_boundary,
                "upstream_boundary": live_boundary.upstream_boundary,
                "google_min_bytes": live_boundary.google_min_bytes,
                "youtube_min_bytes": live_boundary.youtube_min_bytes,
                "proxy_path_required": live_boundary.proxy_path_required,
                "direct_control_excluded": live_boundary.direct_control_excluded,
                "benchmark_required": live_boundary.benchmark_required,
                "cleanup_artifact_required": live_boundary.cleanup_artifact_required,
                "blocked_rows_reduce_pass_threshold": live_boundary.blocked_rows_reduce_pass_threshold,
                "expanded_live_matrix_complete": live_boundary.expanded_live_matrix_complete,
                "current_report_schema": true,
            }),
        );
    }
}
