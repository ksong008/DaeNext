use super::*;
pub(super) fn insert_resident_live_adapter_matrix_service_contract_capabilities(
    report: &mut Value,
) {
    let matrix = crate::production_runtime_owner::resident_live_adapter_matrix_contract();
    let live_evidence = crate::production_runtime_owner::resident_live_matrix_evidence_from_env();
    let entries = matrix
        .entries
        .iter()
        .map(|entry| {
            let remote_live_matrix =
                crate::production_runtime_owner::resident_live_adapter_entry_remote_live_matrix_ready(
                    entry,
                    &live_evidence,
                );
            let missing =
                crate::production_runtime_owner::resident_live_adapter_entry_missing(
                    entry,
                    &live_evidence,
                );
            json!({
                "handler": entry.handler,
                "formal_matrix_handler": entry.formal_matrix_handler,
                "planner_admitted": entry.planner_admitted,
                "tcp_live_adapter": entry.tcp_live_adapter,
                "tcp_semantics": entry.tcp_semantics,
                "tcp_path_ready": entry.tcp_path_ready(),
                "udp_live_adapter": entry.udp_live_adapter,
                "udp_semantics": entry.udp_semantics,
                "udp_path_ready": entry.udp_path_ready(),
                "transport_underlay": entry.transport_underlay,
                "route_group_connectivity": entry.route_group_connectivity,
                "selected_node_fail_closed": entry.selected_node_fail_closed,
                "fingerprint_underlay": entry.fingerprint_underlay,
                "remote_live_matrix": remote_live_matrix,
                "native_executor_ready": entry.native_executor_ready,
                "wired_ready": entry.wired_ready(),
                "live_ready": entry.wired_ready() && remote_live_matrix && missing.is_empty(),
                "fingerprint_behavior": entry.fingerprint_behavior,
                "evidence": entry.evidence,
                "missing": missing,
            })
        })
        .collect::<Vec<_>>();
    let wired_handler_count = matrix
        .entries
        .iter()
        .filter(|entry| entry.wired_ready())
        .count();
    let live_ready_handler_count = matrix
        .entries
        .iter()
        .filter(|entry| {
            let remote_live_matrix =
                crate::production_runtime_owner::resident_live_adapter_entry_remote_live_matrix_ready(
                    entry,
                    &live_evidence,
                );
            let missing =
                crate::production_runtime_owner::resident_live_adapter_entry_missing(
                    entry,
                    &live_evidence,
                );
            entry.wired_ready() && remote_live_matrix && missing.is_empty()
        })
        .count();

    if let Value::Object(report) = report {
        report.insert(
            "resident_live_adapter_matrix_contract_ready".to_owned(),
            json!(true),
        );
        report.insert(
            "resident_live_adapter_matrix_ready".to_owned(),
            json!(matrix.matrix_ready),
        );
        report.insert(
            "resident_live_adapter_matrix_runtime_state_ready".to_owned(),
            json!(matrix.matrix_ready),
        );
        report.insert(
            "resident_live_adapter_entries_ready".to_owned(),
            json!(!entries.is_empty()),
        );
        report.insert(
            "resident_live_adapter_planner_admission_ready".to_owned(),
            json!(matrix.planner_admission_ready),
        );
        report.insert(
            "resident_live_adapter_tcp_ready".to_owned(),
            json!(matrix.tcp_live_adapter_ready),
        );
        report.insert(
            "resident_live_adapter_udp_ready".to_owned(),
            json!(matrix.udp_live_adapter_ready),
        );
        report.insert(
            "resident_live_adapter_transport_underlay_ready".to_owned(),
            json!(matrix.transport_underlay_ready),
        );
        report.insert(
            "resident_live_adapter_route_group_connectivity_ready".to_owned(),
            json!(matrix.route_group_connectivity_ready),
        );
        report.insert(
            "resident_live_adapter_selected_node_fail_closed_ready".to_owned(),
            json!(matrix.selected_node_fail_closed_ready),
        );
        report.insert(
            "resident_live_adapter_fingerprint_underlay_ready".to_owned(),
            json!(matrix.fingerprint_underlay_ready),
        );
        report.insert(
            "resident_live_adapter_native_executor_matrix_ready".to_owned(),
            json!(matrix.native_executor_matrix_ready),
        );
        report.insert(
            "resident_live_adapter_wired_matrix_ready".to_owned(),
            json!(matrix.wired_matrix_ready),
        );
        report.insert(
            "resident_live_adapter_remote_live_matrix_ready".to_owned(),
            json!(matrix.remote_live_matrix_ready),
        );
        report.insert(
            "resident_live_adapter_remote_live_matrix_evidence".to_owned(),
            live_evidence.redacted_report(),
        );
        report.insert(
            "resident_live_adapter_wired_handler_count".to_owned(),
            json!(wired_handler_count),
        );
        report.insert(
            "resident_live_adapter_live_ready_handler_count".to_owned(),
            json!(live_ready_handler_count),
        );
        report.insert(
            "resident_live_adapter_matrix_report_schema".to_owned(),
            json!(matrix.schema),
        );
        report.insert(
            "resident_live_adapter_matrix_entries".to_owned(),
            json!(entries),
        );
        report.insert(
            "resident_live_adapter_matrix_typed_report_ready".to_owned(),
            json!(true),
        );
        report.insert(
            "resident_live_adapter_matrix_typed_report".to_owned(),
            json!({
                "schema": "resident-live-adapter-matrix-typed-report",
                "status": if matrix.matrix_ready { "pass" } else { "blocked" },
                "entry_count": entries.len(),
                "wired_handler_count": wired_handler_count,
                "live_ready_handler_count": live_ready_handler_count,
                "planner_admission_ready": matrix.planner_admission_ready,
                "tcp_live_adapter_ready": matrix.tcp_live_adapter_ready,
                "udp_live_adapter_ready": matrix.udp_live_adapter_ready,
                "transport_underlay_ready": matrix.transport_underlay_ready,
                "route_group_connectivity_ready": matrix.route_group_connectivity_ready,
                "selected_node_fail_closed_ready": matrix.selected_node_fail_closed_ready,
                "fingerprint_underlay_ready": matrix.fingerprint_underlay_ready,
                "native_executor_matrix_ready": matrix.native_executor_matrix_ready,
                "wired_matrix_ready": matrix.wired_matrix_ready,
                "remote_live_matrix_ready": matrix.remote_live_matrix_ready,
                "matrix_ready": matrix.matrix_ready,
                "current_report_schema": true,
            }),
        );
        report.insert(
            "resident_live_adapter_matrix_surface".to_owned(),
            json!({
                "scope": "live resident default adapter from selected node link into TCP/UDP tproxy workers",
                "formal_matrix_dependency": "dae-outbound production matrix remains parser/dataplane/underlay evidence; this resident matrix records which handlers are actually wired into the live default adapter",
                "production_admission_policy": "production admission cannot treat the formal outbound matrix as sufficient while this matrix is not pass",
                "validation_boundary": "external-client-through-resident-proxy",
            }),
        );
    }
}
