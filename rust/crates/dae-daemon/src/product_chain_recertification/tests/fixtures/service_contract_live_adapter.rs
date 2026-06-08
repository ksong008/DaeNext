use super::*;
pub(crate) fn insert_resident_live_adapter_contract(report: &mut serde_json::Map<String, Value>) {
    for key in [
        "resident_live_adapter_matrix_contract_ready",
        "resident_live_adapter_matrix_ready",
        "resident_live_adapter_matrix_runtime_state_ready",
        "resident_live_adapter_entries_ready",
        "resident_live_adapter_planner_admission_ready",
        "resident_live_adapter_tcp_ready",
        "resident_live_adapter_udp_ready",
        "resident_live_adapter_transport_underlay_ready",
        "resident_live_adapter_route_group_connectivity_ready",
        "resident_live_adapter_selected_node_fail_closed_ready",
        "resident_live_adapter_fingerprint_underlay_ready",
        "resident_live_adapter_go_outbound_fallback_retirement_ready",
        "resident_live_adapter_wired_matrix_ready",
        "resident_live_adapter_remote_live_matrix_ready",
        "resident_live_adapter_matrix_typed_report_ready",
    ] {
        report.insert(key.to_owned(), json!(true));
    }
    report.insert(
        "resident_live_adapter_wired_handler_count".to_owned(),
        json!(10),
    );
    report.insert(
        "resident_live_adapter_live_ready_handler_count".to_owned(),
        json!(10),
    );
    report.insert(
        "resident_live_adapter_matrix_report_schema".to_owned(),
        json!("resident-live-adapter-matrix"),
    );
    report.insert(
        "resident_live_adapter_matrix_entries".to_owned(),
        json!([
            {
                "handler": "fixture-handler",
                "formal_matrix_handler": "fixture-handler",
                "planner_admitted": true,
                "tcp_live_adapter": true,
                "udp_live_adapter": true,
                "transport_underlay": true,
                "route_group_connectivity": true,
                "selected_node_fail_closed": true,
                "fingerprint_underlay": true,
                "remote_live_matrix": true,
                "go_outbound_fallback_retired": true,
                "wired_ready": true,
                "live_ready": true,
                "missing": [],
            }
        ]),
    );
    report.insert(
        "resident_live_adapter_matrix_typed_report".to_owned(),
        json!({
            "schema": "resident-live-adapter-matrix-typed-report",
            "status": "pass",
            "entry_count": 10,
            "wired_handler_count": 10,
            "live_ready_handler_count": 10,
            "wired_matrix_ready": true,
            "remote_live_matrix_ready": true,
            "matrix_ready": true,
            "stage_report_schema": false,
        }),
    );
    report.insert(
        "resident_live_adapter_matrix_surface".to_owned(),
        json!({
            "scope": "fixture complete live adapter matrix",
            "live_matrix_host": "38.65.91.47",
        }),
    );
}
