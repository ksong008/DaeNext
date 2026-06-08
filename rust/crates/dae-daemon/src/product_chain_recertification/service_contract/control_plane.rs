fn insert_control_plane_contract_defaults(report: &mut Value) {
    insert_control_plane_contract_success(
        report,
        false, // command_passed
        false, // control_plane_owner_contract_ready
        false, // control_plane_runtime_state_ready
        false, // routing_map_owner_ready
        false, // domain_routing_owner_ready
        false, // outbound_connectivity_owner_ready
        false, // runtime_overview_cache_stats_ready
        false, // control_plane_reload_parity_contract_ready
        false, // control_plane_cleanup_leftovers_gate_ready
        false, // matched_go_rust_default_daemon_benchmark_gate_ready
        false, // control_plane_typed_report_ready
        false, // control_plane_c_tproxy_oracle_retained_until_datapath_core
        false, // go_control_plane_fallback_retirement_contract_ready
        false, // go_control_plane_fallback_retired_candidate
        &Value::Null,
    );
}

#[allow(clippy::too_many_arguments)]
fn insert_control_plane_contract_success(
    report: &mut Value,
    command_passed: bool,
    control_plane_owner_contract_ready: bool,
    control_plane_runtime_state_ready: bool,
    routing_map_owner_ready: bool,
    domain_routing_owner_ready: bool,
    outbound_connectivity_owner_ready: bool,
    runtime_overview_cache_stats_ready: bool,
    control_plane_reload_parity_contract_ready: bool,
    control_plane_cleanup_leftovers_gate_ready: bool,
    matched_go_rust_default_daemon_benchmark_gate_ready: bool,
    control_plane_typed_report_ready: bool,
    control_plane_c_tproxy_oracle_retained_until_datapath_core: bool,
    go_control_plane_fallback_retirement_contract_ready: bool,
    go_control_plane_fallback_retired_candidate: bool,
    capability: &Value,
) {
    if let Value::Object(report) = report {
        report.insert(
            "control_plane_owner_contract_ready".to_owned(),
            json!(command_passed && control_plane_owner_contract_ready),
        );
        report.insert(
            "control_plane_runtime_state_ready".to_owned(),
            json!(command_passed && control_plane_runtime_state_ready),
        );
        report.insert(
            "control_plane_runtime_state_report".to_owned(),
            capability["control_plane_runtime_state_report"].clone(),
        );
        report.insert(
            "routing_map_owner_ready".to_owned(),
            json!(command_passed && routing_map_owner_ready),
        );
        report.insert(
            "domain_routing_owner_ready".to_owned(),
            json!(command_passed && domain_routing_owner_ready),
        );
        report.insert(
            "outbound_connectivity_owner_ready".to_owned(),
            json!(command_passed && outbound_connectivity_owner_ready),
        );
        report.insert(
            "runtime_overview_cache_stats_ready".to_owned(),
            json!(command_passed && runtime_overview_cache_stats_ready),
        );
        report.insert(
            "control_plane_reload_parity_contract_ready".to_owned(),
            json!(command_passed && control_plane_reload_parity_contract_ready),
        );
        report.insert(
            "control_plane_cleanup_leftovers_gate_ready".to_owned(),
            json!(command_passed && control_plane_cleanup_leftovers_gate_ready),
        );
        report.insert(
            "matched_go_rust_default_daemon_benchmark_gate_ready".to_owned(),
            json!(command_passed && matched_go_rust_default_daemon_benchmark_gate_ready),
        );
        report.insert(
            "control_plane_typed_report_ready".to_owned(),
            json!(command_passed && control_plane_typed_report_ready),
        );
        report.insert(
            "control_plane_typed_report".to_owned(),
            capability["control_plane_typed_report"].clone(),
        );
        report.insert(
            "control_plane_owner_surface".to_owned(),
            capability["control_plane_owner_surface"].clone(),
        );
        report.insert(
            "control_plane_report_schema".to_owned(),
            capability["control_plane_report_schema"].clone(),
        );
        report.insert(
            "control_plane_c_tproxy_oracle_retained_until_datapath_core".to_owned(),
            json!(command_passed && control_plane_c_tproxy_oracle_retained_until_datapath_core),
        );
        report.insert(
            "go_control_plane_fallback_retirement_contract_ready".to_owned(),
            json!(command_passed && go_control_plane_fallback_retirement_contract_ready),
        );
        report.insert(
            "go_control_plane_fallback_retired_candidate".to_owned(),
            json!(command_passed && go_control_plane_fallback_retired_candidate),
        );
    }
}
