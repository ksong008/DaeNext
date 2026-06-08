use super::*;
pub(crate) fn insert_control_plane_owner_contract(report: &mut serde_json::Map<String, Value>) {
    report.insert("control_plane_owner_contract_ready".to_owned(), json!(true));
    report.insert("control_plane_runtime_state_ready".to_owned(), json!(true));
    report.insert(
        "control_plane_runtime_state_report".to_owned(),
        json!({
            "schema_version": 1,
            "rust_owned_runtime": true,
            "reload_state_available": true,
            "backend_state_available": true,
            "routing_owner_available": true,
            "domain_owner_available": true,
            "connectivity_owner_available": true,
            "active_handoff_available": true,
            "api_compatible": true,
            "ready_for_default_control_plane": true,
        }),
    );
    report.insert("routing_map_owner_ready".to_owned(), json!(true));
    report.insert("domain_routing_owner_ready".to_owned(), json!(true));
    report.insert("outbound_connectivity_owner_ready".to_owned(), json!(true));
    report.insert("runtime_overview_cache_stats_ready".to_owned(), json!(true));
    report.insert(
        "control_plane_reload_parity_contract_ready".to_owned(),
        json!(true),
    );
    report.insert(
        "control_plane_cleanup_leftovers_gate_ready".to_owned(),
        json!(true),
    );
    report.insert(
        "matched_go_rust_default_daemon_benchmark_gate_ready".to_owned(),
        json!(true),
    );
    report.insert("control_plane_typed_report_ready".to_owned(), json!(true));
    report.insert(
        "control_plane_typed_report".to_owned(),
        json!({
            "schema": "control-api-typed-report",
            "status": "pass",
            "runtime_overview_available": true,
            "reload_core_state_available": true,
            "domain_routing_owner_available": true,
            "runtime_dependency_plan_available": true,
            "stage_report_schema": false,
        }),
    );
    report.insert(
        "control_plane_owner_surface".to_owned(),
        json!({
            "routing_map_owner": "dae-control::RoutingMapOwner",
            "domain_routing_owner": "dae-control::DomainRoutingOwner",
            "outbound_connectivity_owner": "dae-control::OutboundConnectivityOwner",
            "runtime_overview": "formal RuntimeOverview API surface",
            "runtime_cache_stats": "runtime overview/cache/stats typed surface",
            "reload_parity": "reload core state plus rollback contract",
            "cleanup_leftovers_gate": "production runtime cleanup leftovers gate",
            "matched_benchmark_gate": "matched Go/Rust default daemon benchmark gate",
        }),
    );
    report.insert(
        "control_plane_report_schema".to_owned(),
        json!("control-plane-owner"),
    );
    report.insert(
        "control_plane_c_tproxy_oracle_retained_until_datapath_core".to_owned(),
        json!(true),
    );
    report.insert(
        "go_control_plane_fallback_retirement_contract_ready".to_owned(),
        json!(true),
    );
    report.insert(
        "go_control_plane_fallback_retired_candidate".to_owned(),
        json!(true),
    );
}
