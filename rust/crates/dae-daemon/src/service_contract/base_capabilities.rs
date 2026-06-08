use super::*;
pub fn service_contract_capabilities(version: &str) -> Value {
    let control_plane_runtime_state = dae_control::RuntimeStateReport::rust_owned_control_plane();
    let control_plane_runtime_state_ready =
        control_plane_runtime_state.ready_for_default_control_plane();
    let control_api_typed_report = dae_control::ControlApiTypedReport::formal_runtime_control_api();
    let control_plane_typed_report_ready = matches!(
        control_api_typed_report.status,
        dae_control::ControlApiReportStatus::Pass
    ) && control_api_typed_report.runtime_overview_available
        && control_api_typed_report.reload_core_state_available
        && control_api_typed_report.domain_routing_owner_available
        && control_api_typed_report.runtime_dependency_plan_available
        && !control_api_typed_report.stage_report_schema;
    let resident_dataplane_default_switch_ready =
        resident_dataplane_default_switch_ready_from_env();
    let default_path_switch_blocker = if resident_dataplane_default_switch_ready {
        Value::Null
    } else {
        json!(format!(
            "{RESIDENT_DATAPLANE_ENV}=1 is required before the resident default daemon can own redirected TCP/UDP payloads"
        ))
    };
    let mut report = json!({
        "name": "dae-daemon-service-contract",
        "version": version,
        "resident_run_service_contract_ready": true,
        "reload_command_service_contract_ready": true,
        "systemd_notify_ready_supported": true,
        "reload_failure_rollback_supported": true,
        "invalid_runtime_config_rejected_before_current_swap": true,
        "reload_start_failure_attempts_previous_runtime_restore": true,
        "resident_runtime_platform_contract_ready": true,
        "resident_runtime_typed_report_ready": true,
        "resident_runtime_resource_gate_ready": true,
        "resident_runtime_report_schema": "resident-runtime-platform-report",
        "resident_runtime_lifecycle_contract": {
            "pid_file": PID_FILE_PATH,
            "progress_file": PROGRESS_FILE_PATH,
            "abort_file": ABORT_FILE_PATH,
            "ready_record_file_supported": true,
            "systemd_ready_notify_supported": true,
            "systemd_reloading_notify_supported": true,
            "systemd_stopping_notify_supported": true,
            "cleanup_report": "resident-production-runtime-cleanup.json",
            "start_report": "resident-production-runtime-start.json",
        },
        "resident_runtime_resource_limits": {
            "max_rss_bytes": RESIDENT_RUNTIME_MAX_RSS_BYTES,
            "max_thread_count": RESIDENT_RUNTIME_MAX_THREAD_COUNT,
            "max_fd_count": RESIDENT_RUNTIME_MAX_FD_COUNT,
            "max_report_size_bytes": RESIDENT_RUNTIME_MAX_REPORT_SIZE_BYTES,
        },
        "resident_runtime_resource_observation_fields": [
            "resident_memory_rss_bytes",
            "resident_thread_count",
            "resident_fd_count",
            "resident_report_size_bytes"
        ],
        "pid_file_path": PID_FILE_PATH,
        "progress_file_path": PROGRESS_FILE_PATH,
        "abort_file_path": ABORT_FILE_PATH,
        "primary_state_store": DAED_PRIMARY_STATE_STORE,
        "protected_rollback_state_store": DAED_PROTECTED_ROLLBACK_STATE_STORE,
        "rust_daed_writes_wing_db_by_default": false,
        "wing_db_import_supported": true,
        "wing_db_import_destructive_by_default": false,
        "daed_db_primary_required": true,
        "var_lib_daed_required_by_default": false,
        "reload_progress_bytes": {
            "send": (RELOAD_SEND as char).to_string(),
            "processing": (RELOAD_PROCESSING as char).to_string(),
            "done": (RELOAD_DONE as char).to_string(),
            "error": (RELOAD_ERROR as char).to_string(),
        },
        "resident_dataplane_default_switch_required": true,
        "resident_dataplane_env": RESIDENT_DATAPLANE_ENV,
        "resident_dataplane_env_enabled": resident_dataplane_default_switch_ready,
        "resident_dataplane_default_switch_ready": resident_dataplane_default_switch_ready,
        "resident_production_dataplane_ready": resident_dataplane_default_switch_ready,
        "resident_default_daemon_switch_ready": resident_dataplane_default_switch_ready,
        "default_path_switch_blocker": default_path_switch_blocker,
        "boundary": "resident run starts and owns production topology, PARAM-aware tc/eBPF attach, and tproxy listener/sockmap handoff; resident userspace dataplane must be explicitly enabled before default switch; product-chain switch still requires clean admission evidence and explicit host mutation authorization",
    });
    insert_control_plane_service_contract_capabilities(
        &mut report,
        control_plane_runtime_state,
        control_plane_runtime_state_ready,
        control_api_typed_report,
        control_plane_typed_report_ready,
    );
    insert_datapath_core_service_contract_capabilities(&mut report);
    insert_outbound_fingerprint_underlay_service_contract_capabilities(&mut report);
    insert_outbound_production_matrix_service_contract_capabilities(&mut report);
    insert_resident_live_adapter_matrix_service_contract_capabilities(&mut report);
    insert_release_default_switch_service_contract_capabilities(&mut report);
    insert_go_free_product_chain_service_contract_capabilities(&mut report);
    report
}

pub(super) fn insert_control_plane_service_contract_capabilities(
    report: &mut Value,
    control_plane_runtime_state: dae_control::RuntimeStateReport,
    control_plane_runtime_state_ready: bool,
    control_api_typed_report: dae_control::ControlApiTypedReport,
    control_plane_typed_report_ready: bool,
) {
    if let Value::Object(report) = report {
        report.insert("control_plane_owner_contract_ready".to_owned(), json!(true));
        report.insert(
            "control_plane_runtime_state_ready".to_owned(),
            json!(control_plane_runtime_state_ready),
        );
        report.insert(
            "control_plane_runtime_state_report".to_owned(),
            json!({
                "schema_version": control_plane_runtime_state.schema_version,
                "rust_owned_runtime": control_plane_runtime_state.rust_owned_runtime,
                "reload_state_available": control_plane_runtime_state.reload_state_available,
                "backend_state_available": control_plane_runtime_state.backend_state_available,
                "routing_owner_available": control_plane_runtime_state.routing_owner_available,
                "domain_owner_available": control_plane_runtime_state.domain_owner_available,
                "connectivity_owner_available": control_plane_runtime_state.connectivity_owner_available,
                "active_handoff_available": control_plane_runtime_state.active_handoff_available,
                "api_compatible": control_plane_runtime_state.api_compatible,
                "ready_for_default_control_plane": control_plane_runtime_state_ready,
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
        report.insert(
            "control_plane_typed_report_ready".to_owned(),
            json!(control_plane_typed_report_ready),
        );
        report.insert(
            "control_plane_typed_report".to_owned(),
            json!({
                "schema": control_api_typed_report.schema,
                "status": control_api_typed_report.status.as_str(),
                "runtime_overview_available": control_api_typed_report.runtime_overview_available,
                "reload_core_state_available": control_api_typed_report.reload_core_state_available,
                "domain_routing_owner_available": control_api_typed_report.domain_routing_owner_available,
                "runtime_dependency_plan_available": control_api_typed_report.runtime_dependency_plan_available,
                "stage_report_schema": control_api_typed_report.stage_report_schema,
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
}
