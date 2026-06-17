use super::*;
pub fn service_contract_capabilities(version: &str) -> Value {
    let control_plane_runtime_state =
        dae_runtime_control::RuntimeStateReport::rust_owned_control_plane();
    let control_plane_runtime_state_ready =
        control_plane_runtime_state.ready_for_product_control_plane();
    let control_api_typed_report =
        dae_runtime_control::ControlApiTypedReport::formal_runtime_control_api();
    let control_plane_typed_report_ready = matches!(
        control_api_typed_report.status,
        dae_runtime_control::ControlApiReportStatus::Pass
    ) && control_api_typed_report.runtime_overview_available
        && control_api_typed_report.reload_core_state_available
        && control_api_typed_report.domain_routing_owner_available
        && control_api_typed_report.runtime_dependency_plan_available
        && control_api_typed_report.current_report_schema;
    let resident_dataplane_admission_ready = resident_dataplane_admission_ready_from_env();
    let resident_dataplane_admission_blocker = if resident_dataplane_admission_ready {
        Value::Null
    } else {
        json!(format!(
            "{RESIDENT_DATAPLANE_ENV} explicitly disables the resident userspace dataplane"
        ))
    };
    let mut report = json!({
        "name": "dae-daemon-service-contract",
        "version": version,
        "resident_run_service_contract_ready": true,
        "reload_command_service_contract_ready": true,
        "systemd_notify_ready_supported": true,
        "reload_failure_restore_supported": true,
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
        "legacy_import_state_store": DAED_LEGACY_IMPORT_STATE_STORE,
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
        "resident_dataplane_admission_env_required": false,
        "resident_dataplane_source": "rust-native-product-runtime",
        "resident_dataplane_env": RESIDENT_DATAPLANE_ENV,
        "resident_dataplane_env_required": false,
        "resident_dataplane_env_enabled": resident_dataplane_admission_ready,
        "resident_dataplane_admission_ready": resident_dataplane_admission_ready,
        "resident_production_dataplane_ready": resident_dataplane_admission_ready,
        "resident_daemon_runtime_ready": resident_dataplane_admission_ready,
        "resident_dataplane_admission_blocker": resident_dataplane_admission_blocker,
        "boundary": "resident run starts and owns production topology, PARAM-aware tc/eBPF attach, and tproxy listener/sockmap handoff; resident userspace dataplane is enabled by the Rust-native product runtime and keeps fail-closed admission evidence before explicit host mutation",
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
    insert_runtime_state_contract_capabilities(&mut report);
    report
}

fn insert_runtime_state_contract_capabilities(report: &mut Value) {
    let runtime_state_evidence = crate::runtime_state_evidence::runtime_state_evidence_from_env();
    if let Value::Object(report) = report {
        report.insert(
            "production_admission_contract_ready".to_owned(),
            json!(true),
        );
        report.insert(
            "release_native_admission_contract_ready".to_owned(),
            json!(true),
        );
        report.insert(
            "production_default_artifact_path_ready".to_owned(),
            json!(true),
        );
        report.insert(
            "release_default_artifact_path_ready".to_owned(),
            json!(true),
        );
        report.insert(
            "product_runtime_selector_no_env_rust_owned_ready".to_owned(),
            json!(true),
        );
        report.insert(
            "install_service_package_scripts_ready".to_owned(),
            json!(true),
        );
        report.insert(
            "runtime_state_live_evidence_contract_ready".to_owned(),
            json!(true),
        );
        report.insert(
            "release_native_live_evidence_contract_ready".to_owned(),
            json!(true),
        );
        report.insert("backup_manifest_contract_ready".to_owned(), json!(true));
        report.insert("restore_rehearsal_contract_ready".to_owned(), json!(true));
        report.insert(
            "host_write_freeze_contract_required".to_owned(),
            json!(true),
        );
        report.insert(
            "production_runtime_state_claim".to_owned(),
            json!(runtime_state_evidence.ready),
        );
        report.insert(
            "release_native_final_state_claim".to_owned(),
            json!(runtime_state_evidence.ready),
        );
        report.insert(
            "production_admission_report_schema".to_owned(),
            json!("production-admission"),
        );
        report.insert(
            "release_native_admission_report_schema".to_owned(),
            json!("production-admission"),
        );
        report.insert("runtime_state_contract_ready".to_owned(), json!(true));
        report.insert(
            "runtime_state_report_schema".to_owned(),
            json!("runtime-state"),
        );
        report.insert(
            "product_package_ready".to_owned(),
            json!(runtime_state_evidence.product_package_ready),
        );
        report.insert(
            "production_product_package_ready".to_owned(),
            json!(runtime_state_evidence.product_package_ready),
        );
        report.insert(
            "native_product_shell_ready".to_owned(),
            json!(runtime_state_evidence.native_product_shell_ready),
        );
        report.insert(
            "native_orchestration_ready".to_owned(),
            json!(runtime_state_evidence.native_orchestration_ready),
        );
        report.insert(
            "native_control_runtime_api_service_release_ready".to_owned(),
            json!(runtime_state_evidence.native_control_runtime_api_service_release_ready),
        );
        report.insert(
            "native_outbound_dependency_ready".to_owned(),
            json!(runtime_state_evidence.native_outbound_dependency_ready),
        );
        report.insert(
            "userland_native_abi_ready".to_owned(),
            json!(runtime_state_evidence.userland_native_abi_ready),
        );
        report.insert(
            "rust_product_binary_contract_ready".to_owned(),
            json!(runtime_state_evidence.rust_product_binary_contract_ready),
        );
        report.insert(
            "rust_product_lifecycle_contract_ready".to_owned(),
            json!(runtime_state_evidence.rust_product_lifecycle_contract_ready),
        );
        report.insert(
            "rust_product_web_api_package_release_contract_ready".to_owned(),
            json!(runtime_state_evidence.rust_product_web_api_package_release_contract_ready),
        );
        report.insert(
            "live_host_contract_ready".to_owned(),
            json!(runtime_state_evidence.live_host_contract_ready),
        );
        report.insert(
            "state_artifact_ready".to_owned(),
            json!(runtime_state_evidence.final_state_artifact_ready),
        );
        report.insert(
            "runtime_state_typed_report_ready".to_owned(),
            json!(runtime_state_evidence.typed_report_ready),
        );
        report.insert(
            "runtime_state_ready".to_owned(),
            json!(runtime_state_evidence.ready),
        );
        report.insert(
            "runtime_state_evidence".to_owned(),
            runtime_state_evidence.report.clone(),
        );
        report.insert(
            "runtime_state_current_status".to_owned(),
            json!(if runtime_state_evidence.ready {
                "runtime state evidence admitted"
            } else {
                "runtime state blocked pending live matrix and artifact evidence"
            }),
        );
        report.insert(
            "runtime_state_remaining_work".to_owned(),
            json!(runtime_state_evidence.blockers.clone()),
        );
        report.insert(
            "runtime_state_typed_report".to_owned(),
            json!({
                "schema": "runtime-state-typed-report",
                "status": if runtime_state_evidence.ready { "pass" } else { "blocked" },
                "product_package_ready": runtime_state_evidence.product_package_ready,
                "native_product_shell_ready": runtime_state_evidence.native_product_shell_ready,
                "native_orchestration_ready": runtime_state_evidence.native_orchestration_ready,
                "native_control_runtime_api_service_release_ready": runtime_state_evidence.native_control_runtime_api_service_release_ready,
                "native_outbound_dependency_ready": runtime_state_evidence.native_outbound_dependency_ready,
                "userland_native_abi_ready": runtime_state_evidence.userland_native_abi_ready,
                "rust_product_binary_contract_ready": runtime_state_evidence.rust_product_binary_contract_ready,
                "rust_product_lifecycle_contract_ready": runtime_state_evidence.rust_product_lifecycle_contract_ready,
                "rust_product_web_api_package_release_contract_ready": runtime_state_evidence.rust_product_web_api_package_release_contract_ready,
                "live_host_contract_ready": runtime_state_evidence.live_host_contract_ready,
                "state_artifact_ready": runtime_state_evidence.final_state_artifact_ready,
                "runtime_state_ready": runtime_state_evidence.ready,
                "live_host_replacement_applied": runtime_state_evidence.report["liveHostReplacementApplied"].clone(),
                "final_state_validation_applied_on_live_host": runtime_state_evidence.report["finalStateValidationAppliedOnLiveHost"].clone(),
                "current_status": if runtime_state_evidence.ready {
                    "runtime state evidence admitted"
                } else {
                    "runtime state blocked pending live matrix and artifact evidence"
                },
                "blockers": runtime_state_evidence.blockers.clone(),
                "state_evidence": runtime_state_evidence.report.clone(),
            }),
        );
        report.insert(
            "production_live_host_contract_ready".to_owned(),
            json!(runtime_state_evidence.live_host_contract_ready),
        );
        report.insert(
            "production_final_state_artifact_ready".to_owned(),
            json!(runtime_state_evidence.final_state_artifact_ready),
        );
        report.insert(
            "runtime_state_typed_report_ready".to_owned(),
            json!(runtime_state_evidence.typed_report_ready),
        );
        report.insert(
            "runtime_state_ready".to_owned(),
            json!(runtime_state_evidence.ready),
        );
        report.insert(
            "runtime_state_final_evidence".to_owned(),
            runtime_state_evidence.report.clone(),
        );
        report.insert(
            "runtime_state_current_status".to_owned(),
            report
                .get("runtime_state_current_status")
                .cloned()
                .unwrap_or(Value::Null),
        );
        report.insert(
            "runtime_state_remaining_work".to_owned(),
            json!(runtime_state_evidence.blockers.clone()),
        );
        report.insert(
            "runtime_state_typed_report".to_owned(),
            report
                .get("runtime_state_typed_report")
                .cloned()
                .unwrap_or(Value::Null),
        );
    }
}

pub(super) fn insert_control_plane_service_contract_capabilities(
    report: &mut Value,
    control_plane_runtime_state: dae_runtime_control::RuntimeStateReport,
    control_plane_runtime_state_ready: bool,
    control_api_typed_report: dae_runtime_control::ControlApiTypedReport,
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
                "ready_for_product_control_plane": control_plane_runtime_state_ready,
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
        report.insert("native_daemon_benchmark_gate_ready".to_owned(), json!(true));
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
                "current_report_schema": control_api_typed_report.current_report_schema,
            }),
        );
        report.insert(
            "control_plane_owner_surface".to_owned(),
            json!({
                "routing_map_owner": "dae-runtime-control::RoutingMapOwner",
                "domain_routing_owner": "dae-runtime-control::DomainRoutingOwner",
                "outbound_connectivity_owner": "dae-runtime-control::OutboundConnectivityOwner",
                "runtime_overview": "formal RuntimeOverview API surface",
                "runtime_cache_stats": "runtime overview/cache/stats typed surface",
                "reload_parity": "reload core state plus previous-runtime restore contract",
                "cleanup_leftovers_gate": "production runtime cleanup leftovers gate",
                "native_benchmark_gate": "native daemon benchmark gate",
            }),
        );
        report.insert(
            "control_plane_report_schema".to_owned(),
            json!("control-plane-owner"),
        );
        report.insert(
            "control_plane_native_tproxy_contract_ready".to_owned(),
            json!(true),
        );
        report.insert(
            "control_plane_native_dependency_contract_ready".to_owned(),
            json!(true),
        );
        report.insert(
            "control_plane_native_dependency_production_ready".to_owned(),
            json!(true),
        );
        report.insert(
            "control_plane_native_dependency_candidate".to_owned(),
            json!(true),
        );
    }
}
