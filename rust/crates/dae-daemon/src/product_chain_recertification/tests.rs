use super::*;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

mod baseline;
mod control_plane_owner;
mod datapath_core;
mod default_switch;
mod dependency_boundary;
mod go_free_product_chain;
mod local_validation;
mod native_owned_entry_gates;
mod outbound_fingerprint_underlay;
mod outbound_production_matrix;
mod readiness_host_write;
mod release_default_switch;
mod repo_status;
mod resident_runtime_platform;
mod run_command_replacement;
mod runtime_control_contract;

fn write_fixture_file(path: &Path, text: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

fn write_candidate_service_contract(path: &Path, resident_dataplane_ready: bool) {
    write_candidate_service_contract_value(
        path,
        &candidate_service_contract_value(resident_dataplane_ready),
    );
}

fn candidate_service_contract_value(resident_dataplane_ready: bool) -> Value {
    let mut report = serde_json::Map::new();
    report.insert(
        "resident_run_service_contract_ready".to_owned(),
        json!(true),
    );
    report.insert(
        "reload_command_service_contract_ready".to_owned(),
        json!(true),
    );
    report.insert("systemd_notify_ready_supported".to_owned(), json!(true));
    report.insert("reload_failure_rollback_supported".to_owned(), json!(true));
    report.insert(
        "invalid_runtime_config_rejected_before_current_swap".to_owned(),
        json!(true),
    );
    report.insert(
        "reload_start_failure_attempts_previous_runtime_restore".to_owned(),
        json!(true),
    );
    report.insert(
        "resident_production_dataplane_ready".to_owned(),
        json!(resident_dataplane_ready),
    );
    report.insert(
        "resident_default_daemon_switch_ready".to_owned(),
        json!(resident_dataplane_ready),
    );
    report.insert(
        "resident_runtime_platform_contract_ready".to_owned(),
        json!(true),
    );
    report.insert(
        "resident_runtime_typed_report_ready".to_owned(),
        json!(true),
    );
    report.insert(
        "resident_runtime_resource_gate_ready".to_owned(),
        json!(true),
    );
    report.insert(
        "resident_runtime_report_schema".to_owned(),
        json!("resident-runtime-platform-report"),
    );
    report.insert(
        "resident_runtime_lifecycle_contract".to_owned(),
        json!({
            "pid_file": "/var/run/dae.pid",
            "progress_file": "/var/run/dae.progress",
            "abort_file": "/var/run/dae.abort",
            "ready_record_file_supported": true,
            "cleanup_report": "resident-production-runtime-cleanup.json",
            "start_report": "resident-production-runtime-start.json",
        }),
    );
    report.insert(
        "resident_runtime_resource_limits".to_owned(),
        json!({
            "max_rss_bytes": 536870912_u64,
            "max_thread_count": 256,
            "max_fd_count": 1024,
            "max_report_size_bytes": 524288,
        }),
    );
    report.insert(
        "resident_runtime_resource_observation_fields".to_owned(),
        json!([
            "resident_memory_rss_bytes",
            "resident_thread_count",
            "resident_fd_count",
            "resident_report_size_bytes",
        ]),
    );
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
    for key in [
        "datapath_core_contract_ready",
        "datapath_core_runtime_state_ready",
        "tcp_tproxy_datapath_ready",
        "tcp_route_sniff_direct_block_proxy_ready",
        "udp_tproxy_datapath_ready",
        "udp_endpoint_pool_ready",
        "dns_tproxy_datapath_ready",
        "dns_cache_route_integration_ready",
        "sniff_result_contract_ready",
        "route_result_contract_ready",
        "direct_block_proxy_action_contract_ready",
        "datapath_core_benchmark_gate_ready",
        "datapath_core_typed_report_ready",
        "no_go_userspace_datapath_fallback_contract_ready",
        "c_tproxy_oracle_retired_after_datapath_core",
        "go_datapath_core_fallback_retirement_contract_ready",
        "go_datapath_core_fallback_retired_candidate",
    ] {
        report.insert(key.to_owned(), json!(true));
    }
    report.insert(
        "datapath_core_typed_report".to_owned(),
        json!({
            "schema": "datapath-core-typed-report",
            "status": "pass",
            "stage_report_schema": false,
        }),
    );
    report.insert(
        "datapath_core_surface".to_owned(),
        json!({
            "tcp": "dae-datapath active TCP route/sniff/direct/block/proxy",
            "udp": "dae-datapath active UDP endpoint/direct/proxy/block",
            "dns": "dae-dns qtype/qclass/cache/forward/reject",
            "sniff": "dae-sniffing packet and TCP sniff contract",
            "resident_adapter": "dae-daemon production_runtime_owner resident dataplane",
        }),
    );
    report.insert(
        "datapath_core_report_schema".to_owned(),
        json!("datapath-core"),
    );
    for key in [
        "outbound_fingerprint_underlay_contract_ready",
        "standard_tls_underlay_contract_ready",
        "fingerprint_aware_tls_underlay_contract_ready",
        "link_fingerprint_plan_ready",
        "global_fingerprint_plan_ready",
        "unknown_fingerprint_fail_closed_ready",
        "rustls_standard_tls_no_fingerprint_ready",
        "boring_fingerprint_underlay_ready",
        "no_silent_fingerprint_rustls_fallback_ready",
        "fingerprint_underlay_live_evidence_contract_ready",
        "utls_wire_oracle_comparison_recorded",
        "full_utls_parity_not_declared_without_wire_oracle",
        "outbound_fingerprint_underlay_typed_report_ready",
        "go_fingerprint_underlay_fallback_retirement_contract_ready",
        "go_fingerprint_underlay_fallback_retired_candidate",
        "security_underlay_capability_contract_ready",
        "common_security_underlay_ready",
    ] {
        report.insert(key.to_owned(), json!(true));
    }
    for key in [
        "expanded_security_underlay_complete",
        "security_underlay_release_gate_ready",
    ] {
        report.insert(key.to_owned(), json!(false));
    }
    report.insert(
        "outbound_fingerprint_underlay_report_schema".to_owned(),
        json!("outbound-fingerprint-underlay"),
    );
    report.insert(
        "outbound_fingerprint_underlay_surface".to_owned(),
        json!({
            "registry": "dae-outbound::shared_transport::utls_fingerprint",
            "standard_tls_underlay": "rustls when no fingerprint is selected or fingerprint resolves to unsafe",
            "fingerprint_aware_tls_underlay": "boring-backed resident adapter for link fingerprint or global fingerprint fallback",
            "unknown_fingerprint_policy": "fail-closed",
            "no_silent_fallback_policy": "fingerprint-aware requests must not degrade to standard rustls",
        }),
    );
    report.insert(
        "outbound_fingerprint_underlay_typed_report".to_owned(),
        json!({
            "schema": "outbound-fingerprint-underlay-typed-report",
            "status": "pass",
            "stage_report_schema": false,
        }),
    );
    report.insert(
        "security_underlay_capability_report_schema".to_owned(),
        json!("security-underlay-capability"),
    );
    report.insert(
        "security_underlay_capability_row_count".to_owned(),
        json!(2),
    );
    report.insert(
        "security_underlay_capability_rows".to_owned(),
        json!([
            {"capabilityId": "standard-tls-common-underlay", "status": "admitted"},
            {"capabilityId": "reality-security-underlay", "status": "blocked", "blockerId": "missing-security-underlay"}
        ]),
    );
    report.insert(
        "security_underlay_capability_typed_report".to_owned(),
        json!({
            "schema": "security-underlay-capability-typed-report",
            "status": "pass",
            "common_security_underlay_ready": true,
            "expanded_security_underlay_complete": false,
            "release_gate_ready": false,
            "stage_report_schema": false,
        }),
    );
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
        "stream_wrapper_capability_contract_ready",
        "websocket_wss_loopback_ready",
    ] {
        report.insert(key.to_owned(), json!(true));
    }
    for key in [
        "expanded_source_matrix_complete",
        "expanded_source_matrix_release_gate_ready",
        "expanded_source_matrix_c10_ready",
        "stream_wrapper_resident_source_admission_ready",
        "expanded_stream_wrapper_complete",
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
            "status": "partial",
            "websocket_wss_loopback_ready": true,
            "resident_source_admission_ready": true,
            "expanded_stream_wrapper_complete": false,
            "stage_report_schema": false,
        }),
    );
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
    for key in [
        "release_default_switch_contract_ready",
        "release_default_artifact_path_ready",
        "default_runtime_selector_no_env_rust_owned_ready",
        "install_service_package_scripts_ready",
        "release_default_switch_live_evidence_contract_ready",
        "backup_manifest_contract_ready",
        "rollback_rehearsal_contract_ready",
        "host_write_freeze_contract_required",
        "go_product_shell_allowed_until_go_free",
        "release_default_switch_typed_report_ready",
    ] {
        report.insert(key.to_owned(), json!(true));
    }
    report.insert(
        "release_default_switch_final_go_free_claim".to_owned(),
        json!(false),
    );
    report.insert(
        "release_default_switch_report_schema".to_owned(),
        json!("release-default-switch"),
    );
    report.insert(
        "release_default_switch_required_live_hosts".to_owned(),
        json!(["38", "10.10.10.2"]),
    );
    report.insert(
        "release_default_switch_surface".to_owned(),
        json!([
            "release/action/docker/package default candidate path",
            "default runtime selector with no environment override",
            "install service and package script default command contract",
            "candidate service-contract and live evidence record contract",
            "backup manifest and rollback script contract",
            "read-only host-write freeze before any production mutation"
        ]),
    );
    report.insert(
        "release_default_switch_typed_report".to_owned(),
        json!({
            "schema": "release-default-switch-typed-report",
            "status": "pass",
            "stage_report_schema": false,
        }),
    );
    report.insert(
        "go_free_product_chain_contract_ready".to_owned(),
        json!(true),
    );
    report.insert("default_product_package_go_free".to_owned(), json!(false));
    report.insert(
        "go_product_shell_retired_from_default_package".to_owned(),
        json!(false),
    );
    report.insert(
        "go_orchestration_retired_from_default_package".to_owned(),
        json!(false),
    );
    report.insert(
        "go_control_runtime_api_service_release_retired_from_default_package".to_owned(),
        json!(false),
    );
    report.insert(
        "go_outbound_dependency_retired_from_default_package".to_owned(),
        json!(false),
    );
    report.insert("go_compat_oracle_boundary_ready".to_owned(), json!(true));
    report.insert(
        "rust_product_binary_contract_ready".to_owned(),
        json!(false),
    );
    report.insert(
        "rust_product_lifecycle_contract_ready".to_owned(),
        json!(false),
    );
    report.insert(
        "rust_product_web_api_package_release_contract_ready".to_owned(),
        json!(false),
    );
    report.insert("go_free_live_host_contract_ready".to_owned(), json!(false));
    report.insert("go_free_rollback_model_ready".to_owned(), json!(true));
    report.insert(
        "go_free_product_chain_typed_report_ready".to_owned(),
        json!(true),
    );
    report.insert("go_free_product_chain_ready".to_owned(), json!(false));
    report.insert(
        "go_free_product_chain_report_schema".to_owned(),
        json!("go-free-product-chain"),
    );
    report.insert(
        "go_free_product_chain_default_dependency_policy".to_owned(),
        json!(
            "Go dependencies are not allowed in the default product package after this gate passes"
        ),
    );
    report.insert(
        "go_free_product_chain_retained_go_scope".to_owned(),
        json!("oracle/test/compat only until the final product package is proven go-free"),
    );
    report.insert(
        "go_free_product_chain_surface".to_owned(),
        json!([
            "Rust product binary owns run/reload/stop/service-contract",
            "Rust product binary owns Web/API/package/release entry points",
            "Go product shell is absent from default package and release path",
            "Go orchestration and Go outbound dependencies are absent from default package",
            "Go compatibility code is retained only as oracle/test/compat evidence",
            "live host and rollback evidence pass on the final go-free package"
        ]),
    );
    report.insert(
        "go_free_product_chain_typed_report".to_owned(),
        json!({
            "schema": "go-free-product-chain-typed-report",
            "status": "blocked",
            "stage_report_schema": false,
        }),
    );
    Value::Object(report)
}

fn write_candidate_service_contract_value(path: &Path, report: &Value) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let report = serde_json::to_string(report).unwrap();
    std::fs::write(
        path,
        format!(
            "#!/bin/sh\n\
             if [ \"$1\" = \"validate\" ]; then exit 0; fi\n\
             if [ \"$1\" = \"service-contract\" ]; then\n\
               cat <<'JSON'\n\
{report}\n\
JSON\n\
               exit 0\n\
             fi\n\
             exit 2\n"
        ),
    )
    .unwrap();
    #[cfg(unix)]
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

fn init_fixture_repo(path: &Path, branch: &str) {
    std::fs::create_dir_all(path).unwrap();
    assert!(
        Command::new("git")
            .args(["init", "--quiet"])
            .current_dir(path)
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new("git")
            .args(["checkout", "--quiet", "-B", branch])
            .current_dir(path)
            .status()
            .unwrap()
            .success()
    );
}

fn resident_ready_product_chain_options(
    root: &Path,
    mut options: ProductChainRecertificationOptions,
) -> ProductChainRecertificationOptions {
    let binary = root.join("resident-ready-candidate");
    write_candidate_service_contract(&binary, true);
    options.resident_default_daemon_binary_source = Some(binary);
    options
}

fn resident_service_only_product_chain_options(
    root: &Path,
    mut options: ProductChainRecertificationOptions,
) -> ProductChainRecertificationOptions {
    let binary = root.join("resident-service-only-candidate");
    write_candidate_service_contract(&binary, false);
    options.resident_default_daemon_binary_source = Some(binary);
    options
}

fn clean_product_chain_evidence() -> ProductChainEvidence {
    ProductChainEvidence {
        topology: json!({
            "chain": "daed2.0-web-wing-daecore",
            "daed2_wing_repo_used": true,
            "standalone_dae_wing_repo_used": false,
        }),
        service: json!({
            "status": "pass",
            "service_contract_preserved": true,
        }),
        go_mod: json!({
            "status": "pass",
            "outbound_quic_go_dependency_boundary_preserved": true,
        }),
        repos: Vec::new(),
        runtime_control_api: json!({
            "status": "pass",
            "runtime_control_api_source_contract_preserved": true,
        }),
        native_owned_entry_gates: json!({
            "status": "pass",
            "product_chain_topology_locked": true,
            "default_bundle_boundary_clean": true,
            "default_runtime_selector_rust_owned": true,
            "explicit_go_rollback_only": true,
            "runtime_selector_matrix_recorded": true,
            "daed_service_contract_ready": true,
            "c0_product_chain_topology_lock": {
                "status": "pass",
                "product_chain_topology_locked": true,
            },
            "c1_default_bundle_boundary": {
                "status": "pass",
                "default_bundle_boundary_clean": true,
            },
            "c2_default_runtime_selector": {
                "status": "pass",
                "default_runtime_selector_rust_owned": true,
                "explicit_go_rollback_only": true,
                "runtime_selector_matrix_recorded": true,
            },
            "c3_daed_service_contract": {
                "status": "pass",
                "daed_service_contract_ready": true,
            },
        }),
        native_owned_entry_gate_blockers: Vec::new(),
        resident_runtime_platform_gate: json!({
            "name": "resident-runtime-platform",
            "status": "pass",
            "requested": true,
            "resident_runtime_platform_ready": true,
            "resident_runtime_resource_gate_ready": true,
            "resident_runtime_resource_gate_passed": true,
            "resident_run_service_contract_ready": true,
            "reload_command_service_contract_ready": true,
            "systemd_notify_ready_supported": true,
            "reload_failure_rollback_supported": true,
            "invalid_runtime_config_rejected_before_current_swap": true,
            "reload_start_failure_attempts_previous_runtime_restore": true,
            "resident_production_dataplane_ready": true,
            "resident_runtime_platform_contract_ready": true,
            "resident_runtime_typed_report_ready": true,
            "pid_progress_ready_abort_cleanup_contract_ready": true,
            "resident_runtime_resource_gate": {
                "status": "pass",
                "ready": true,
                "memory_thread_fd_limits_declared": true,
                "report_size_gate_passed": true,
            },
            "blockers": [],
        }),
        resident_runtime_platform_gate_blockers: Vec::new(),
        control_plane_owner_gate: json!({
            "name": "control-plane-owner",
            "status": "pass",
            "requested": true,
            "control_plane_owner_ready": true,
            "go_control_plane_fallback_retired_candidate": true,
            "control_plane_owner_default_switch_admission_ready": true,
            "control_plane_owner_contract_ready": true,
            "control_plane_runtime_state_ready": true,
            "routing_map_owner_ready": true,
            "domain_routing_owner_ready": true,
            "outbound_connectivity_owner_ready": true,
            "runtime_overview_cache_stats_ready": true,
            "control_plane_reload_parity_contract_ready": true,
            "control_plane_cleanup_leftovers_gate_ready": true,
            "matched_go_rust_default_daemon_benchmark_gate_ready": true,
            "control_plane_typed_report_ready": true,
            "control_plane_c_tproxy_oracle_retained_until_datapath_core": true,
            "go_control_plane_fallback_retirement_contract_ready": true,
            "blockers": [],
        }),
        control_plane_owner_gate_blockers: Vec::new(),
        datapath_core_gate: json!({
            "name": "datapath-core",
            "status": "pass",
            "requested": true,
            "datapath_core_ready": true,
            "go_datapath_core_fallback_retired_candidate": true,
            "datapath_core_default_switch_admission_ready": true,
            "datapath_core_contract_ready": true,
            "datapath_core_runtime_state_ready": true,
            "tcp_datapath_core_ready": true,
            "udp_datapath_core_ready": true,
            "dns_datapath_core_ready": true,
            "tcp_tproxy_datapath_ready": true,
            "tcp_route_sniff_direct_block_proxy_ready": true,
            "udp_tproxy_datapath_ready": true,
            "udp_endpoint_pool_ready": true,
            "dns_tproxy_datapath_ready": true,
            "dns_cache_route_integration_ready": true,
            "sniff_result_contract_ready": true,
            "route_result_contract_ready": true,
            "direct_block_proxy_action_contract_ready": true,
            "datapath_core_benchmark_gate_ready": true,
            "datapath_core_typed_report_ready": true,
            "no_go_userspace_datapath_fallback_contract_ready": true,
            "c_tproxy_oracle_retired_after_datapath_core": true,
            "go_datapath_core_fallback_retirement_contract_ready": true,
            "blockers": [],
        }),
        datapath_core_gate_blockers: Vec::new(),
        outbound_fingerprint_underlay_gate: json!({
            "name": "outbound-fingerprint-underlay",
            "status": "pass",
            "requested": true,
            "outbound_fingerprint_underlay_ready": true,
            "go_fingerprint_underlay_fallback_retired_candidate": true,
            "outbound_fingerprint_underlay_default_switch_admission_ready": true,
            "outbound_fingerprint_underlay_contract_ready": true,
            "standard_tls_underlay_contract_ready": true,
            "fingerprint_aware_tls_underlay_contract_ready": true,
            "link_fingerprint_plan_ready": true,
            "global_fingerprint_plan_ready": true,
            "unknown_fingerprint_fail_closed_ready": true,
            "rustls_standard_tls_no_fingerprint_ready": true,
            "boring_fingerprint_underlay_ready": true,
            "no_silent_fingerprint_rustls_fallback_ready": true,
            "fingerprint_underlay_live_evidence_contract_ready": true,
            "utls_wire_oracle_comparison_recorded": true,
            "full_utls_parity_not_declared_without_wire_oracle": true,
            "outbound_fingerprint_underlay_typed_report_ready": true,
            "go_fingerprint_underlay_fallback_retirement_contract_ready": true,
            "blockers": [],
        }),
        outbound_fingerprint_underlay_gate_blockers: Vec::new(),
        outbound_production_matrix_gate: json!({
            "name": "outbound-production-matrix",
            "status": "pass",
            "requested": true,
            "outbound_production_matrix_ready": true,
            "go_outbound_fallback_retired_candidate": true,
            "outbound_production_matrix_default_switch_admission_ready": true,
            "outbound_production_matrix_contract_ready": true,
            "outbound_production_matrix_runtime_state_ready": true,
            "outbound_matrix_entries_ready": true,
            "parser_export_metadata_matrix_ready": true,
            "tcp_udp_dataplane_matrix_ready": true,
            "transport_underlay_matrix_ready": true,
            "route_group_connectivity_matrix_ready": true,
            "reload_behavior_matrix_ready": true,
            "live_smoke_matrix_ready": true,
            "go_outbound_fallback_retirement_matrix_ready": true,
            "outbound_production_matrix_typed_report_ready": true,
            "resident_live_adapter_matrix_contract_ready": true,
            "resident_live_adapter_matrix_ready": true,
            "resident_live_adapter_matrix_runtime_state_ready": true,
            "resident_live_adapter_wired_matrix_ready": true,
            "resident_live_adapter_remote_live_matrix_ready": true,
            "resident_live_adapter_matrix_typed_report_ready": true,
            "blockers": [],
        }),
        outbound_production_matrix_gate_blockers: Vec::new(),
        dirty_repos: Vec::new(),
        missing_repos: Vec::new(),
        unavailable_repos: Vec::new(),
        branch_mismatched_repos: Vec::new(),
    }
}
