use std::fs;
use std::io;
use std::path::Path;
use std::process::{Command, Output};
use std::thread;
use std::time::Duration;

use serde_json::{Value, json};

use super::path_string;

pub(super) fn service_contract_json(path: &Path) -> Value {
    let Ok(text) = fs::read_to_string(path) else {
        return json!({
            "status": "fail",
            "path": path_string(path),
            "error": "service file could not be read",
            "service_contract_preserved": false,
        });
    };
    let dae_exec_start_pre =
        text.contains("ExecStartPre=/usr/bin/dae validate -c /etc/dae/config.dae");
    let dae_exec_start =
        text.contains("ExecStart=/usr/bin/dae run --disable-timestamp -c /etc/dae/config.dae");
    let dae_exec_reload = text.contains("ExecReload=/usr/bin/dae reload $MAINPID");
    let dae_optional_env_file = text.contains("EnvironmentFile=-/etc/default/dae");
    let uses_rust_optin = text.contains("dae-daemon-optin");
    let dae_service_contract_preserved =
        dae_exec_start_pre && dae_exec_start && dae_exec_reload && !uses_rust_optin;
    let daed_exec_start_pre = text.contains("ExecStartPre=/usr/bin/daed validate -c /etc/daed/")
        || text.contains("ExecStartPre=/usr/bin/daed validate -c /etc/daed");
    let daed_exec_start = text.contains("ExecStart=/usr/bin/daed run -c /etc/daed/")
        || text.contains("ExecStart=/usr/bin/daed run -c /etc/daed");
    let daed_exec_reload_signal = text.contains("ExecReload=/bin/kill -HUP $MAINPID");
    let daed_type_simple = text.contains("Type=simple");
    let daed_user_root = text.contains("User=root");
    let daed_optional_env_file = text.contains("EnvironmentFile=-/etc/default/daed");
    let daed_service_contract_preserved = daed_exec_start_pre
        && daed_exec_start
        && daed_exec_reload_signal
        && daed_type_simple
        && daed_user_root;
    let service_contract_preserved =
        dae_service_contract_preserved || daed_service_contract_preserved;
    let service_contract_kind = if daed_service_contract_preserved {
        "daed"
    } else if dae_service_contract_preserved {
        "dae"
    } else {
        "unknown"
    };
    json!({
        "status": if service_contract_preserved { "pass" } else { "fail" },
        "path": path_string(path),
        "service_contract_kind": service_contract_kind,
        "exec_start_pre_validate_preserved": dae_exec_start_pre,
        "exec_start_go_default_run_preserved": dae_exec_start,
        "exec_reload_pid_signal_preserved": dae_exec_reload,
        "optional_env_file_for_backend_rollbacks": dae_optional_env_file,
        "rust_optin_binary_referenced": uses_rust_optin,
        "dae_service_contract_preserved": dae_service_contract_preserved,
        "daed_exec_start_pre_validate_preserved": daed_exec_start_pre,
        "daed_exec_start_run_config_dir_preserved": daed_exec_start,
        "daed_exec_reload_hup_preserved": daed_exec_reload_signal,
        "daed_type_simple_preserved": daed_type_simple,
        "daed_user_root_preserved": daed_user_root,
        "daed_optional_env_file_for_runtime_rollbacks": daed_optional_env_file,
        "daed_service_contract_preserved": daed_service_contract_preserved,
        "service_contract_preserved": service_contract_preserved,
    })
}

pub(super) fn candidate_validate_report(
    requested: bool,
    binary_source: Option<&Path>,
    staged_config_source: Option<&Path>,
) -> Value {
    let executable = requested
        && binary_source.is_some_and(Path::is_file)
        && staged_config_source.is_some_and(Path::is_file);
    if !executable {
        return json!({
            "executed": false,
            "passed": false,
            "command": Value::Null,
            "exit_code": Value::Null,
            "stdout": "",
            "stderr": "",
        });
    }
    let binary_source = binary_source.unwrap();
    let staged_config_source = staged_config_source.unwrap();
    let command = vec![
        path_string(binary_source),
        "validate".to_owned(),
        "-c".to_owned(),
        path_string(staged_config_source),
    ];
    match run_candidate_command(
        binary_source,
        &["validate", "-c"],
        Some(staged_config_source),
    ) {
        Ok(output) => json!({
            "executed": true,
            "passed": output.status.success(),
            "command": command,
            "exit_code": output.status.code(),
            "stdout": bounded_command_output(&output.stdout),
            "stderr": bounded_command_output(&output.stderr),
        }),
        Err(err) => json!({
            "executed": true,
            "passed": false,
            "command": command,
            "exit_code": Value::Null,
            "stdout": "",
            "stderr": err.to_string(),
        }),
    }
}

pub(super) fn candidate_service_contract_report(
    requested: bool,
    binary_source: Option<&Path>,
) -> Value {
    let executable = requested && binary_source.is_some_and(Path::is_file);
    if !executable {
        let mut report = json!({
            "executed": false,
            "passed": false,
            "command": Value::Null,
            "exit_code": Value::Null,
            "stdout": "",
            "stderr": "",
            "resident_run_service_contract_ready": false,
            "reload_command_service_contract_ready": false,
            "resident_production_dataplane_ready": false,
            "resident_default_daemon_switch_ready": false,
            "resident_dataplane_default_switch_ready": false,
            "resident_dataplane_env": Value::Null,
            "resident_dataplane_env_enabled": false,
            "default_path_switch_blocker": Value::Null,
            "reload_failure_rollback_supported": false,
            "invalid_runtime_config_rejected_before_current_swap": false,
            "reload_start_failure_attempts_previous_runtime_restore": false,
            "systemd_notify_ready_supported": false,
            "resident_runtime_platform_contract_ready": false,
            "resident_runtime_typed_report_ready": false,
            "resident_runtime_resource_gate_ready": false,
            "resident_runtime_report_schema": Value::Null,
            "resident_runtime_lifecycle_contract": Value::Null,
            "resident_runtime_resource_limits": Value::Null,
            "resident_runtime_resource_observation_fields": [],
            "service_contract_report_size_bytes": 0,
            "rust_daed_validate_command_ready": false,
        });
        insert_control_plane_contract_defaults(&mut report);
        insert_datapath_core_contract_defaults(&mut report);
        insert_outbound_fingerprint_underlay_contract_defaults(&mut report);
        insert_outbound_production_matrix_contract_defaults(&mut report);
        insert_resident_live_adapter_matrix_contract_defaults(&mut report);
        insert_release_default_switch_contract_defaults(&mut report);
        insert_go_free_product_chain_contract_defaults(&mut report);
        return report;
    }
    let binary_source = binary_source.unwrap();
    let command = vec![path_string(binary_source), "service-contract".to_owned()];
    match run_candidate_command(binary_source, &["service-contract"], None) {
        Ok(output) => {
            let stdout = bounded_command_output(&output.stdout);
            let capability = serde_json::from_slice::<Value>(&output.stdout).unwrap_or(Value::Null);
            let resident_run_ready = capability["resident_run_service_contract_ready"]
                .as_bool()
                .unwrap_or(false);
            let reload_ready = capability["reload_command_service_contract_ready"]
                .as_bool()
                .unwrap_or(false);
            let resident_production_dataplane_ready =
                capability["resident_production_dataplane_ready"]
                    .as_bool()
                    .unwrap_or(false);
            let resident_default_daemon_switch_declared =
                capability["resident_default_daemon_switch_ready"]
                    .as_bool()
                    .unwrap_or(false);
            let resident_dataplane_default_switch_ready =
                capability["resident_dataplane_default_switch_ready"]
                    .as_bool()
                    .unwrap_or(resident_default_daemon_switch_declared);
            let resident_dataplane_env = capability["resident_dataplane_env"]
                .as_str()
                .map(str::to_owned);
            let resident_dataplane_env_enabled = capability["resident_dataplane_env_enabled"]
                .as_bool()
                .unwrap_or(resident_dataplane_default_switch_ready);
            let default_path_switch_blocker = capability["default_path_switch_blocker"].clone();
            let reload_failure_rollback_supported = capability["reload_failure_rollback_supported"]
                .as_bool()
                .unwrap_or(false);
            let invalid_runtime_config_rejected_before_current_swap =
                capability["invalid_runtime_config_rejected_before_current_swap"]
                    .as_bool()
                    .unwrap_or(false);
            let reload_start_failure_attempts_previous_runtime_restore =
                capability["reload_start_failure_attempts_previous_runtime_restore"]
                    .as_bool()
                    .unwrap_or(false);
            let systemd_notify_ready_supported = capability["systemd_notify_ready_supported"]
                .as_bool()
                .unwrap_or(false);
            let resident_runtime_platform_contract_ready =
                capability["resident_runtime_platform_contract_ready"]
                    .as_bool()
                    .unwrap_or(false);
            let resident_runtime_typed_report_ready =
                capability["resident_runtime_typed_report_ready"]
                    .as_bool()
                    .unwrap_or(false);
            let resident_runtime_resource_gate_ready =
                capability["resident_runtime_resource_gate_ready"]
                    .as_bool()
                    .unwrap_or(false);
            let rust_daed_validate_command_ready = capability["rust_daed_validate_command_ready"]
                .as_bool()
                .unwrap_or(false);
            let control_plane_owner_contract_ready =
                capability["control_plane_owner_contract_ready"]
                    .as_bool()
                    .unwrap_or(false);
            let control_plane_runtime_state_ready = capability["control_plane_runtime_state_ready"]
                .as_bool()
                .unwrap_or(false);
            let routing_map_owner_ready = capability["routing_map_owner_ready"]
                .as_bool()
                .unwrap_or(false);
            let domain_routing_owner_ready = capability["domain_routing_owner_ready"]
                .as_bool()
                .unwrap_or(false);
            let outbound_connectivity_owner_ready = capability["outbound_connectivity_owner_ready"]
                .as_bool()
                .unwrap_or(false);
            let runtime_overview_cache_stats_ready =
                capability["runtime_overview_cache_stats_ready"]
                    .as_bool()
                    .unwrap_or(false);
            let control_plane_reload_parity_contract_ready =
                capability["control_plane_reload_parity_contract_ready"]
                    .as_bool()
                    .unwrap_or(false);
            let control_plane_cleanup_leftovers_gate_ready =
                capability["control_plane_cleanup_leftovers_gate_ready"]
                    .as_bool()
                    .unwrap_or(false);
            let matched_go_rust_default_daemon_benchmark_gate_ready =
                capability["matched_go_rust_default_daemon_benchmark_gate_ready"]
                    .as_bool()
                    .unwrap_or(false);
            let control_plane_typed_report_ready = capability["control_plane_typed_report_ready"]
                .as_bool()
                .unwrap_or(false);
            let control_plane_c_tproxy_oracle_retained_until_datapath_core =
                capability["control_plane_c_tproxy_oracle_retained_until_datapath_core"]
                    .as_bool()
                    .unwrap_or(false);
            let go_control_plane_fallback_retirement_contract_ready =
                capability["go_control_plane_fallback_retirement_contract_ready"]
                    .as_bool()
                    .unwrap_or(false);
            let go_control_plane_fallback_retired_candidate =
                capability["go_control_plane_fallback_retired_candidate"]
                    .as_bool()
                    .unwrap_or(false);
            let datapath_core_contract_ready = capability["datapath_core_contract_ready"]
                .as_bool()
                .unwrap_or(false);
            let datapath_core_runtime_state_ready = capability["datapath_core_runtime_state_ready"]
                .as_bool()
                .unwrap_or(false);
            let tcp_tproxy_datapath_ready = capability["tcp_tproxy_datapath_ready"]
                .as_bool()
                .unwrap_or(false);
            let tcp_route_sniff_direct_block_proxy_ready =
                capability["tcp_route_sniff_direct_block_proxy_ready"]
                    .as_bool()
                    .unwrap_or(false);
            let udp_tproxy_datapath_ready = capability["udp_tproxy_datapath_ready"]
                .as_bool()
                .unwrap_or(false);
            let udp_endpoint_pool_ready = capability["udp_endpoint_pool_ready"]
                .as_bool()
                .unwrap_or(false);
            let dns_tproxy_datapath_ready = capability["dns_tproxy_datapath_ready"]
                .as_bool()
                .unwrap_or(false);
            let dns_cache_route_integration_ready = capability["dns_cache_route_integration_ready"]
                .as_bool()
                .unwrap_or(false);
            let sniff_result_contract_ready = capability["sniff_result_contract_ready"]
                .as_bool()
                .unwrap_or(false);
            let route_result_contract_ready = capability["route_result_contract_ready"]
                .as_bool()
                .unwrap_or(false);
            let direct_block_proxy_action_contract_ready =
                capability["direct_block_proxy_action_contract_ready"]
                    .as_bool()
                    .unwrap_or(false);
            let datapath_core_benchmark_gate_ready =
                capability["datapath_core_benchmark_gate_ready"]
                    .as_bool()
                    .unwrap_or(false);
            let datapath_core_typed_report_ready = capability["datapath_core_typed_report_ready"]
                .as_bool()
                .unwrap_or(false);
            let no_go_userspace_datapath_fallback_contract_ready =
                capability["no_go_userspace_datapath_fallback_contract_ready"]
                    .as_bool()
                    .unwrap_or(false);
            let c_tproxy_oracle_retired_after_datapath_core =
                capability["c_tproxy_oracle_retired_after_datapath_core"]
                    .as_bool()
                    .unwrap_or(false);
            let go_datapath_core_fallback_retirement_contract_ready =
                capability["go_datapath_core_fallback_retirement_contract_ready"]
                    .as_bool()
                    .unwrap_or(false);
            let go_datapath_core_fallback_retired_candidate =
                capability["go_datapath_core_fallback_retired_candidate"]
                    .as_bool()
                    .unwrap_or(false);
            let resident_default_daemon_switch_ready = output.status.success()
                && resident_run_ready
                && reload_ready
                && resident_production_dataplane_ready
                && resident_default_daemon_switch_declared
                && reload_failure_rollback_supported
                && invalid_runtime_config_rejected_before_current_swap
                && reload_start_failure_attempts_previous_runtime_restore;
            let capability_for_report = capability.clone();
            let mut report = json!({
                "executed": true,
                "passed": output.status.success()
                    && resident_run_ready
                    && reload_ready
                    && reload_failure_rollback_supported
                    && invalid_runtime_config_rejected_before_current_swap
                    && reload_start_failure_attempts_previous_runtime_restore,
                "command": command,
                "exit_code": output.status.code(),
                "stdout": stdout,
                "stderr": bounded_command_output(&output.stderr),
                "resident_run_service_contract_ready": output.status.success() && resident_run_ready,
                "reload_command_service_contract_ready": output.status.success() && reload_ready,
                "resident_production_dataplane_ready": output.status.success() && resident_production_dataplane_ready,
                "resident_default_daemon_switch_ready": resident_default_daemon_switch_ready,
                "resident_dataplane_default_switch_ready": output.status.success() && resident_dataplane_default_switch_ready,
                "resident_dataplane_env": resident_dataplane_env,
                "resident_dataplane_env_enabled": output.status.success() && resident_dataplane_env_enabled,
                "default_path_switch_blocker": default_path_switch_blocker,
                "reload_failure_rollback_supported": output.status.success() && reload_failure_rollback_supported,
                "invalid_runtime_config_rejected_before_current_swap": output.status.success() && invalid_runtime_config_rejected_before_current_swap,
                "reload_start_failure_attempts_previous_runtime_restore": output.status.success() && reload_start_failure_attempts_previous_runtime_restore,
                "systemd_notify_ready_supported": output.status.success() && systemd_notify_ready_supported,
                "resident_runtime_platform_contract_ready": output.status.success() && resident_runtime_platform_contract_ready,
                "resident_runtime_typed_report_ready": output.status.success() && resident_runtime_typed_report_ready,
                "resident_runtime_resource_gate_ready": output.status.success() && resident_runtime_resource_gate_ready,
                "resident_runtime_report_schema": capability["resident_runtime_report_schema"].clone(),
                "resident_runtime_lifecycle_contract": capability["resident_runtime_lifecycle_contract"].clone(),
                "resident_runtime_resource_limits": capability["resident_runtime_resource_limits"].clone(),
                "resident_runtime_resource_observation_fields": capability["resident_runtime_resource_observation_fields"].clone(),
                "service_contract_report_size_bytes": output.stdout.len(),
                "rust_daed_validate_command_ready": output.status.success() && rust_daed_validate_command_ready,
                "capability": capability_for_report,
            });
            insert_control_plane_contract_success(
                &mut report,
                output.status.success(),
                control_plane_owner_contract_ready,
                control_plane_runtime_state_ready,
                routing_map_owner_ready,
                domain_routing_owner_ready,
                outbound_connectivity_owner_ready,
                runtime_overview_cache_stats_ready,
                control_plane_reload_parity_contract_ready,
                control_plane_cleanup_leftovers_gate_ready,
                matched_go_rust_default_daemon_benchmark_gate_ready,
                control_plane_typed_report_ready,
                control_plane_c_tproxy_oracle_retained_until_datapath_core,
                go_control_plane_fallback_retirement_contract_ready,
                go_control_plane_fallback_retired_candidate,
                &capability,
            );
            insert_datapath_core_contract_success(
                &mut report,
                output.status.success(),
                datapath_core_contract_ready,
                datapath_core_runtime_state_ready,
                tcp_tproxy_datapath_ready,
                tcp_route_sniff_direct_block_proxy_ready,
                udp_tproxy_datapath_ready,
                udp_endpoint_pool_ready,
                dns_tproxy_datapath_ready,
                dns_cache_route_integration_ready,
                sniff_result_contract_ready,
                route_result_contract_ready,
                direct_block_proxy_action_contract_ready,
                datapath_core_benchmark_gate_ready,
                datapath_core_typed_report_ready,
                no_go_userspace_datapath_fallback_contract_ready,
                c_tproxy_oracle_retired_after_datapath_core,
                go_datapath_core_fallback_retirement_contract_ready,
                go_datapath_core_fallback_retired_candidate,
                &capability,
            );
            insert_outbound_fingerprint_underlay_contract_success(
                &mut report,
                output.status.success(),
                &capability,
            );
            insert_outbound_production_matrix_contract_success(
                &mut report,
                output.status.success(),
                &capability,
            );
            insert_resident_live_adapter_matrix_contract_success(
                &mut report,
                output.status.success(),
                &capability,
            );
            insert_release_default_switch_contract_success(
                &mut report,
                output.status.success(),
                &capability,
            );
            insert_go_free_product_chain_contract_success(
                &mut report,
                output.status.success(),
                &capability,
            );
            report
        }
        Err(err) => {
            let mut report = json!({
            "executed": true,
            "passed": false,
            "command": command,
            "exit_code": Value::Null,
            "stdout": "",
            "stderr": err.to_string(),
            "resident_run_service_contract_ready": false,
            "reload_command_service_contract_ready": false,
            "resident_production_dataplane_ready": false,
            "resident_default_daemon_switch_ready": false,
            "resident_dataplane_default_switch_ready": false,
            "resident_dataplane_env": Value::Null,
            "resident_dataplane_env_enabled": false,
            "default_path_switch_blocker": Value::Null,
            "reload_failure_rollback_supported": false,
            "invalid_runtime_config_rejected_before_current_swap": false,
            "reload_start_failure_attempts_previous_runtime_restore": false,
            "systemd_notify_ready_supported": false,
            "resident_runtime_platform_contract_ready": false,
            "resident_runtime_typed_report_ready": false,
            "resident_runtime_resource_gate_ready": false,
            "resident_runtime_report_schema": Value::Null,
            "resident_runtime_lifecycle_contract": Value::Null,
            "resident_runtime_resource_limits": Value::Null,
            "resident_runtime_resource_observation_fields": [],
            "service_contract_report_size_bytes": 0,
            "rust_daed_validate_command_ready": false,
            });
            insert_control_plane_contract_defaults(&mut report);
            insert_datapath_core_contract_defaults(&mut report);
            insert_outbound_fingerprint_underlay_contract_defaults(&mut report);
            insert_outbound_production_matrix_contract_defaults(&mut report);
            insert_resident_live_adapter_matrix_contract_defaults(&mut report);
            insert_release_default_switch_contract_defaults(&mut report);
            insert_go_free_product_chain_contract_defaults(&mut report);
            report
        }
    }
}

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

fn insert_datapath_core_contract_defaults(report: &mut Value) {
    insert_datapath_core_contract_success(
        report,
        false, // command_passed
        false, // datapath_core_contract_ready
        false, // datapath_core_runtime_state_ready
        false, // tcp_tproxy_datapath_ready
        false, // tcp_route_sniff_direct_block_proxy_ready
        false, // udp_tproxy_datapath_ready
        false, // udp_endpoint_pool_ready
        false, // dns_tproxy_datapath_ready
        false, // dns_cache_route_integration_ready
        false, // sniff_result_contract_ready
        false, // route_result_contract_ready
        false, // direct_block_proxy_action_contract_ready
        false, // datapath_core_benchmark_gate_ready
        false, // datapath_core_typed_report_ready
        false, // no_go_userspace_datapath_fallback_contract_ready
        false, // c_tproxy_oracle_retired_after_datapath_core
        false, // go_datapath_core_fallback_retirement_contract_ready
        false, // go_datapath_core_fallback_retired_candidate
        &Value::Null,
    );
}

#[allow(clippy::too_many_arguments)]
fn insert_datapath_core_contract_success(
    report: &mut Value,
    command_passed: bool,
    datapath_core_contract_ready: bool,
    datapath_core_runtime_state_ready: bool,
    tcp_tproxy_datapath_ready: bool,
    tcp_route_sniff_direct_block_proxy_ready: bool,
    udp_tproxy_datapath_ready: bool,
    udp_endpoint_pool_ready: bool,
    dns_tproxy_datapath_ready: bool,
    dns_cache_route_integration_ready: bool,
    sniff_result_contract_ready: bool,
    route_result_contract_ready: bool,
    direct_block_proxy_action_contract_ready: bool,
    datapath_core_benchmark_gate_ready: bool,
    datapath_core_typed_report_ready: bool,
    no_go_userspace_datapath_fallback_contract_ready: bool,
    c_tproxy_oracle_retired_after_datapath_core: bool,
    go_datapath_core_fallback_retirement_contract_ready: bool,
    go_datapath_core_fallback_retired_candidate: bool,
    capability: &Value,
) {
    if let Value::Object(report) = report {
        report.insert(
            "datapath_core_contract_ready".to_owned(),
            json!(command_passed && datapath_core_contract_ready),
        );
        report.insert(
            "datapath_core_runtime_state_ready".to_owned(),
            json!(command_passed && datapath_core_runtime_state_ready),
        );
        report.insert(
            "tcp_tproxy_datapath_ready".to_owned(),
            json!(command_passed && tcp_tproxy_datapath_ready),
        );
        report.insert(
            "tcp_route_sniff_direct_block_proxy_ready".to_owned(),
            json!(command_passed && tcp_route_sniff_direct_block_proxy_ready),
        );
        report.insert(
            "udp_tproxy_datapath_ready".to_owned(),
            json!(command_passed && udp_tproxy_datapath_ready),
        );
        report.insert(
            "udp_endpoint_pool_ready".to_owned(),
            json!(command_passed && udp_endpoint_pool_ready),
        );
        report.insert(
            "dns_tproxy_datapath_ready".to_owned(),
            json!(command_passed && dns_tproxy_datapath_ready),
        );
        report.insert(
            "dns_cache_route_integration_ready".to_owned(),
            json!(command_passed && dns_cache_route_integration_ready),
        );
        report.insert(
            "sniff_result_contract_ready".to_owned(),
            json!(command_passed && sniff_result_contract_ready),
        );
        report.insert(
            "route_result_contract_ready".to_owned(),
            json!(command_passed && route_result_contract_ready),
        );
        report.insert(
            "direct_block_proxy_action_contract_ready".to_owned(),
            json!(command_passed && direct_block_proxy_action_contract_ready),
        );
        report.insert(
            "datapath_core_benchmark_gate_ready".to_owned(),
            json!(command_passed && datapath_core_benchmark_gate_ready),
        );
        report.insert(
            "datapath_core_typed_report_ready".to_owned(),
            json!(command_passed && datapath_core_typed_report_ready),
        );
        report.insert(
            "datapath_core_typed_report".to_owned(),
            capability["datapath_core_typed_report"].clone(),
        );
        report.insert(
            "datapath_core_surface".to_owned(),
            capability["datapath_core_surface"].clone(),
        );
        report.insert(
            "datapath_core_report_schema".to_owned(),
            capability["datapath_core_report_schema"].clone(),
        );
        report.insert(
            "no_go_userspace_datapath_fallback_contract_ready".to_owned(),
            json!(command_passed && no_go_userspace_datapath_fallback_contract_ready),
        );
        report.insert(
            "c_tproxy_oracle_retired_after_datapath_core".to_owned(),
            json!(command_passed && c_tproxy_oracle_retired_after_datapath_core),
        );
        report.insert(
            "go_datapath_core_fallback_retirement_contract_ready".to_owned(),
            json!(command_passed && go_datapath_core_fallback_retirement_contract_ready),
        );
        report.insert(
            "go_datapath_core_fallback_retired_candidate".to_owned(),
            json!(command_passed && go_datapath_core_fallback_retired_candidate),
        );
    }
}

const OUTBOUND_FINGERPRINT_UNDERLAY_BOOL_FIELDS: &[&str] = &[
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
    "expanded_security_underlay_complete",
    "security_underlay_release_gate_ready",
];

const OUTBOUND_FINGERPRINT_UNDERLAY_COPY_FIELDS: &[&str] = &[
    "outbound_fingerprint_underlay_report_schema",
    "outbound_fingerprint_underlay_surface",
    "outbound_fingerprint_underlay_typed_report",
    "security_underlay_capability_report_schema",
    "security_underlay_capability_row_count",
    "security_underlay_capability_rows",
    "security_underlay_capability_typed_report",
];

const OUTBOUND_PRODUCTION_MATRIX_BOOL_FIELDS: &[&str] = &[
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
    "expanded_source_matrix_complete",
    "expanded_source_matrix_blocked_rows_visible",
    "expanded_source_matrix_release_gate_ready",
    "expanded_source_matrix_c10_ready",
    "stream_wrapper_capability_contract_ready",
    "websocket_wss_loopback_ready",
    "stream_wrapper_resident_source_admission_ready",
    "expanded_stream_wrapper_complete",
];

const OUTBOUND_PRODUCTION_MATRIX_COPY_FIELDS: &[&str] = &[
    "outbound_production_matrix_report_schema",
    "outbound_production_matrix_entries",
    "outbound_production_matrix_typed_report",
    "source_shape_registry_report_schema",
    "source_shape_registry_schema_version",
    "source_shape_registry_row_count",
    "source_shape_registry_rows",
    "expanded_source_matrix_status_counts",
    "expanded_source_matrix_completion_blocker",
    "expanded_source_matrix_typed_report",
    "stream_wrapper_capability_report_schema",
    "stream_wrapper_capability_row_count",
    "stream_wrapper_capability_rows",
    "stream_wrapper_capability_typed_report",
];

const RESIDENT_LIVE_ADAPTER_MATRIX_BOOL_FIELDS: &[&str] = &[
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
];

const RESIDENT_LIVE_ADAPTER_MATRIX_COPY_FIELDS: &[&str] = &[
    "resident_live_adapter_wired_handler_count",
    "resident_live_adapter_live_ready_handler_count",
    "resident_live_adapter_matrix_report_schema",
    "resident_live_adapter_matrix_entries",
    "resident_live_adapter_matrix_typed_report",
    "resident_live_adapter_matrix_surface",
];

const RELEASE_DEFAULT_SWITCH_BOOL_FIELDS: &[&str] = &[
    "release_default_switch_contract_ready",
    "release_default_artifact_path_ready",
    "default_runtime_selector_no_env_rust_owned_ready",
    "install_service_package_scripts_ready",
    "release_default_switch_live_evidence_contract_ready",
    "backup_manifest_contract_ready",
    "rollback_rehearsal_contract_ready",
    "host_write_freeze_contract_required",
    "go_product_shell_allowed_until_go_free",
    "release_default_switch_final_go_free_claim",
    "release_default_switch_typed_report_ready",
];

const RELEASE_DEFAULT_SWITCH_COPY_FIELDS: &[&str] = &[
    "release_default_switch_report_schema",
    "release_default_switch_required_live_hosts",
    "release_default_switch_surface",
    "release_default_switch_typed_report",
];

const GO_FREE_PRODUCT_CHAIN_BOOL_FIELDS: &[&str] = &[
    "go_free_product_chain_contract_ready",
    "default_product_package_go_free",
    "go_product_shell_retired_from_default_package",
    "go_orchestration_retired_from_default_package",
    "go_control_runtime_api_service_release_retired_from_default_package",
    "go_outbound_dependency_retired_from_default_package",
    "go_compat_oracle_boundary_ready",
    "rust_product_binary_contract_ready",
    "rust_product_lifecycle_contract_ready",
    "rust_product_web_api_package_release_contract_ready",
    "go_free_live_host_contract_ready",
    "go_free_rollback_model_ready",
    "go_free_product_chain_typed_report_ready",
    "go_free_product_chain_ready",
];

const GO_FREE_PRODUCT_CHAIN_COPY_FIELDS: &[&str] = &[
    "go_free_product_chain_report_schema",
    "go_free_product_chain_default_dependency_policy",
    "go_free_product_chain_retained_go_scope",
    "go_free_product_chain_surface",
    "go_free_product_chain_typed_report",
];

fn insert_outbound_fingerprint_underlay_contract_defaults(report: &mut Value) {
    insert_contract_bool_fields(
        report,
        false,
        &Value::Null,
        OUTBOUND_FINGERPRINT_UNDERLAY_BOOL_FIELDS,
    );
    insert_contract_copy_fields(
        report,
        &Value::Null,
        OUTBOUND_FINGERPRINT_UNDERLAY_COPY_FIELDS,
    );
}

fn insert_outbound_fingerprint_underlay_contract_success(
    report: &mut Value,
    command_passed: bool,
    capability: &Value,
) {
    insert_contract_bool_fields(
        report,
        command_passed,
        capability,
        OUTBOUND_FINGERPRINT_UNDERLAY_BOOL_FIELDS,
    );
    insert_contract_copy_fields(
        report,
        capability,
        OUTBOUND_FINGERPRINT_UNDERLAY_COPY_FIELDS,
    );
}

fn insert_outbound_production_matrix_contract_defaults(report: &mut Value) {
    insert_contract_bool_fields(
        report,
        false,
        &Value::Null,
        OUTBOUND_PRODUCTION_MATRIX_BOOL_FIELDS,
    );
    insert_contract_copy_fields(report, &Value::Null, OUTBOUND_PRODUCTION_MATRIX_COPY_FIELDS);
}

fn insert_outbound_production_matrix_contract_success(
    report: &mut Value,
    command_passed: bool,
    capability: &Value,
) {
    insert_contract_bool_fields(
        report,
        command_passed,
        capability,
        OUTBOUND_PRODUCTION_MATRIX_BOOL_FIELDS,
    );
    insert_contract_copy_fields(report, capability, OUTBOUND_PRODUCTION_MATRIX_COPY_FIELDS);
}

fn insert_resident_live_adapter_matrix_contract_defaults(report: &mut Value) {
    insert_contract_bool_fields(
        report,
        false,
        &Value::Null,
        RESIDENT_LIVE_ADAPTER_MATRIX_BOOL_FIELDS,
    );
    insert_contract_copy_fields(
        report,
        &Value::Null,
        RESIDENT_LIVE_ADAPTER_MATRIX_COPY_FIELDS,
    );
}

fn insert_resident_live_adapter_matrix_contract_success(
    report: &mut Value,
    command_passed: bool,
    capability: &Value,
) {
    insert_contract_bool_fields(
        report,
        command_passed,
        capability,
        RESIDENT_LIVE_ADAPTER_MATRIX_BOOL_FIELDS,
    );
    insert_contract_copy_fields(report, capability, RESIDENT_LIVE_ADAPTER_MATRIX_COPY_FIELDS);
}

fn insert_release_default_switch_contract_defaults(report: &mut Value) {
    insert_contract_bool_fields(
        report,
        false,
        &Value::Null,
        RELEASE_DEFAULT_SWITCH_BOOL_FIELDS,
    );
    insert_contract_copy_fields(report, &Value::Null, RELEASE_DEFAULT_SWITCH_COPY_FIELDS);
}

fn insert_release_default_switch_contract_success(
    report: &mut Value,
    command_passed: bool,
    capability: &Value,
) {
    insert_contract_bool_fields(
        report,
        command_passed,
        capability,
        RELEASE_DEFAULT_SWITCH_BOOL_FIELDS,
    );
    insert_contract_copy_fields(report, capability, RELEASE_DEFAULT_SWITCH_COPY_FIELDS);
}

fn insert_go_free_product_chain_contract_defaults(report: &mut Value) {
    insert_contract_bool_fields(
        report,
        false,
        &Value::Null,
        GO_FREE_PRODUCT_CHAIN_BOOL_FIELDS,
    );
    insert_contract_copy_fields(report, &Value::Null, GO_FREE_PRODUCT_CHAIN_COPY_FIELDS);
}

fn insert_go_free_product_chain_contract_success(
    report: &mut Value,
    command_passed: bool,
    capability: &Value,
) {
    insert_contract_bool_fields(
        report,
        command_passed,
        capability,
        GO_FREE_PRODUCT_CHAIN_BOOL_FIELDS,
    );
    insert_contract_copy_fields(report, capability, GO_FREE_PRODUCT_CHAIN_COPY_FIELDS);
}

fn insert_contract_bool_fields(
    report: &mut Value,
    command_passed: bool,
    capability: &Value,
    fields: &[&str],
) {
    if let Value::Object(report) = report {
        for field in fields {
            report.insert(
                (*field).to_owned(),
                json!(command_passed && capability[*field].as_bool().unwrap_or(false)),
            );
        }
    }
}

fn insert_contract_copy_fields(report: &mut Value, capability: &Value, fields: &[&str]) {
    if let Value::Object(report) = report {
        for field in fields {
            report.insert((*field).to_owned(), capability[*field].clone());
        }
    }
}

fn run_candidate_command(
    binary_source: &Path,
    args: &[&str],
    path_arg: Option<&Path>,
) -> io::Result<Output> {
    const MAX_ATTEMPTS: usize = 20;
    for attempt in 0..MAX_ATTEMPTS {
        let mut command = Command::new(binary_source);
        command.args(args);
        if let Some(path_arg) = path_arg {
            command.arg(path_arg);
        }
        match command.output() {
            Err(err) if err.raw_os_error() == Some(libc::ETXTBSY) && attempt + 1 < MAX_ATTEMPTS => {
                thread::sleep(Duration::from_millis(10));
            }
            result => return result,
        }
    }
    unreachable!("candidate command retry loop always returns")
}

fn bounded_command_output(bytes: &[u8]) -> String {
    const MAX_OUTPUT_BYTES: usize = 4000;
    String::from_utf8_lossy(&bytes[..bytes.len().min(MAX_OUTPUT_BYTES)]).into_owned()
}
