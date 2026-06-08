use super::*;
pub(crate) fn candidate_service_contract_report(
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
