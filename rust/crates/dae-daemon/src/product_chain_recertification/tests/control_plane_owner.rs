use super::*;

#[test]
fn control_plane_owner_gate_accepts_complete_candidate_contract() {
    let root = std::env::temp_dir().join(format!(
        "dae-daemon-product-chain-c5-ready-{}",
        std::process::id()
    ));
    let artifact_dir = root.join("artifact");
    let manifest_file = artifact_dir.join("product-chain-recertification.json");
    let options = resident_ready_product_chain_options(
        &root,
        ProductChainRecertificationOptions {
            execute: true,
            default_path_mutation_requested: true,
            ..ProductChainRecertificationOptions::default()
        },
    );
    let report = report_value(
        &options,
        &artifact_dir,
        &manifest_file,
        ProductChainAdmissionEvidence {
            reload_runtime_parity_admitted: true,
            matched_benchmark_recorded: true,
            ..ProductChainAdmissionEvidence::default()
        },
        None,
    );

    let gate = &report["control_plane_owner_gate"];
    assert_eq!(gate["status"].as_str().unwrap(), "pass");
    assert!(report["control_plane_owner_ready"].as_bool().unwrap());
    assert!(
        report["go_control_plane_fallback_retired_candidate"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["control_plane_owner_default_switch_admission_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(gate["routing_map_owner_ready"].as_bool().unwrap());
    assert!(gate["domain_routing_owner_ready"].as_bool().unwrap());
    assert!(gate["outbound_connectivity_owner_ready"].as_bool().unwrap());
    assert!(
        gate["runtime_overview_cache_stats_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(
        gate["control_plane_cleanup_leftovers_gate_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["c5_control_plane_owner"]["control_plane_owner_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["typed_report"]["control_plane_owner_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["typed_report"]["go_control_plane_fallback_retired_candidate"]
            .as_bool()
            .unwrap()
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn control_plane_owner_gate_blocks_missing_domain_owner_contract() {
    let root = std::env::temp_dir().join(format!(
        "dae-daemon-product-chain-c5-domain-block-{}",
        std::process::id()
    ));
    let artifact_dir = root.join("artifact");
    let manifest_file = artifact_dir.join("product-chain-recertification.json");
    let binary = root.join("resident-candidate-missing-domain-owner");
    write_candidate_service_contract_without_domain_owner(&binary);
    let options = ProductChainRecertificationOptions {
        execute: true,
        default_path_mutation_requested: true,
        resident_default_daemon_binary_source: Some(binary),
        ..ProductChainRecertificationOptions::default()
    };
    let report = report_value(
        &options,
        &artifact_dir,
        &manifest_file,
        ProductChainAdmissionEvidence {
            reload_runtime_parity_admitted: true,
            matched_benchmark_recorded: true,
            ..ProductChainAdmissionEvidence::default()
        },
        None,
    );

    let gate = &report["control_plane_owner_gate"];
    assert_eq!(gate["status"].as_str().unwrap(), "blocked");
    assert!(!report["control_plane_owner_ready"].as_bool().unwrap());
    assert!(
        !report["go_control_plane_fallback_retired_candidate"]
            .as_bool()
            .unwrap()
    );
    assert!(gate["blockers"].as_array().unwrap().iter().any(|blocker| {
        blocker
            .as_str()
            .unwrap()
            .contains("domain routing owner is not ready")
    }));
    assert!(
        report["remaining_blockers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|blocker| blocker
                .as_str()
                .unwrap()
                .contains("domain routing owner is not ready"))
    );
    let _ = std::fs::remove_dir_all(root);
}

fn write_candidate_service_contract_without_domain_owner(path: &Path) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(
        path,
        "#!/bin/sh\n\
         if [ \"$1\" = \"service-contract\" ]; then\n\
           printf '%s\\n' '{\"resident_run_service_contract_ready\":true,\"reload_command_service_contract_ready\":true,\"systemd_notify_ready_supported\":true,\"reload_failure_rollback_supported\":true,\"invalid_runtime_config_rejected_before_current_swap\":true,\"reload_start_failure_attempts_previous_runtime_restore\":true,\"resident_production_dataplane_ready\":true,\"resident_default_daemon_switch_ready\":true,\"resident_runtime_platform_contract_ready\":true,\"resident_runtime_typed_report_ready\":true,\"resident_runtime_resource_gate_ready\":true,\"resident_runtime_report_schema\":\"resident-runtime-platform-report\",\"resident_runtime_lifecycle_contract\":{\"pid_file\":\"/var/run/dae.pid\",\"progress_file\":\"/var/run/dae.progress\",\"abort_file\":\"/var/run/dae.abort\",\"ready_record_file_supported\":true,\"cleanup_report\":\"resident-production-runtime-cleanup.json\",\"start_report\":\"resident-production-runtime-start.json\"},\"resident_runtime_resource_limits\":{\"max_rss_bytes\":536870912,\"max_thread_count\":256,\"max_fd_count\":1024,\"max_report_size_bytes\":524288},\"control_plane_owner_contract_ready\":true,\"control_plane_runtime_state_ready\":true,\"routing_map_owner_ready\":true,\"domain_routing_owner_ready\":false,\"outbound_connectivity_owner_ready\":true,\"runtime_overview_cache_stats_ready\":true,\"control_plane_reload_parity_contract_ready\":true,\"control_plane_cleanup_leftovers_gate_ready\":true,\"matched_go_rust_default_daemon_benchmark_gate_ready\":true,\"control_plane_typed_report_ready\":true,\"control_plane_c_tproxy_oracle_retained_until_datapath_core\":true,\"go_control_plane_fallback_retirement_contract_ready\":true,\"go_control_plane_fallback_retired_candidate\":true}'\n\
           exit 0\n\
         fi\n\
         exit 2\n",
    )
    .unwrap();
    #[cfg(unix)]
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}
