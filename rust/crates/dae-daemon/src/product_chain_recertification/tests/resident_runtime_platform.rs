use super::*;

#[test]
fn resident_runtime_platform_gate_accepts_complete_candidate_contract() {
    let root = std::env::temp_dir().join(format!(
        "dae-daemon-product-chain-c4-ready-{}",
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
        ProductChainAdmissionEvidence::default(),
        None,
    );

    let gate = &report["resident_runtime_platform_gate"];
    assert_eq!(gate["status"].as_str().unwrap(), "pass");
    assert!(report["resident_runtime_platform_ready"].as_bool().unwrap());
    assert!(
        report["c4_resident_runtime_platform"]["resident_runtime_platform_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(
        gate["resident_runtime_resource_gate"]["memory_thread_fd_limits_declared"]
            .as_bool()
            .unwrap()
    );
    assert!(
        gate["resident_runtime_resource_gate"]["report_size_gate_passed"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["typed_report"]["resident_runtime_platform_ready"]
            .as_bool()
            .unwrap()
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn resident_runtime_platform_gate_blocks_missing_resource_contract() {
    let root = std::env::temp_dir().join(format!(
        "dae-daemon-product-chain-c4-resource-block-{}",
        std::process::id()
    ));
    let artifact_dir = root.join("artifact");
    let manifest_file = artifact_dir.join("product-chain-recertification.json");
    let binary = root.join("resident-candidate-missing-resource");
    write_candidate_service_contract_without_resource_gate(&binary);
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
        ProductChainAdmissionEvidence::default(),
        None,
    );

    let gate = &report["resident_runtime_platform_gate"];
    assert_eq!(gate["status"].as_str().unwrap(), "blocked");
    assert!(!report["resident_runtime_platform_ready"].as_bool().unwrap());
    assert!(gate["blockers"].as_array().unwrap().iter().any(|blocker| {
        blocker
            .as_str()
            .unwrap()
            .contains("memory/thread/fd/report-size resource gate")
    }));
    assert!(
        report["remaining_blockers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|blocker| blocker
                .as_str()
                .unwrap()
                .contains("memory/thread/fd/report-size resource gate"))
    );
    let _ = std::fs::remove_dir_all(root);
}

fn write_candidate_service_contract_without_resource_gate(path: &Path) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(
        path,
        "#!/bin/sh\n\
         if [ \"$1\" = \"service-contract\" ]; then\n\
           printf '%s\\n' '{\"resident_run_service_contract_ready\":true,\"reload_command_service_contract_ready\":true,\"systemd_notify_ready_supported\":true,\"reload_failure_rollback_supported\":true,\"invalid_runtime_config_rejected_before_current_swap\":true,\"reload_start_failure_attempts_previous_runtime_restore\":true,\"resident_production_dataplane_ready\":true,\"resident_default_daemon_switch_ready\":true,\"resident_runtime_platform_contract_ready\":true,\"resident_runtime_typed_report_ready\":true}'\n\
           exit 0\n\
         fi\n\
         exit 2\n",
    )
    .unwrap();
    #[cfg(unix)]
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}
