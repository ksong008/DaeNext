use super::*;

#[test]
fn product_chain_run_command_replacement_plan_is_read_only_and_admitted_after_default_request() {
    let root = std::env::temp_dir().join(format!(
        "dae-daemon-product-chain-run-command-plan-{}",
        std::process::id()
    ));
    let artifact_dir = root.join("artifact");
    let manifest_file = artifact_dir.join("product-chain-recertification.json");
    let options = resident_ready_product_chain_options(
        &root,
        ProductChainRecertificationOptions {
            execute: true,
            default_path_mutation_requested: true,
            production_run_command_replacement_dry_run_requested: true,
            ..ProductChainRecertificationOptions::default()
        },
    );
    let report = report_value(
        &options,
        &artifact_dir,
        &manifest_file,
        ProductChainAdmissionEvidence {
            true_rust_default_daemon_admitted: true,
            production_dataplane_admitted: true,
            reload_runtime_parity_admitted: true,
            matched_benchmark_recorded: true,
            bpf_go_fallback_retired: true,
        },
        Some(clean_product_chain_evidence()),
    );
    let plan = &report["production_run_command_replacement_plan"];
    assert!(plan["requested"].as_bool().unwrap());
    assert!(plan["dry_run"].as_bool().unwrap());
    assert!(plan["admitted"].as_bool().unwrap());
    assert!(!plan["go_fallback_required"].as_bool().unwrap());
    assert!(plan["go_fallback_retired"].as_bool().unwrap());
    assert!(plan["backup_required"].as_bool().unwrap());
    assert!(plan["rollback_required"].as_bool().unwrap());
    assert!(plan["post_replacement_smoke_required"].as_bool().unwrap());
    assert!(!plan["host_mutation_allow_requested"].as_bool().unwrap());
    assert!(!plan["host_mutation_allowed"].as_bool().unwrap());
    assert_eq!(
        plan["requires_explicit_execute_flag"].as_str().unwrap(),
        "--execute-production-run-command-replacement"
    );
    assert_eq!(
        plan["requires_explicit_host_mutation_allow_flag"]
            .as_str()
            .unwrap(),
        "--allow-host-default-path-mutation"
    );
    assert!(
        plan["backup_artifact_dir"]
            .as_str()
            .unwrap()
            .contains("production-run-command-replacement-backup")
    );
    assert!(
        plan["rollback_script"]
            .as_str()
            .unwrap()
            .contains("rollback-production-run-command-replacement.sh")
    );
    assert!(!plan["rollback_commands"].as_array().unwrap().is_empty());
    assert!(
        !plan["post_replacement_smoke_commands"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(
        !plan["service_manager_commands"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(
        !plan["pre_execution_checks"]["host_mutation_allowed"]
            .as_bool()
            .unwrap()
    );
    assert!(!plan["actual_mutation_executed"].as_bool().unwrap());
    assert!(!plan["production_run_command_replaced"].as_bool().unwrap());
    assert!(plan["read_only"].as_bool().unwrap());
    assert!(!report["production_run_command_replaced"].as_bool().unwrap());
    assert!(report["read_only"].as_bool().unwrap());
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn product_chain_run_command_replacement_execute_request_is_blocked_without_host_mutation() {
    let root = std::env::temp_dir().join(format!(
        "dae-daemon-product-chain-run-command-execute-{}",
        std::process::id()
    ));
    let artifact_dir = root.join("artifact");
    let manifest_file = artifact_dir.join("product-chain-recertification.json");
    let options = resident_ready_product_chain_options(
        &root,
        ProductChainRecertificationOptions {
            execute: true,
            default_path_mutation_requested: true,
            production_run_command_replacement_dry_run_requested: true,
            production_run_command_replacement_execute_requested: true,
            ..ProductChainRecertificationOptions::default()
        },
    );
    let report = report_value(
        &options,
        &artifact_dir,
        &manifest_file,
        ProductChainAdmissionEvidence {
            true_rust_default_daemon_admitted: true,
            production_dataplane_admitted: true,
            reload_runtime_parity_admitted: true,
            matched_benchmark_recorded: true,
            bpf_go_fallback_retired: true,
        },
        Some(clean_product_chain_evidence()),
    );
    let plan = &report["production_run_command_replacement_plan"];
    assert!(plan["execute_requested"].as_bool().unwrap());
    assert!(!plan["execute_allowed"].as_bool().unwrap());
    assert!(!plan["host_mutation_allow_requested"].as_bool().unwrap());
    assert!(!plan["host_mutation_allowed"].as_bool().unwrap());
    assert!(!plan["actual_mutation_executed"].as_bool().unwrap());
    assert!(!plan["production_run_command_replaced"].as_bool().unwrap());
    assert!(
        plan["execution_blockers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|blocker| blocker
                .as_str()
                .unwrap()
                .contains("host default path mutation is not allowed"))
    );
    assert!(
        report["remaining_blockers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|blocker| blocker
                .as_str()
                .unwrap()
                .contains("host default path mutation is not allowed"))
    );
    assert!(!report["production_run_command_replaced"].as_bool().unwrap());
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn product_chain_run_command_replacement_host_mutation_allow_gate_admits_without_writing_host() {
    let root = std::env::temp_dir().join(format!(
        "dae-daemon-product-chain-run-command-host-allow-{}",
        std::process::id()
    ));
    let artifact_dir = root.join("artifact");
    let manifest_file = artifact_dir.join("product-chain-recertification.json");
    let options = resident_ready_product_chain_options(
        &root,
        ProductChainRecertificationOptions {
            execute: true,
            default_path_mutation_requested: true,
            production_run_command_replacement_dry_run_requested: true,
            production_run_command_replacement_execute_requested: true,
            host_default_path_mutation_allow_requested: true,
            ..ProductChainRecertificationOptions::default()
        },
    );
    let report = report_value(
        &options,
        &artifact_dir,
        &manifest_file,
        ProductChainAdmissionEvidence {
            true_rust_default_daemon_admitted: true,
            production_dataplane_admitted: true,
            reload_runtime_parity_admitted: true,
            matched_benchmark_recorded: true,
            bpf_go_fallback_retired: true,
        },
        Some(clean_product_chain_evidence()),
    );
    let plan = &report["production_run_command_replacement_plan"];
    assert!(plan["admitted"].as_bool().unwrap());
    assert!(plan["execute_requested"].as_bool().unwrap());
    assert!(plan["execute_allowed"].as_bool().unwrap());
    assert!(!plan["go_fallback_required"].as_bool().unwrap());
    assert!(plan["go_fallback_retired"].as_bool().unwrap());
    assert!(plan["host_mutation_allow_requested"].as_bool().unwrap());
    assert!(plan["host_mutation_allowed"].as_bool().unwrap());
    assert_eq!(
        plan["host_mutation_execution_mode"].as_str().unwrap(),
        "read-only-admission-only"
    );
    assert!(plan["execution_blockers"].as_array().unwrap().is_empty());
    assert!(report["remaining_blockers"].as_array().unwrap().is_empty());
    assert!(!plan["actual_mutation_executed"].as_bool().unwrap());
    assert!(!plan["production_run_command_replaced"].as_bool().unwrap());
    assert!(!report["production_run_command_replaced"].as_bool().unwrap());
    assert!(plan["read_only"].as_bool().unwrap());
    assert!(report["read_only"].as_bool().unwrap());
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn product_chain_run_command_replacement_apply_plan_is_dry_run_only() {
    let root = std::env::temp_dir().join(format!(
        "dae-daemon-product-chain-run-command-apply-plan-{}",
        std::process::id()
    ));
    let artifact_dir = root.join("artifact");
    let manifest_file = artifact_dir.join("product-chain-recertification.json");
    let options = resident_ready_product_chain_options(
        &root,
        ProductChainRecertificationOptions {
            execute: true,
            default_path_mutation_requested: true,
            production_run_command_replacement_dry_run_requested: true,
            production_run_command_replacement_execute_requested: true,
            production_run_command_replacement_apply_plan_requested: true,
            host_default_path_mutation_allow_requested: true,
            ..ProductChainRecertificationOptions::default()
        },
    );
    let report = report_value(
        &options,
        &artifact_dir,
        &manifest_file,
        ProductChainAdmissionEvidence {
            true_rust_default_daemon_admitted: true,
            production_dataplane_admitted: true,
            reload_runtime_parity_admitted: true,
            matched_benchmark_recorded: true,
            bpf_go_fallback_retired: true,
        },
        Some(clean_product_chain_evidence()),
    );
    let plan = &report["production_run_command_replacement_plan"];
    let apply_plan = &plan["apply_plan"];
    assert!(plan["admitted"].as_bool().unwrap());
    assert!(plan["execute_allowed"].as_bool().unwrap());
    assert!(plan["apply_plan_requested"].as_bool().unwrap());
    assert!(apply_plan["requested"].as_bool().unwrap());
    assert!(apply_plan["admitted"].as_bool().unwrap());
    assert_eq!(
        apply_plan["execution_mode"].as_str().unwrap(),
        "read-only-apply-plan"
    );
    assert!(!apply_plan["host_write_allowed"].as_bool().unwrap());
    assert!(!apply_plan["actual_host_write_executed"].as_bool().unwrap());
    assert!(
        !apply_plan["production_run_command_replaced"]
            .as_bool()
            .unwrap()
    );
    assert!(apply_plan["read_only"].as_bool().unwrap());
    assert!(
        apply_plan["execution_blockers"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(report["remaining_blockers"].as_array().unwrap().is_empty());
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn product_chain_run_command_replacement_materializes_read_only_artifacts() {
    let root = std::env::temp_dir().join(format!(
        "dae-daemon-product-chain-run-command-artifacts-{}",
        std::process::id()
    ));
    let artifact_dir = root.join("artifact");
    let service_file = root.join("dae.service");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(
        &service_file,
        "ExecStart=/usr/bin/dae run --disable-timestamp -c /etc/dae/config.dae\n",
    )
    .unwrap();
    let options = ProductChainRecertificationOptions {
        service_file: service_file.clone(),
        ..ProductChainRecertificationOptions::default()
    };
    let report = json!({
        "production_run_command_replacement_plan": {
            "requested": true
        }
    });
    let artifacts =
        materialize_production_run_command_replacement_artifacts(&options, &report, &artifact_dir)
            .unwrap();
    assert_eq!(artifacts["status"].as_str().unwrap(), "pass");
    assert!(artifacts["executed"].as_bool().unwrap());
    assert!(artifacts["backup_manifest_materialized"].as_bool().unwrap());
    assert!(artifacts["rollback_script_materialized"].as_bool().unwrap());
    assert!(!artifacts["backup_copy_executed"].as_bool().unwrap());
    assert!(
        !artifacts["actual_host_mutation_executed"]
            .as_bool()
            .unwrap()
    );

    let backup_manifest_file = artifact_dir
        .join("production-run-command-replacement-backup")
        .join("backup-manifest.json");
    let rollback_script = artifact_dir.join("rollback-production-run-command-replacement.sh");
    assert!(backup_manifest_file.exists());
    assert!(rollback_script.exists());
    let backup_manifest: Value =
        serde_json::from_slice(&std::fs::read(&backup_manifest_file).unwrap()).unwrap();
    assert_eq!(
        backup_manifest["service_file"].as_str().unwrap(),
        path_string(&service_file)
    );
    assert!(!backup_manifest["backup_copy_executed"].as_bool().unwrap());
    assert!(
        !backup_manifest["actual_host_mutation_executed"]
            .as_bool()
            .unwrap()
    );
    let rollback_text = std::fs::read_to_string(&rollback_script).unwrap();
    assert!(rollback_text.contains("DAE_PRODUCTION_ROLLBACK_EXECUTE=1"));
    assert!(rollback_text.contains("read-only admission mode"));
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn product_chain_run_command_replacement_materializes_apply_plan_artifacts() {
    let root = std::env::temp_dir().join(format!(
        "dae-daemon-product-chain-run-command-apply-artifacts-{}",
        std::process::id()
    ));
    let artifact_dir = root.join("artifact");
    let service_file = root.join("dae.service");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(
        &service_file,
        "ExecStart=/usr/bin/dae run --disable-timestamp -c /etc/dae/config.dae\n",
    )
    .unwrap();
    let options = ProductChainRecertificationOptions {
        service_file: service_file.clone(),
        ..ProductChainRecertificationOptions::default()
    };
    let report = json!({
        "production_run_command_replacement_plan": {
            "requested": true,
            "apply_plan": {
                "requested": true,
                "admitted": true,
                "execution_blockers": []
            }
        }
    });
    let artifacts =
        materialize_production_run_command_replacement_artifacts(&options, &report, &artifact_dir)
            .unwrap();
    assert!(artifacts["apply_manifest_materialized"].as_bool().unwrap());
    assert!(artifacts["service_diff_materialized"].as_bool().unwrap());
    assert!(
        !artifacts["apply_plan_artifacts"]["host_write_allowed"]
            .as_bool()
            .unwrap()
    );

    let apply_manifest_file = artifact_dir.join("production-run-command-replacement-apply.json");
    let service_diff_file = artifact_dir.join("production-run-command-replacement-service.diff");
    assert!(apply_manifest_file.exists());
    assert!(service_diff_file.exists());
    let apply_manifest: Value =
        serde_json::from_slice(&std::fs::read(&apply_manifest_file).unwrap()).unwrap();
    assert!(apply_manifest["admitted"].as_bool().unwrap());
    assert!(!apply_manifest["host_write_allowed"].as_bool().unwrap());
    assert!(
        !apply_manifest["actual_host_write_executed"]
            .as_bool()
            .unwrap()
    );
    let service_diff = std::fs::read_to_string(&service_diff_file).unwrap();
    assert!(service_diff.contains("-ExecStart=/usr/bin/dae run"));
    assert!(service_diff.contains("+ExecStart=dae-daemon-optin run"));
    let _ = std::fs::remove_dir_all(root);
}
