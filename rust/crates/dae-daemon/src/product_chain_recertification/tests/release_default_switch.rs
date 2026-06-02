use super::*;

#[test]
fn release_default_switch_gate_passes_with_complete_freeze_and_rehearsal_evidence() {
    let mut candidate_service_contract = candidate_service_contract_value(true);
    candidate_service_contract["executed"] = json!(true);
    candidate_service_contract["passed"] = json!(true);
    let resident_gate = json!({
        "candidate_service_contract": candidate_service_contract,
        "binary_source": "/tmp/resident-ready-candidate",
    });
    let outbound_gate = json!({
        "outbound_production_matrix_ready": true,
    });
    let plan = json!({
        "requested": true,
        "admitted": true,
        "actual_mutation_executed": false,
        "production_run_command_replaced": false,
        "backup_manifest_materialized": true,
        "rollback_script_materialized": true,
        "apply_manifest_materialized": true,
        "service_diff_materialized": true,
    });
    let readiness = json!({
        "ready_for_manual_authorization": true,
    });
    let rehearsal = json!({
        "pass": true,
    });
    let freeze = json!({
        "pass": true,
    });
    let gate = release_default_switch::release_default_switch_gate_json(
        true,
        &ProductChainRecertificationOptions {
            default_path_mutation_requested: true,
            production_run_command_replacement_dry_run_requested: true,
            ..ProductChainRecertificationOptions::default()
        },
        true,
        true,
        &outbound_gate,
        &resident_gate,
        &plan,
        Some(&readiness),
        Some(&rehearsal),
        Some(&freeze),
    )
    .report;

    assert_eq!(gate["status"].as_str().unwrap(), "pass");
    assert!(
        gate["release_default_switch_admission_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(gate["release_default_switch_ready"].as_bool().unwrap());
    assert!(gate["host_write_freeze_passed"].as_bool().unwrap());
    assert!(gate["rollback_rehearsal_passed"].as_bool().unwrap());
    assert!(gate["blockers"].as_array().unwrap().is_empty());
}

#[test]
fn release_default_switch_report_value_records_admission_before_materialized_host_freeze() {
    let root = std::env::temp_dir().join(format!(
        "dae-daemon-product-chain-c9-admission-{}",
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

    assert!(
        report["release_default_switch_admission_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(!report["release_default_switch_ready"].as_bool().unwrap());
    assert_eq!(
        report["release_default_switch_gate"]["status"]
            .as_str()
            .unwrap(),
        "admission-pass-pending-host-freeze"
    );
    assert!(
        report["c9_release_default_switch"]["blockers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|blocker| blocker
                .as_str()
                .unwrap()
                .contains("host-write freeze is not pass"))
    );
    let _ = std::fs::remove_dir_all(root);
}
