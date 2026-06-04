use super::*;

#[test]
fn outbound_production_matrix_gate_accepts_complete_candidate_contract() {
    let root = std::env::temp_dir().join(format!(
        "dae-daemon-product-chain-c8-ready-{}",
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
            production_dataplane_admitted: true,
            reload_runtime_parity_admitted: true,
            matched_benchmark_recorded: true,
            ..ProductChainAdmissionEvidence::default()
        },
        None,
    );

    let gate = &report["outbound_production_matrix_gate"];
    assert_eq!(gate["status"].as_str().unwrap(), "pass");
    assert!(
        report["outbound_production_matrix_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["go_outbound_fallback_retired_candidate"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["outbound_production_matrix_default_switch_admission_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(
        gate["parser_export_metadata_matrix_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(gate["tcp_udp_dataplane_matrix_ready"].as_bool().unwrap());
    assert!(gate["transport_underlay_matrix_ready"].as_bool().unwrap());
    assert!(gate["live_smoke_matrix_ready"].as_bool().unwrap());
    assert!(
        report["c8_outbound_production_matrix"]["outbound_production_matrix_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["typed_report"]["outbound_production_matrix_ready"]
            .as_bool()
            .unwrap()
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn outbound_production_matrix_gate_blocks_missing_live_smoke_matrix() {
    let root = std::env::temp_dir().join(format!(
        "dae-daemon-product-chain-c8-live-block-{}",
        std::process::id()
    ));
    let artifact_dir = root.join("artifact");
    let manifest_file = artifact_dir.join("product-chain-recertification.json");
    let binary = root.join("resident-candidate-missing-live-matrix");
    let mut service_contract = candidate_service_contract_value(true);
    service_contract["live_smoke_matrix_ready"] = json!(false);
    write_candidate_service_contract_value(&binary, &service_contract);
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
            production_dataplane_admitted: true,
            reload_runtime_parity_admitted: true,
            matched_benchmark_recorded: true,
            ..ProductChainAdmissionEvidence::default()
        },
        None,
    );

    let gate = &report["outbound_production_matrix_gate"];
    assert_eq!(gate["status"].as_str().unwrap(), "blocked");
    assert!(
        !report["outbound_production_matrix_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(gate["blockers"].as_array().unwrap().iter().any(|blocker| {
        blocker
            .as_str()
            .unwrap()
            .contains("live smoke matrix is not ready")
    }));
    assert!(
        report["remaining_blockers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|blocker| blocker
                .as_str()
                .unwrap()
                .contains("live smoke matrix is not ready"))
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn outbound_production_matrix_gate_blocks_missing_resident_live_adapter_matrix() {
    let root = std::env::temp_dir().join(format!(
        "dae-daemon-product-chain-c8-live-adapter-block-{}",
        std::process::id()
    ));
    let artifact_dir = root.join("artifact");
    let manifest_file = artifact_dir.join("product-chain-recertification.json");
    let binary = root.join("resident-candidate-missing-live-adapter-matrix");
    let mut service_contract = candidate_service_contract_value(true);
    service_contract["resident_live_adapter_matrix_ready"] = json!(false);
    service_contract["resident_live_adapter_matrix_runtime_state_ready"] = json!(false);
    service_contract["resident_live_adapter_wired_matrix_ready"] = json!(false);
    service_contract["resident_live_adapter_remote_live_matrix_ready"] = json!(false);
    write_candidate_service_contract_value(&binary, &service_contract);
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
            production_dataplane_admitted: true,
            reload_runtime_parity_admitted: true,
            matched_benchmark_recorded: true,
            ..ProductChainAdmissionEvidence::default()
        },
        None,
    );

    let gate = &report["outbound_production_matrix_gate"];
    assert_eq!(gate["status"].as_str().unwrap(), "blocked");
    assert!(
        !gate["resident_live_adapter_matrix_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(gate["blockers"].as_array().unwrap().iter().any(|blocker| {
        blocker
            .as_str()
            .unwrap()
            .contains("resident live adapter matrix is not ready")
    }));
    assert!(
        report["remaining_blockers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|blocker| blocker
                .as_str()
                .unwrap()
                .contains("resident live adapter matrix is not ready"))
    );
    let _ = std::fs::remove_dir_all(root);
}
