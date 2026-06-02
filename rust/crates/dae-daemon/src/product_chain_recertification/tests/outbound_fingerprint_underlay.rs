use super::*;

#[test]
fn outbound_fingerprint_underlay_gate_accepts_complete_candidate_contract() {
    let root = std::env::temp_dir().join(format!(
        "dae-daemon-product-chain-c7-ready-{}",
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

    let gate = &report["outbound_fingerprint_underlay_gate"];
    assert_eq!(gate["status"].as_str().unwrap(), "pass");
    assert!(
        report["outbound_fingerprint_underlay_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["go_fingerprint_underlay_fallback_retired_candidate"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["outbound_fingerprint_underlay_default_switch_admission_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(
        gate["unknown_fingerprint_fail_closed_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(
        gate["no_silent_fingerprint_rustls_fallback_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(
        gate["full_utls_parity_not_declared_without_wire_oracle"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["c7_outbound_fingerprint_underlay"]["outbound_fingerprint_underlay_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["typed_report"]["outbound_fingerprint_underlay_ready"]
            .as_bool()
            .unwrap()
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn outbound_fingerprint_underlay_gate_blocks_silent_rustls_fallback() {
    let root = std::env::temp_dir().join(format!(
        "dae-daemon-product-chain-c7-fallback-block-{}",
        std::process::id()
    ));
    let artifact_dir = root.join("artifact");
    let manifest_file = artifact_dir.join("product-chain-recertification.json");
    let binary = root.join("resident-candidate-fingerprint-fallback-block");
    let mut service_contract = candidate_service_contract_value(true);
    service_contract["no_silent_fingerprint_rustls_fallback_ready"] = json!(false);
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

    let gate = &report["outbound_fingerprint_underlay_gate"];
    assert_eq!(gate["status"].as_str().unwrap(), "blocked");
    assert!(
        !report["outbound_fingerprint_underlay_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(gate["blockers"].as_array().unwrap().iter().any(|blocker| {
        blocker
            .as_str()
            .unwrap()
            .contains("silently fall back to rustls")
    }));
    assert!(
        report["remaining_blockers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|blocker| blocker
                .as_str()
                .unwrap()
                .contains("silently fall back to rustls"))
    );
    let _ = std::fs::remove_dir_all(root);
}
