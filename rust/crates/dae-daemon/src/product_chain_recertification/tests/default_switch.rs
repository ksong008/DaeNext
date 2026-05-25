use super::*;

#[test]
fn product_chain_default_path_mutation_request_allows_switch_without_replacing_run_command() {
    let root = std::env::temp_dir().join(format!(
        "dae-daemon-product-chain-default-path-request-{}",
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
            true_rust_default_daemon_admitted: true,
            production_dataplane_admitted: true,
            reload_runtime_parity_admitted: true,
            matched_benchmark_recorded: true,
        },
        Some(clean_product_chain_evidence()),
    );
    assert!(report["default_path_mutation_requested"].as_bool().unwrap());
    assert!(
        report["resident_default_daemon_switch_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(report["default_path_mutation_allowed"].as_bool().unwrap());
    assert!(report["default_switch_allowed"].as_bool().unwrap());
    assert!(report["product_chain_switch_allowed"].as_bool().unwrap());
    assert!(
        report["product_chain_recertification_clean"]
            .as_bool()
            .unwrap()
    );
    assert!(!report["production_run_command_replaced"].as_bool().unwrap());
    assert!(report["read_only"].as_bool().unwrap());
    assert!(report["remaining_blockers"].as_array().unwrap().is_empty());
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn product_chain_default_path_mutation_blocks_service_contract_only_resident_path() {
    let root = std::env::temp_dir().join(format!(
        "dae-daemon-product-chain-resident-service-only-{}",
        std::process::id()
    ));
    let artifact_dir = root.join("artifact");
    let manifest_file = artifact_dir.join("product-chain-recertification.json");
    let options = resident_service_only_product_chain_options(
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
            true_rust_default_daemon_admitted: true,
            production_dataplane_admitted: true,
            reload_runtime_parity_admitted: true,
            matched_benchmark_recorded: true,
        },
        Some(clean_product_chain_evidence()),
    );
    assert!(
        report["product_chain_recertification_clean"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !report["resident_default_daemon_switch_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["resident_default_daemon_service_contract"]["resident_run_service_contract_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["resident_default_daemon_service_contract"]["reload_command_service_contract_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !report["resident_default_daemon_service_contract"]["resident_production_dataplane_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(!report["default_path_mutation_allowed"].as_bool().unwrap());
    assert!(!report["product_chain_switch_allowed"].as_bool().unwrap());
    assert!(
        report["remaining_blockers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|blocker| blocker
                .as_str()
                .unwrap()
                .contains("resident default service path does not admit production dataplane"))
    );
    let _ = std::fs::remove_dir_all(root);
}
