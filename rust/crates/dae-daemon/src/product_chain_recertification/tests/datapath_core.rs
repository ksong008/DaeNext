use super::*;

#[test]
fn datapath_core_gate_accepts_complete_candidate_contract() {
    let root = std::env::temp_dir().join(format!(
        "dae-daemon-product-chain-c6-ready-{}",
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

    let gate = &report["datapath_core_gate"];
    assert_eq!(gate["status"].as_str().unwrap(), "pass");
    assert!(report["datapath_core_ready"].as_bool().unwrap());
    assert!(
        report["go_datapath_core_fallback_retired_candidate"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["datapath_core_default_switch_admission_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(gate["tcp_datapath_core_ready"].as_bool().unwrap());
    assert!(gate["udp_datapath_core_ready"].as_bool().unwrap());
    assert!(gate["dns_datapath_core_ready"].as_bool().unwrap());
    assert!(
        gate["tcp_route_sniff_direct_block_proxy_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(gate["dns_cache_route_integration_ready"].as_bool().unwrap());
    assert!(
        report["c6_datapath_core"]["datapath_core_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["typed_report"]["datapath_core_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["typed_report"]["go_datapath_core_fallback_retired_candidate"]
            .as_bool()
            .unwrap()
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn datapath_core_gate_blocks_missing_dns_cache_route_contract() {
    let root = std::env::temp_dir().join(format!(
        "dae-daemon-product-chain-c6-dns-block-{}",
        std::process::id()
    ));
    let artifact_dir = root.join("artifact");
    let manifest_file = artifact_dir.join("product-chain-recertification.json");
    let binary = root.join("resident-candidate-missing-dns-cache-route");
    let mut service_contract = candidate_service_contract_value(true);
    service_contract["dns_cache_route_integration_ready"] = json!(false);
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

    let gate = &report["datapath_core_gate"];
    assert_eq!(gate["status"].as_str().unwrap(), "blocked");
    assert!(!report["datapath_core_ready"].as_bool().unwrap());
    assert!(
        !report["go_datapath_core_fallback_retired_candidate"]
            .as_bool()
            .unwrap()
    );
    assert!(gate["blockers"].as_array().unwrap().iter().any(|blocker| {
        blocker
            .as_str()
            .unwrap()
            .contains("DNS cache/route integration is not ready")
    }));
    assert!(
        report["remaining_blockers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|blocker| blocker
                .as_str()
                .unwrap()
                .contains("DNS cache/route integration is not ready"))
    );
    let _ = std::fs::remove_dir_all(root);
}
