use super::*;

#[test]
fn product_chain_recertification_is_read_only_by_default() {
    let root = std::env::temp_dir().join(format!(
        "dae-daemon-product-chain-default-{}",
        std::process::id()
    ));
    let report = product_chain_recertification_report(
        &root,
        &ProductChainRecertificationOptions::default(),
        ProductChainAdmissionEvidence::default(),
    )
    .unwrap();
    assert!(!report["execute"].as_bool().unwrap());
    assert!(
        !report["product_chain_recertification_recorded"]
            .as_bool()
            .unwrap()
    );
    assert!(!report["default_switch_allowed"].as_bool().unwrap());
    assert!(!report["product_chain_switch_allowed"].as_bool().unwrap());
}

#[test]
fn product_chain_recertification_records_service_and_go_mod_boundaries() {
    let root = std::env::temp_dir().join(format!(
        "dae-daemon-product-chain-record-{}",
        std::process::id()
    ));
    let fixture = root.join("fixture");
    std::fs::create_dir_all(&fixture).unwrap();
    let service = fixture.join("dae.service");
    let go_mod = fixture.join("go.mod");
    std::fs::write(
            &service,
            "ExecStartPre=/usr/bin/dae validate -c /etc/dae/config.dae\nExecStart=/usr/bin/dae run --disable-timestamp -c /etc/dae/config.dae\nExecReload=/usr/bin/dae reload $MAINPID\n",
        )
        .unwrap();
    std::fs::write(
            &go_mod,
            "replace github.com/daeuniverse/outbound => github.com/ksong008/outbound v0.0.0\nreplace github.com/daeuniverse/quic-go => github.com/ksong008/quic-go v0.0.0\n",
        )
        .unwrap();
    for repo in ["dae", "dae-wing", "daed", "outbound", "quic-go"] {
        let repo_dir = fixture.join(repo);
        init_fixture_repo(&repo_dir, expected_product_chain_branch(repo));
    }
    let options = ProductChainRecertificationOptions {
        execute: true,
        default_path_mutation_requested: false,
        production_run_command_replacement_dry_run_requested: false,
        production_run_command_replacement_execute_requested: false,
        production_run_command_replacement_apply_plan_requested: false,
        host_default_path_mutation_allow_requested: false,
        local_validation_fresh_install_plan_requested: false,
        local_validation_config_source: None,
        local_validation_binary_source: None,
        resident_default_daemon_binary_source: None,
        dae_repo: fixture.join("dae"),
        dae_wing_repo: fixture.join("dae-wing"),
        daed_repo: fixture.join("daed"),
        outbound_repo: fixture.join("outbound"),
        quic_go_repo: fixture.join("quic-go"),
        service_file: service,
        go_mod_file: go_mod,
    };
    let report = product_chain_recertification_report(
        &root,
        &options,
        ProductChainAdmissionEvidence {
            true_rust_default_daemon_admitted: true,
            production_dataplane_admitted: true,
            reload_runtime_parity_admitted: true,
            matched_benchmark_recorded: true,
            bpf_go_fallback_retired: true,
        },
    )
    .unwrap();
    assert!(
        report["product_chain_recertification_recorded"]
            .as_bool()
            .unwrap()
    );
    assert!(report["service_contract_preserved"].as_bool().unwrap());
    assert!(
        report["outbound_quic_go_dependency_boundary_preserved"]
            .as_bool()
            .unwrap()
    );
    assert!(report["sibling_repos_present"].as_bool().unwrap());
    assert!(report["sibling_repo_status_available"].as_bool().unwrap());
    assert!(
        report["product_chain_branch_contract_preserved"]
            .as_bool()
            .unwrap()
    );
    assert!(report["clean_product_chain_baseline"].as_bool().unwrap());
    assert!(
        !report["daed_wing_runtime_control_api_regression_recorded"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !report["product_chain_structural_baseline_clean"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !report["product_chain_recertification_clean"]
            .as_bool()
            .unwrap()
    );
    assert!(!report["default_switch_allowed"].as_bool().unwrap());
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn product_chain_recertification_blocks_wrong_daed2_branch_contract() {
    let root = std::env::temp_dir().join(format!(
        "dae-daemon-product-chain-branch-contract-{}",
        std::process::id()
    ));
    let fixture = root.join("fixture");
    std::fs::create_dir_all(&fixture).unwrap();
    let service = fixture.join("dae.service");
    let go_mod = fixture.join("go.mod");
    std::fs::write(
            &service,
            "ExecStartPre=/usr/bin/dae validate -c /etc/dae/config.dae\nExecStart=/usr/bin/dae run --disable-timestamp -c /etc/dae/config.dae\nExecReload=/usr/bin/dae reload $MAINPID\n",
        )
        .unwrap();
    std::fs::write(
            &go_mod,
            "replace github.com/daeuniverse/outbound => github.com/ksong008/outbound v0.0.0\nreplace github.com/daeuniverse/quic-go => github.com/ksong008/quic-go v0.0.0\n",
        )
        .unwrap();
    init_fixture_repo(&fixture.join("dae"), "daex");
    init_fixture_repo(&fixture.join("dae-wing"), "daewing2.0");
    init_fixture_repo(&fixture.join("daed"), "daed2.0");
    init_fixture_repo(&fixture.join("outbound"), "outboundrust");
    init_fixture_repo(&fixture.join("quic-go"), "quic-go-daex-align");

    let options = ProductChainRecertificationOptions {
        execute: true,
        dae_repo: fixture.join("dae"),
        dae_wing_repo: fixture.join("dae-wing"),
        daed_repo: fixture.join("daed"),
        outbound_repo: fixture.join("outbound"),
        quic_go_repo: fixture.join("quic-go"),
        service_file: service,
        go_mod_file: go_mod,
        ..ProductChainRecertificationOptions::default()
    };
    let report = product_chain_recertification_report(
        &root,
        &options,
        ProductChainAdmissionEvidence {
            true_rust_default_daemon_admitted: true,
            production_dataplane_admitted: true,
            reload_runtime_parity_admitted: true,
            matched_benchmark_recorded: true,
            bpf_go_fallback_retired: true,
        },
    )
    .unwrap();

    assert!(
        !report["product_chain_branch_contract_preserved"]
            .as_bool()
            .unwrap()
    );
    assert!(!report["clean_product_chain_baseline"].as_bool().unwrap());
    let mismatched = report["branch_mismatched_sibling_repos"]
        .as_array()
        .unwrap();
    assert!(mismatched.iter().any(|entry| {
        entry
            .as_str()
            .unwrap()
            .contains("daed:daed2.0!=daed2-daex-align")
    }));
    assert!(mismatched.iter().any(|entry| {
        entry
            .as_str()
            .unwrap()
            .contains("outbound:outboundrust!=outbound-daex-align")
    }));
    assert_eq!(
        report["expected_product_chain_branches"]["dae"]
            .as_str()
            .unwrap(),
        "daex"
    );
    assert_eq!(
        report["typed_report"]["product_chain_branch_contract_preserved"]
            .as_bool()
            .unwrap(),
        false
    );
    assert!(
        report["remaining_blockers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|blocker| blocker
                .as_str()
                .unwrap()
                .contains("branches do not match daed2.0 switch contract"))
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn product_chain_clean_baseline_records_runtime_control_api_regression_without_switching_default_path()
 {
    let root = std::env::temp_dir().join(format!(
        "dae-daemon-product-chain-clean-api-baseline-{}",
        std::process::id()
    ));
    let artifact_dir = root.join("artifact");
    let manifest_file = artifact_dir.join("product-chain-recertification.json");
    let evidence = clean_product_chain_evidence();
    let options = ProductChainRecertificationOptions {
        execute: true,
        ..ProductChainRecertificationOptions::default()
    };
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
        Some(evidence),
    );
    assert!(
        report["runtime_control_api_clean_baseline"]["recorded"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["runtime_control_api_source_baseline_recorded"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["runtime_control_api_final_admission_recorded"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        report["typed_report"]["schema"].as_str().unwrap(),
        "product-chain-recertification-typed-report-v1"
    );
    assert_eq!(report["typed_report"]["status"].as_str().unwrap(), "pass");
    assert!(
        !report["typed_report"]["stage_report_schema"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["daed_wing_runtime_control_api_regression_recorded"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["daed_wing_runtime_control_api_default_switch_regression_recorded"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["product_chain_structural_baseline_clean"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["product_chain_default_switch_admission_clean"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["product_chain_recertification_clean"]
            .as_bool()
            .unwrap()
    );
    assert!(!report["default_path_mutation_allowed"].as_bool().unwrap());
    assert!(!report["default_switch_allowed"].as_bool().unwrap());
    assert!(!report["product_chain_switch_allowed"].as_bool().unwrap());
    assert!(
        report["remaining_blockers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|blocker| blocker.as_str().unwrap().contains("default path mutation"))
    );
    assert!(
        !report["remaining_blockers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|blocker| blocker.as_str().unwrap().contains("runtime/control API"))
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn product_chain_structural_baseline_does_not_require_default_switch_admission() {
    let root = std::env::temp_dir().join(format!(
        "dae-daemon-product-chain-structural-no-default-{}",
        std::process::id()
    ));
    let artifact_dir = root.join("artifact");
    let manifest_file = artifact_dir.join("product-chain-recertification.json");
    let options = ProductChainRecertificationOptions {
        execute: true,
        ..ProductChainRecertificationOptions::default()
    };
    let report = report_value(
        &options,
        &artifact_dir,
        &manifest_file,
        ProductChainAdmissionEvidence::default(),
        Some(clean_product_chain_evidence()),
    );

    assert!(
        report["runtime_control_api_clean_baseline"]["recorded"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["runtime_control_api_source_baseline_recorded"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !report["runtime_control_api_final_admission_recorded"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["daed_wing_runtime_control_api_regression_recorded"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !report["daed_wing_runtime_control_api_default_switch_regression_recorded"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["product_chain_structural_baseline_clean"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["product_chain_recertification_clean"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !report["product_chain_default_switch_admission_clean"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(report["typed_report"]["status"].as_str().unwrap(), "pass");
    assert!(
        report["typed_report"]["structural_baseline_clean"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !report["typed_report"]["default_switch_admission_clean"]
            .as_bool()
            .unwrap()
    );
    assert!(!report["default_path_mutation_allowed"].as_bool().unwrap());
    assert!(!report["product_chain_switch_allowed"].as_bool().unwrap());
    let blockers = report["remaining_blockers"].as_array().unwrap();
    assert!(blockers.iter().any(|blocker| {
        blocker
            .as_str()
            .unwrap()
            .contains("true Rust default daemon admission")
    }));
    assert!(blockers.iter().any(|blocker| {
        blocker
            .as_str()
            .unwrap()
            .contains("BPF-side Go fallback retirement")
    }));
    assert!(
        blockers
            .iter()
            .any(|blocker| blocker.as_str().unwrap().contains("default path mutation"))
    );
    assert!(
        !blockers
            .iter()
            .any(|blocker| blocker.as_str().unwrap().contains("runtime/control API"))
    );
    let _ = std::fs::remove_dir_all(root);
}
