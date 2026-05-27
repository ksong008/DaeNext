use super::*;

#[test]
fn product_chain_recertification_blocks_when_repo_status_is_unavailable() {
    let root = std::env::temp_dir().join(format!(
        "dae-daemon-product-chain-nongit-{}",
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
        std::fs::create_dir_all(fixture.join(repo)).unwrap();
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
    assert!(report["sibling_repos_present"].as_bool().unwrap());
    assert!(!report["sibling_repo_status_available"].as_bool().unwrap());
    assert!(
        !report["unavailable_sibling_repos"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(!report["clean_product_chain_baseline"].as_bool().unwrap());
    assert!(
        !report["product_chain_recertification_clean"]
            .as_bool()
            .unwrap()
    );
    assert!(!report["default_switch_allowed"].as_bool().unwrap());
    let _ = std::fs::remove_dir_all(root);
}
