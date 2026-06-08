use super::*;
#[test]
pub(crate) fn daemon_runner_product_chain_accepts_fallback_retirement_without_release_switch() {
    let root = std::env::temp_dir().join(format!(
        "dae-daemon-run-product-chain-fallback-retirement-{}",
        std::process::id()
    ));
    let fixture = std::env::temp_dir().join(format!(
        "dae-daemon-product-chain-fallback-retirement-fixture-{}",
        std::process::id()
    ));
    let config = fixture.join("config.dae");
    let service = fixture.join("install/dae.service");
    let go_mod = fixture.join("go.mod");
    std::fs::create_dir_all(config.parent().unwrap()).unwrap();
    std::fs::write(
        &config,
        "global {\n  log_level: info\n}\n\nrouting {\n  pname(NetworkManager) -> direct\n}\n",
    )
    .unwrap();
    std::fs::create_dir_all(service.parent().unwrap()).unwrap();
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
        std::fs::create_dir_all(&repo_dir).unwrap();
        assert!(
            std::process::Command::new("git")
                .args(["init", "--quiet"])
                .current_dir(&repo_dir)
                .status()
                .unwrap()
                .success()
        );
    }

    let output = run_with_args_and_version(
        [
            "run".to_owned(),
            "--config".to_owned(),
            config.display().to_string(),
            "--root".to_owned(),
            root.display().to_string(),
            "--disable-timestamp".to_owned(),
            "--disable-sudo".to_owned(),
            "--production-runtime-fallback-retirement-product-chain-recertified".to_owned(),
            "--production-runtime-fallback-retirement-explicit-approval".to_owned(),
            "--execute-product-chain-recertification".to_owned(),
            "--product-chain-dae-repo".to_owned(),
            fixture.join("dae").display().to_string(),
            "--product-chain-dae-wing-repo".to_owned(),
            fixture.join("dae-wing").display().to_string(),
            "--product-chain-daed-repo".to_owned(),
            fixture.join("daed").display().to_string(),
            "--product-chain-outbound-repo".to_owned(),
            fixture.join("outbound").display().to_string(),
            "--product-chain-quic-go-repo".to_owned(),
            fixture.join("quic-go").display().to_string(),
            "--product-chain-service-file".to_owned(),
            service.display().to_string(),
            "--product-chain-go-mod-file".to_owned(),
            go_mod.display().to_string(),
            "--exit-after-ready".to_owned(),
        ],
        "test-version",
    );
    assert_eq!(output.exit_code, 0, "{}", output.stderr);
    let json: Value = serde_json::from_str(&output.stdout).unwrap();
    let fallback_gate = &json["production_runtime_owner"]["ebpf_backend_capabilities"]["kernel_program_fallback_retirement_gate"];
    assert!(fallback_gate["admitted"].as_bool().unwrap());
    assert!(
        json["production_runtime_owner"]["go_bpf_fallback_retired"]
            .as_bool()
            .unwrap()
    );
    assert!(
        json["product_chain_recertification"]["admission_input"]["bpf_go_fallback_retired"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["product_chain_recertification_clean"]
            .as_bool()
            .unwrap()
    );
    let dae_branch_mismatch =
        json["product_chain_recertification"]["branch_mismatched_sibling_repos"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| entry.as_str().unwrap())
            .find(|entry| entry.starts_with("dae:"))
            .unwrap();
    assert!(dae_branch_mismatch.ends_with("!=dae-daex-align"));
    assert!(
        !json["product_chain_default_switch_admission_clean"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["release_gate_open"].as_bool().unwrap());
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
    assert!(!json["product_chain_switch_allowed"].as_bool().unwrap());
    assert!(
        !json["default_daemon_live_matrix"]["matrix_complete"]
            .as_bool()
            .unwrap()
    );
    let release_blockers = json["release_product_chain_live_gate"]["remaining_blockers"]
        .as_array()
        .unwrap();
    assert!(release_blockers.iter().any(|blocker| {
        blocker
            .as_str()
            .unwrap()
            .contains("full default daemon live matrix")
    }));
    assert!(release_blockers.iter().any(|blocker| {
        blocker
            .as_str()
            .unwrap()
            .contains("resident userspace dataplane")
    }));
    assert!(fallback_gate["default_switch_allowed"].as_bool().unwrap());
    assert!(
        fallback_gate["c_tproxy_object_retirement_allowed"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !fallback_gate["tc_command_fallback_retirement_allowed"]
            .as_bool()
            .unwrap()
    );
    let _ = std::fs::remove_dir_all(root);
    let _ = std::fs::remove_dir_all(fixture);
}
