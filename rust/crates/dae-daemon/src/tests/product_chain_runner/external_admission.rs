use super::*;
#[test]
pub(crate) fn daemon_runner_product_chain_accepts_external_admission_evidence() {
    let root = std::env::temp_dir().join(format!(
        "dae-daemon-run-product-chain-external-admission-{}",
        std::process::id()
    ));
    let fixture = std::env::temp_dir().join(format!(
        "dae-daemon-product-chain-external-admission-fixture-{}",
        std::process::id()
    ));
    let config = fixture.join("config.dae");
    let service = fixture.join("install/dae.service");
    let go_mod = fixture.join("go.mod");
    let admission = fixture.join("admission.json");
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
    std::fs::write(
        &admission,
        serde_json::to_vec_pretty(&json!({
            "production_dataplane_admitted": true,
            "reload_runtime_parity_admitted": true,
            "matched_go_rust_default_daemon_benchmark_recorded": true,
            "bpf_go_fallback_retired": true,
            "true_rust_default_daemon_admitted": true,
        }))
        .unwrap(),
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
            "--execute-product-chain-recertification".to_owned(),
            "--product-chain-admission-evidence".to_owned(),
            admission.display().to_string(),
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
    assert!(
        json["product_chain_admission_evidence_override"]["used"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        json["product_chain_admission_evidence_override"]["source"]
            .as_str()
            .unwrap(),
        admission.display().to_string()
    );
    assert!(
        json["product_chain_recertification"]["admission_input"]
            ["true_rust_default_daemon_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        json["product_chain_recertification"]["runtime_control_api_clean_baseline"]
            ["true_rust_default_daemon_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["true_rust_default_daemon_admitted"].as_bool().unwrap());
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
    assert!(
        !json["default_daemon_live_matrix"]["matrix_complete"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["release_product_chain_live_gate"]["release_gate_open"]
            .as_bool()
            .unwrap()
    );
    assert!(
        json["release_product_chain_live_gate"]["go_runtime_outbound_fallback_required"]
            .as_bool()
            .unwrap()
    );
    let _ = std::fs::remove_dir_all(root);
    let _ = std::fs::remove_dir_all(fixture);
}
