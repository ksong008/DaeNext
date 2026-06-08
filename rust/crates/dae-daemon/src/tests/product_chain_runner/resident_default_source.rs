use super::*;
#[test]
pub(crate) fn daemon_runner_product_chain_accepts_explicit_resident_default_candidate_source() {
    let root = std::env::temp_dir().join(format!(
        "dae-daemon-run-product-chain-resident-source-{}",
        std::process::id()
    ));
    let fixture = std::env::temp_dir().join(format!(
        "dae-daemon-product-chain-resident-source-fixture-{}",
        std::process::id()
    ));
    let config = fixture.join("config.dae");
    let service = fixture.join("install/dae.service");
    let go_mod = fixture.join("go.mod");
    let resident_binary = fixture.join("resident-candidate");
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
        &resident_binary,
        "#!/bin/sh\nif [ \"$1\" = \"service-contract\" ]; then printf '%s\\n' '{\"resident_run_service_contract_ready\":true,\"reload_command_service_contract_ready\":true,\"resident_production_dataplane_ready\":false}'; exit 0; fi\nexit 2\n",
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&resident_binary, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
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
            "--request-default-path-mutation".to_owned(),
            "--product-chain-resident-default-daemon-binary-source".to_owned(),
            resident_binary.display().to_string(),
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
    let gate = &json["product_chain_recertification"]["resident_default_daemon_switch_gate"];
    assert_eq!(
        gate["binary_source"].as_str().unwrap(),
        resident_binary.display().to_string()
    );
    assert_eq!(gate["status"].as_str().unwrap(), "blocked");
    assert!(
        !json["product_chain_recertification"]["resident_default_daemon_switch_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["product_chain_recertification"]["default_path_mutation_allowed"]
            .as_bool()
            .unwrap()
    );
    assert!(gate["blockers"].as_array().unwrap().iter().any(|blocker| {
        blocker
            .as_str()
            .unwrap()
            .contains("resident default service path does not admit production dataplane")
    }));
    assert!(
        !json["product_chain_recertification"]["local_validation_fresh_install_plan"]["requested"]
            .as_bool()
            .unwrap()
    );
    let _ = std::fs::remove_dir_all(root);
    let _ = std::fs::remove_dir_all(fixture);
}
