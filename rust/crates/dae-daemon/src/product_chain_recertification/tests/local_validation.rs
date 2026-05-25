use super::*;

#[test]
fn product_chain_freezes_local_validation_fresh_install_without_production_authorization() {
    let root = std::env::temp_dir().join(format!(
        "dae-daemon-product-chain-local-validation-install-{}",
        std::process::id()
    ));
    let artifact_dir = root.join("artifact");
    let service_file = root.join("install").join("dae.service");
    let config_source = root.join("example.dae");
    let binary_source = root.join("dae-daemon-optin");
    std::fs::create_dir_all(&artifact_dir).unwrap();
    std::fs::create_dir_all(service_file.parent().unwrap()).unwrap();
    std::fs::write(
            &service_file,
            "ExecStartPre=/usr/bin/dae validate -c /etc/dae/config.dae\nExecStart=/usr/bin/dae run --disable-timestamp -c /etc/dae/config.dae\nExecReload=/usr/bin/dae reload $MAINPID\n",
        )
        .unwrap();
    std::fs::write(&config_source, "global {\n  log_level: info\n}\n").unwrap();
    std::fs::write(
        &binary_source,
        "#!/bin/sh\n[ \"$1\" = \"validate\" ] && exit 0\nexit 2\n",
    )
    .unwrap();
    #[cfg(unix)]
    std::fs::set_permissions(&binary_source, std::fs::Permissions::from_mode(0o755)).unwrap();
    let options = ProductChainRecertificationOptions {
        service_file: service_file.clone(),
        local_validation_fresh_install_plan_requested: true,
        local_validation_config_source: Some(config_source.clone()),
        local_validation_binary_source: Some(binary_source.clone()),
        ..ProductChainRecertificationOptions::default()
    };
    let mut report = json!({
        "service_contract_preserved": true,
        "product_chain_recertification_clean": true,
        "production_run_command_replaced": false,
        "daed2_product_chain_switch_rehearsal_passed": true,
        "production_replacement_readiness": {
            "ready_for_manual_authorization": true,
            "checks": {
                "no_host_write_executed": true
            },
            "host_inventory": {
                "usr_bin_dae_exists": false,
                "usr_local_bin_dae_exists": false,
                "installed_system_service_exists": false,
                "installed_system_service_files": [],
                "runtime_config_file": "/etc/dae/config.dae",
                "runtime_config_exists": false
            },
            "readiness_file": "/tmp/production-replacement-readiness.json",
            "required_artifacts": {
                "apply_manifest_file": "/tmp/production-run-command-replacement-apply.json",
                "service_diff_file": "/tmp/production-run-command-replacement-service.diff",
                "backup_manifest_file": "/tmp/backup-manifest.json",
                "rollback_script": "/tmp/rollback-production-run-command-replacement.sh"
            }
        },
        "daed2_product_chain_switch_rehearsal": {
            "pass": true,
            "actual_host_write_executed": false,
            "rehearsal_file": "/tmp/daed2-product-chain-switch-rehearsal.json"
        }
    });

    let local_plan =
        materialize_local_validation_fresh_install_plan(&options, &report, &artifact_dir).unwrap();
    assert_eq!(local_plan["status"].as_str().unwrap(), "blocked");
    assert!(!local_plan["pass"].as_bool().unwrap());
    assert_eq!(
        local_plan["scope"].as_str().unwrap(),
        "local-validation-only"
    );
    assert_eq!(
        local_plan["inputs"]["config_source"].as_str().unwrap(),
        path_string(&config_source)
    );
    assert_eq!(
        local_plan["installation_targets"]["binary_target"]
            .as_str()
            .unwrap(),
        "/usr/bin/dae"
    );
    assert!(
        !local_plan["production_host_write_authorized"]
            .as_bool()
            .unwrap()
    );
    assert!(
        local_plan["candidate_validate"]["passed"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !local_plan["checks"]["resident_run_service_contract_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !local_plan["checks"]["reload_command_service_contract_ready"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        local_plan["installation_targets"]["config_target_mode"]
            .as_str()
            .unwrap(),
        "0600"
    );
    assert!(std::path::Path::new(local_plan["plan_file"].as_str().unwrap()).exists());
    attach_local_validation_fresh_install_plan(&mut report, local_plan);

    let freeze =
        materialize_production_host_write_plan_freeze_report(&report, &artifact_dir).unwrap();
    assert!(!freeze["pass"].as_bool().unwrap());
    assert!(
        !freeze["checks"]["local_validation_fresh_install_plan_passed"]
            .as_bool()
            .unwrap()
    );
    assert!(
        freeze["blockers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|blocker| blocker
                .as_str()
                .unwrap()
                .contains("candidate service command contract"))
    );
    let _ = std::fs::remove_dir_all(root);
}
