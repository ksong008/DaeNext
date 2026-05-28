use super::*;

#[test]
fn product_chain_production_replacement_readiness_report_requires_manual_authorization() {
    let root = std::env::temp_dir().join(format!(
        "dae-daemon-product-chain-replacement-readiness-{}",
        std::process::id()
    ));
    let artifact_dir = root.join("artifact");
    let manifest_file = artifact_dir.join("product-chain-recertification.json");
    let service_file = root.join("dae.service");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(
            &service_file,
            "ExecStartPre=/usr/bin/dae validate -c /etc/dae/config.dae\nExecStart=/usr/bin/dae run --disable-timestamp -c /etc/dae/config.dae\nExecReload=/usr/bin/dae reload $MAINPID\n",
        )
        .unwrap();
    let options = resident_ready_product_chain_options(
        &root,
        ProductChainRecertificationOptions {
            execute: true,
            default_path_mutation_requested: true,
            production_run_command_replacement_dry_run_requested: true,
            production_run_command_replacement_execute_requested: true,
            production_run_command_replacement_apply_plan_requested: true,
            host_default_path_mutation_allow_requested: true,
            service_file,
            ..ProductChainRecertificationOptions::default()
        },
    );
    let mut report = report_value(
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
        Some(clean_product_chain_evidence()),
    );
    let artifacts =
        materialize_production_run_command_replacement_artifacts(&options, &report, &artifact_dir)
            .unwrap();
    attach_production_run_command_replacement_artifacts(&mut report, artifacts);
    let readiness =
        materialize_production_replacement_readiness_report(&report, &artifact_dir).unwrap();
    attach_production_replacement_readiness(&mut report, readiness.clone());

    assert_eq!(
        readiness["status"].as_str().unwrap(),
        "pass",
        "readiness report: {}",
        serde_json::to_string_pretty(&readiness).unwrap()
    );
    assert!(
        readiness["ready_for_manual_authorization"]
            .as_bool()
            .unwrap()
    );
    assert!(
        readiness["manual_authorization_required"]
            .as_bool()
            .unwrap()
    );
    assert!(!readiness["host_write_allowed"].as_bool().unwrap());
    assert!(!readiness["host_write_executed"].as_bool().unwrap());
    assert!(
        !readiness["production_run_command_replaced"]
            .as_bool()
            .unwrap()
    );
    assert!(
        readiness["readiness_blockers"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(
        !readiness["checks"]["go_fallback_required"]
            .as_bool()
            .unwrap()
    );
    assert!(
        readiness["checks"]["go_fallback_retired"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["production_replacement_ready_for_manual_authorization"]
            .as_bool()
            .unwrap()
    );
    assert!(std::path::Path::new(readiness["readiness_file"].as_str().unwrap()).exists());
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn product_chain_daed2_switch_rehearsal_report_uses_readiness_artifacts() {
    let root = std::env::temp_dir().join(format!(
        "dae-daemon-product-chain-daed2-rehearsal-{}",
        std::process::id()
    ));
    let artifact_dir = root.join("artifact");
    let manifest_file = artifact_dir.join("product-chain-recertification.json");
    let service_file = root.join("dae.service");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(
            &service_file,
            "ExecStartPre=/usr/bin/dae validate -c /etc/dae/config.dae\nExecStart=/usr/bin/dae run --disable-timestamp -c /etc/dae/config.dae\nExecReload=/usr/bin/dae reload $MAINPID\n",
        )
        .unwrap();
    let options = resident_ready_product_chain_options(
        &root,
        ProductChainRecertificationOptions {
            execute: true,
            default_path_mutation_requested: true,
            production_run_command_replacement_dry_run_requested: true,
            production_run_command_replacement_execute_requested: true,
            production_run_command_replacement_apply_plan_requested: true,
            host_default_path_mutation_allow_requested: true,
            service_file,
            ..ProductChainRecertificationOptions::default()
        },
    );
    let mut report = report_value(
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
        Some(clean_product_chain_evidence()),
    );
    let artifacts =
        materialize_production_run_command_replacement_artifacts(&options, &report, &artifact_dir)
            .unwrap();
    attach_production_run_command_replacement_artifacts(&mut report, artifacts);
    let readiness =
        materialize_production_replacement_readiness_report(&report, &artifact_dir).unwrap();
    attach_production_replacement_readiness(&mut report, readiness);
    let rehearsal =
        materialize_daed2_product_chain_switch_rehearsal_report(&report, &artifact_dir).unwrap();
    attach_daed2_product_chain_switch_rehearsal(&mut report, rehearsal.clone());

    assert_eq!(rehearsal["status"].as_str().unwrap(), "pass");
    assert!(rehearsal["pass"].as_bool().unwrap());
    assert!(rehearsal["daed2_product_chain_used"].as_bool().unwrap());
    assert!(
        rehearsal["checks"]["production_replacement_readiness_passed"]
            .as_bool()
            .unwrap()
    );
    assert!(!rehearsal["actual_host_write_executed"].as_bool().unwrap());
    assert!(
        report["daed2_product_chain_switch_rehearsal_passed"]
            .as_bool()
            .unwrap()
    );
    assert!(std::path::Path::new(rehearsal["rehearsal_file"].as_str().unwrap()).exists());
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn product_chain_host_write_plan_freeze_requires_phase4_authorization() {
    let root = std::env::temp_dir().join(format!(
        "dae-daemon-product-chain-host-write-freeze-{}",
        std::process::id()
    ));
    let artifact_dir = root.join("artifact");
    let manifest_file = artifact_dir.join("product-chain-recertification.json");
    let service_file = root.join("dae.service");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(
            &service_file,
            "ExecStartPre=/usr/bin/dae validate -c /etc/dae/config.dae\nExecStart=/usr/bin/dae run --disable-timestamp -c /etc/dae/config.dae\nExecReload=/usr/bin/dae reload $MAINPID\n",
        )
        .unwrap();
    let options = resident_ready_product_chain_options(
        &root,
        ProductChainRecertificationOptions {
            execute: true,
            default_path_mutation_requested: true,
            production_run_command_replacement_dry_run_requested: true,
            production_run_command_replacement_execute_requested: true,
            production_run_command_replacement_apply_plan_requested: true,
            host_default_path_mutation_allow_requested: true,
            service_file,
            ..ProductChainRecertificationOptions::default()
        },
    );
    let mut report = report_value(
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
        Some(clean_product_chain_evidence()),
    );
    let artifacts =
        materialize_production_run_command_replacement_artifacts(&options, &report, &artifact_dir)
            .unwrap();
    attach_production_run_command_replacement_artifacts(&mut report, artifacts);
    let readiness =
        materialize_production_replacement_readiness_report(&report, &artifact_dir).unwrap();
    attach_production_replacement_readiness(&mut report, readiness);
    let rehearsal =
        materialize_daed2_product_chain_switch_rehearsal_report(&report, &artifact_dir).unwrap();
    attach_daed2_product_chain_switch_rehearsal(&mut report, rehearsal);
    let host_inventory = report["production_replacement_readiness"]["host_inventory"]
        .as_object_mut()
        .unwrap();
    host_inventory.insert("usr_bin_dae_exists".to_owned(), json!(true));
    host_inventory.insert("installed_system_service_exists".to_owned(), json!(true));
    host_inventory.insert("runtime_config_exists".to_owned(), json!(true));
    host_inventory.insert(
        "installed_system_service_files".to_owned(),
        json!(["/etc/systemd/system/dae.service"]),
    );
    let freeze =
        materialize_production_host_write_plan_freeze_report(&report, &artifact_dir).unwrap();
    attach_production_host_write_plan_freeze(&mut report, freeze.clone());

    assert_eq!(freeze["status"].as_str().unwrap(), "pass");
    assert!(freeze["pass"].as_bool().unwrap());
    assert!(freeze["frozen"].as_bool().unwrap());
    assert_eq!(freeze["operation_mode"].as_str().unwrap(), "replacement");
    assert!(!freeze["fresh_install_requires_replan"].as_bool().unwrap());
    assert!(
        freeze["manual_authorization_required_for_phase4"]
            .as_bool()
            .unwrap()
    );
    assert!(
        freeze["phase4_must_not_start_without_user_authorization"]
            .as_bool()
            .unwrap()
    );
    assert!(!freeze["host_write_allowed"].as_bool().unwrap());
    assert!(!freeze["actual_host_write_executed"].as_bool().unwrap());
    assert!(!freeze["production_run_command_replaced"].as_bool().unwrap());
    assert!(
        !freeze["frozen_execution_checklist"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(
        report["production_host_write_plan_freeze_passed"]
            .as_bool()
            .unwrap()
    );
    assert!(std::path::Path::new(freeze["freeze_file"].as_str().unwrap()).exists());
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn product_chain_host_write_plan_freeze_blocks_unplanned_fresh_install() {
    let root = std::env::temp_dir().join(format!(
        "dae-daemon-product-chain-host-write-fresh-install-{}",
        std::process::id()
    ));
    let artifact_dir = root.join("artifact");
    std::fs::create_dir_all(&artifact_dir).unwrap();
    let report = json!({
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

    let freeze =
        materialize_production_host_write_plan_freeze_report(&report, &artifact_dir).unwrap();

    assert_eq!(freeze["status"].as_str().unwrap(), "blocked");
    assert!(!freeze["pass"].as_bool().unwrap());
    assert!(!freeze["frozen"].as_bool().unwrap());
    assert_eq!(freeze["operation_mode"].as_str().unwrap(), "fresh-install");
    assert!(freeze["fresh_install_requires_replan"].as_bool().unwrap());
    assert!(
        freeze["blockers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|blocker| blocker.as_str().unwrap().contains("fresh install"))
    );
    assert!(
        freeze["blockers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|blocker| blocker.as_str().unwrap().contains("/etc/dae/config.dae"))
    );
    assert!(
        freeze["frozen_execution_checklist"]
            .as_array()
            .unwrap()
            .iter()
            .any(|step| step.as_str().unwrap().contains("fresh installation"))
    );
    let _ = std::fs::remove_dir_all(root);
}
