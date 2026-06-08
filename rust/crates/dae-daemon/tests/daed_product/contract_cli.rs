use super::*;
#[test]
pub(super) fn daed_product_contract_reports_c10_initial_state_paths() {
    let output = Command::new(binary())
        .args(["service-contract", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        report["primary_state_store"].as_str().unwrap(),
        "/etc/daed/daed.db"
    );
    assert_eq!(
        report["protected_rollback_state_store"].as_str().unwrap(),
        "/etc/daed/wing.db"
    );
    assert!(
        !report["rust_daed_writes_wing_db_by_default"]
            .as_bool()
            .unwrap()
    );
    assert!(report["wing_db_import_supported"].as_bool().unwrap());
    assert!(
        report["rust_daed_validate_command_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["rust_daed_setup_auth_user_storage_api_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["rust_daed_static_webui_serving_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["rust_daed_resource_crud_api_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(report["rust_daed_materializer_ready"].as_bool().unwrap());
    assert!(report["rust_daed_runtime_owner_ready"].as_bool().unwrap());
    assert!(
        report["rust_daed_logs_sse_latency_subscription_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["rust_daed_import_export_package_surface_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["rust_daed_subscription_fetch_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["rust_daed_latency_probe_tcp_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["rust_daed_resetpass_parity_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["rust_daed_package_manifest_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["rust_daed_webui_route_audit_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["rust_daed_local_package_admission_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["go_free_product_chain_typed_report"]["rust_product_binary_contract_ready"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        report["go_free_product_chain_typed_report"]["status"]
            .as_str()
            .unwrap(),
        "blocked"
    );
    assert!(
        !report["go_free_live_host_contract_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(!report["go_free_rollback_model_ready"].as_bool().unwrap());
    assert!(
        report["go_free_product_chain_typed_report"]["blockers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|blocker| blocker
                .as_str()
                .unwrap()
                .contains("rollback artifact validation is not recorded"))
    );
    assert!(!report["go_free_product_chain_ready"].as_bool().unwrap());

    let package = Command::new(binary())
        .args(["package-info", "--json"])
        .output()
        .unwrap();
    assert!(package.status.success());
    let package: Value = serde_json::from_slice(&package.stdout).unwrap();
    assert_eq!(
        package["primary_state_store"].as_str().unwrap(),
        "/etc/daed/daed.db"
    );
    assert!(
        package["current_batch_ready"]["local_package_admission"]
            .as_bool()
            .unwrap()
    );
    assert!(
        package["current_batch_ready"]["validate_command"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !package["package_surface"]["default_package_switch_live_applied"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !package["package_surface"]["rollback_validation_applied_on_live_host"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !package["package_surface"]["release_default_switch_admission"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !package["package_surface"]["production_package_admission"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !package["full_go_free_product_chain_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(!package["webui"]["leptos_considered"].as_bool().unwrap());
}

#[test]
pub(super) fn daed_version_command_supports_package_smoke_test() {
    let output = Command::new(binary())
        .env("DAE_DAEMON_VERSION", "c10-smoke")
        .arg("--version")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), "c10-smoke\n");
}

#[test]
pub(super) fn daed_validate_accepts_config_file_and_config_dir_without_state_mutation() {
    let temp = temp_dir("validate");
    let config_file = temp.join("empty.dae");
    fs::write(&config_file, "global {} routing {}").unwrap();
    fs::set_permissions(&config_file, fs::Permissions::from_mode(0o600)).unwrap();

    let output = Command::new(binary())
        .args(["validate", "-c"])
        .arg(&config_file)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty());

    let json_output = Command::new(binary())
        .args(["validate", "-c"])
        .arg(&config_file)
        .arg("--json")
        .output()
        .unwrap();
    assert!(json_output.status.success());
    let report: Value = serde_json::from_slice(&json_output.stdout).unwrap();
    assert_eq!(report["status"].as_str().unwrap(), "pass");
    assert_eq!(report["kind"].as_str().unwrap(), "dae-config-file");
    assert!(!report["mutationExecuted"].as_bool().unwrap());

    let config_dir = temp.join("config-dir");
    fs::create_dir_all(&config_dir).unwrap();
    let dir_output = Command::new(binary())
        .args(["validate", "-c"])
        .arg(&config_dir)
        .arg("--json")
        .output()
        .unwrap();
    assert!(
        dir_output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&dir_output.stderr)
    );
    let dir_report: Value = serde_json::from_slice(&dir_output.stdout).unwrap();
    assert_eq!(dir_report["kind"].as_str().unwrap(), "daed-config-dir");
    assert!(!dir_report["statePresent"].as_bool().unwrap());
    assert!(dir_report["freshInstallStateOptional"].as_bool().unwrap());
    assert!(!config_dir.join("daed.db").exists());

    let bad_config = temp.join("bad.dae");
    fs::write(&bad_config, "this is not dae config").unwrap();
    let bad = Command::new(binary())
        .args(["validate", "-c"])
        .arg(&bad_config)
        .output()
        .unwrap();
    assert!(!bad.status.success());
    assert!(
        String::from_utf8_lossy(&bad.stderr).contains("validate failed"),
        "stderr={}",
        String::from_utf8_lossy(&bad.stderr)
    );
    let _ = fs::remove_dir_all(temp);
}

#[test]
pub(super) fn daed_state_migrate_does_not_modify_wing_db() {
    let temp = temp_dir("state-migrate");
    let wing = temp.join("wing.db");
    let daed = temp.join("daed.db");

    let check_wing = Command::new(binary())
        .args(["state", "check", "--state"])
        .arg(&wing)
        .output()
        .unwrap();
    assert!(check_wing.status.success());
    let wing_hash_before = sha256(&wing);

    let migrate = Command::new(binary())
        .args(["state", "migrate", "--from-wing-db"])
        .arg(&wing)
        .args(["--to"])
        .arg(&daed)
        .output()
        .unwrap();
    assert!(
        migrate.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&migrate.stderr)
    );
    let report: Value = serde_json::from_slice(&migrate.stdout).unwrap();
    assert!(report["wing_db_unchanged"].as_bool().unwrap());
    assert_eq!(wing_hash_before, sha256(&wing));

    let check_daed = Command::new(binary())
        .args(["state", "check", "--state"])
        .arg(&daed)
        .output()
        .unwrap();
    assert!(check_daed.status.success());
    let report: Value = serde_json::from_slice(&check_daed.stdout).unwrap();
    assert!(report["schema_ready"].as_bool().unwrap());

    fs::remove_dir_all(temp).unwrap();
}
