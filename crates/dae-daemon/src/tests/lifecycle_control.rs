use super::*;
#[test]
pub(super) fn lifecycle_smoke_uses_isolated_paths() {
    let root = std::env::temp_dir().join(format!(
        "dae-lifecycle-smoke-daemon-test-{}",
        std::process::id()
    ));
    let report = lifecycle_smoke_report(&root).unwrap();
    assert!(
        report["rust_daemon_lifecycle_smoke_passed"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["isolated_pid_progress_paths_validated"]
            .as_bool()
            .unwrap()
    );
    assert!(!report["production_paths_mutated"].as_bool().unwrap());
    assert!(!report["benchmark_executable_now"].as_bool().unwrap());
    assert!(!report["production_admission_allowed"].as_bool().unwrap());
    let _ = std::fs::remove_dir_all(root);
}

#[test]
pub(super) fn daemon_runner_lifecycle_smoke_command_outputs_json() {
    let root = std::env::temp_dir().join(format!(
        "dae-lifecycle-smoke-runner-test-{}",
        std::process::id()
    ));
    let output = run_with_args_and_version(
        [
            "lifecycle-smoke".to_owned(),
            "--root".to_owned(),
            root.display().to_string(),
        ],
        "test-version",
    );
    assert_eq!(output.exit_code, 0, "{}", output.stderr);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();
    assert!(
        json["rust_daemon_lifecycle_smoke_passed"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["production_paths_mutated"].as_bool().unwrap());
    let _ = std::fs::remove_dir_all(root);
}

#[test]
pub(super) fn control_plane_owner_preflight_uses_isolated_paths() {
    let root = std::env::temp_dir().join(format!(
        "dae-control-plane-owner-daemon-test-{}",
        std::process::id()
    ));
    let report = control_plane_owner_preflight_report(&root).unwrap();
    assert!(
        report["rust_control_plane_owner_preflight_recorded"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["control_plane_startup_sequence_recorded"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["control_plane_reload_owner_sequence_recorded"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["control_plane_restore_sequence_recorded"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["listener_reuse_contract_recorded"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["dns_cache_migration_guard_recorded"]
            .as_bool()
            .unwrap()
    );
    assert!(!report["production_listener_bound"].as_bool().unwrap());
    assert!(!report["ebpf_attached"].as_bool().unwrap());
    assert!(!report["production_admission_allowed"].as_bool().unwrap());
    assert_eq!(report["reload_core"]["flip"].as_u64().unwrap(), 1);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
pub(super) fn daemon_runner_control_plane_owner_command_outputs_json() {
    let root = std::env::temp_dir().join(format!(
        "dae-control-plane-owner-runner-test-{}",
        std::process::id()
    ));
    let output = run_with_args_and_version(
        [
            "control-plane-owner-preflight".to_owned(),
            "--root".to_owned(),
            root.display().to_string(),
        ],
        "test-version",
    );
    assert_eq!(output.exit_code, 0, "{}", output.stderr);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();
    assert!(
        json["rust_control_plane_owner_smoke_passed"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["rust_control_plane_entrypoint_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["production_listener_bound"].as_bool().unwrap());
    let _ = std::fs::remove_dir_all(root);
}

#[test]
pub(super) fn signal_control_plane_smoke_uses_isolated_paths() {
    let root = std::env::temp_dir().join(format!(
        "dae-signal-control-plane-daemon-test-{}",
        std::process::id()
    ));
    let report = signal_control_plane_smoke_report(&root).unwrap();
    assert!(
        report["rust_signal_control_plane_smoke_passed"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["reload_signal_progress_owner_sequence_validated"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["suspend_signal_progress_sequence_validated"]
            .as_bool()
            .unwrap()
    );
    assert!(report["abort_file_one_shot_consumed"].as_bool().unwrap());
    assert!(report["isolated_pid_removed_on_stop"].as_bool().unwrap());
    assert!(
        !report["production_signal_handler_installed"]
            .as_bool()
            .unwrap()
    );
    assert!(!report["production_listener_bound"].as_bool().unwrap());
    assert!(!report["ebpf_attached"].as_bool().unwrap());
    assert!(!report["production_admission_allowed"].as_bool().unwrap());
    let _ = std::fs::remove_dir_all(root);
}

#[test]
pub(super) fn daemon_runner_signal_control_plane_command_outputs_json() {
    let root = std::env::temp_dir().join(format!(
        "dae-signal-control-plane-runner-test-{}",
        std::process::id()
    ));
    let output = run_with_args_and_version(
        [
            "signal-control-plane-smoke".to_owned(),
            "--root".to_owned(),
            root.display().to_string(),
        ],
        "test-version",
    );
    assert_eq!(output.exit_code, 0, "{}", output.stderr);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();
    assert!(
        json["rust_signal_control_plane_smoke_passed"]
            .as_bool()
            .unwrap()
    );
    assert!(
        json["owner"]["rust_control_plane_owner_smoke_passed"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["rust_control_plane_entrypoint_admitted"]
            .as_bool()
            .unwrap()
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
pub(super) fn run_entrypoint_preflight_composes_prior_smokes() {
    let root = std::env::temp_dir().join(format!(
        "dae-run-entrypoint-daemon-test-{}",
        std::process::id()
    ));
    let report = run_entrypoint_preflight_report(&root).unwrap();
    assert!(
        report["run_entrypoint_wrapper_available"]
            .as_bool()
            .unwrap()
    );
    assert!(report["run_entrypoint_wrapper_composed"].as_bool().unwrap());
    assert!(
        report["run_entrypoint_lifecycle_smoke_reused"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["run_entrypoint_signal_control_plane_smoke_reused"]
            .as_bool()
            .unwrap()
    );
    assert!(report["rust_run_command_owned"].as_bool().unwrap());
    assert!(report["production_run_command_owned"].as_bool().unwrap());
    assert!(report["rust_run_entrypoint_exists"].as_bool().unwrap());
    assert!(!report["production_admission_allowed"].as_bool().unwrap());
    let _ = std::fs::remove_dir_all(root);
}

#[test]
pub(super) fn daemon_runner_run_entrypoint_command_outputs_json() {
    let root = std::env::temp_dir().join(format!(
        "dae-run-entrypoint-runner-test-{}",
        std::process::id()
    ));
    let output = run_with_args_and_version(
        [
            "run-entrypoint-preflight".to_owned(),
            "--root".to_owned(),
            root.display().to_string(),
        ],
        "test-version",
    );
    assert_eq!(output.exit_code, 0, "{}", output.stderr);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();
    assert!(json["run_entrypoint_wrapper_composed"].as_bool().unwrap());
    assert!(
        json["composed_smokes"]["lifecycle"]["rust_daemon_lifecycle_smoke_passed"]
            .as_bool()
            .unwrap()
    );
    assert!(
        json["composed_smokes"]["signal_control_plane"]["rust_signal_control_plane_smoke_passed"]
            .as_bool()
            .unwrap()
    );
    assert!(json["production_run_command_owned"].as_bool().unwrap());
    let _ = std::fs::remove_dir_all(root);
}

#[test]
pub(super) fn product_run_identity_admits_runtime_identity_only() {
    let root = std::env::temp_dir().join(format!(
        "dae-product-run-identity-daemon-test-{}",
        std::process::id()
    ));
    let opts = ProductRunIdentityAdmissionOptions::under_root(&root);
    let report = product_run_identity_admission_report(&opts).unwrap();
    assert!(report["rust_run_identity_admitted"].as_bool().unwrap());
    assert!(report["rust_run_entrypoint_exists"].as_bool().unwrap());
    assert!(report["config_corpus_loaded"].as_bool().unwrap());
    assert!(
        report["isolated_pid_progress_paths_validated"]
            .as_bool()
            .unwrap()
    );
    assert!(!report["production_run_command_owned"].as_bool().unwrap());
    assert!(
        !report["rust_control_plane_entrypoint_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!report["benchmark_executable_now"].as_bool().unwrap());
    assert!(!report["production_admission_allowed"].as_bool().unwrap());
    let _ = std::fs::remove_dir_all(root);
}

#[test]
pub(super) fn daemon_runner_product_run_identity_command_outputs_json() {
    let root = std::env::temp_dir().join(format!(
        "dae-product-run-identity-runner-test-{}",
        std::process::id()
    ));
    let output = run_with_args_and_version(
        [
            "product-run-identity-admission".to_owned(),
            "--root".to_owned(),
            root.display().to_string(),
            "--disable-timestamp".to_owned(),
            "--disable-sudo".to_owned(),
        ],
        "test-version",
    );
    assert_eq!(output.exit_code, 0, "{}", output.stderr);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();
    assert!(json["rust_run_identity_admitted"].as_bool().unwrap());
    assert!(json["run_shaped_flags_validated"].as_bool().unwrap());
    assert!(json["run_entrypoint_wrapper_reused"].as_bool().unwrap());
    assert!(
        json["run_entrypoint_wrapper"]["run_entrypoint_wrapper_composed"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["production_listener_bound"].as_bool().unwrap());
    let _ = std::fs::remove_dir_all(root);
}

#[test]
pub(super) fn control_plane_entrypoint_admits_runtime_contract_only() {
    let root = std::env::temp_dir().join(format!(
        "dae-control-plane-entrypoint-daemon-test-{}",
        std::process::id()
    ));
    let report = control_plane_entrypoint_admission_report(&root).unwrap();
    assert!(
        report["control_plane_entrypoint_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(report["rust_run_entrypoint_exists"].as_bool().unwrap());
    assert!(
        report["rust_control_plane_entrypoint_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(report["run_identity_admission_reused"].as_bool().unwrap());
    assert!(
        report["control_plane_owner_preflight_reused"]
            .as_bool()
            .unwrap()
    );
    assert!(!report["production_listener_bound"].as_bool().unwrap());
    assert!(!report["ebpf_attached"].as_bool().unwrap());
    assert!(!report["benchmark_executable_now"].as_bool().unwrap());
    assert!(!report["production_admission_allowed"].as_bool().unwrap());
    let _ = std::fs::remove_dir_all(root);
}

#[test]
pub(super) fn daemon_runner_control_plane_entrypoint_command_outputs_json() {
    let root = std::env::temp_dir().join(format!(
        "dae-control-plane-entrypoint-runner-test-{}",
        std::process::id()
    ));
    let output = run_with_args_and_version(
        [
            "control-plane-entrypoint-admission".to_owned(),
            "--root".to_owned(),
            root.display().to_string(),
        ],
        "test-version",
    );
    assert_eq!(output.exit_code, 0, "{}", output.stderr);
    let json: Value = serde_json::from_str(&output.stdout).unwrap();
    assert!(json["control_plane_entrypoint_admitted"].as_bool().unwrap());
    assert!(
        json["control_plane_owner"]["rust_control_plane_owner_smoke_passed"]
            .as_bool()
            .unwrap()
    );
    assert!(
        json["run_identity"]["rust_run_identity_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["true_rust_native_daemon_admitted"].as_bool().unwrap());
    let _ = std::fs::remove_dir_all(root);
}
