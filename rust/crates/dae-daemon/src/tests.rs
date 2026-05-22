use serde_json::Value;

use crate::{
    Stage156DefaultRunIdentityOptions, daemon_identity, run_with_args_and_version,
    stage149_identity_preflight_report, stage150_lifecycle_smoke_report,
    stage151_control_plane_owner_preflight_report, stage152_signal_control_plane_smoke_report,
    stage153_run_entrypoint_preflight_report, stage156_default_run_identity_admission_report,
};

#[test]
fn daemon_identity_is_opt_in_and_not_default() {
    let report = daemon_identity("test-version");
    assert_eq!(report["name"].as_str().unwrap(), "dae-daemon-optin");
    assert_eq!(report["crate"].as_str().unwrap(), "dae-daemon");
    assert_eq!(report["version"].as_str().unwrap(), "test-version");
    assert!(report["rust_daemon_identity_scaffolded"].as_bool().unwrap());
    assert!(
        report["rust_daemon_crate_manifest_exists"]
            .as_bool()
            .unwrap()
    );
    assert!(report["rust_daemon_optin_binary_exists"].as_bool().unwrap());
    assert!(
        !report["rust_default_run_entrypoint_exists"]
            .as_bool()
            .unwrap()
    );
    assert!(!report["default_switch_allowed"].as_bool().unwrap());
}

#[test]
fn stage149_preflight_keeps_benchmark_closed() {
    let report = stage149_identity_preflight_report("test-version");
    assert!(report["rust_daemon_identity_scaffolded"].as_bool().unwrap());
    assert!(
        !report["rust_daemon_lifecycle_smoke_passed"]
            .as_bool()
            .unwrap()
    );
    assert!(!report["benchmark_executable_now"].as_bool().unwrap());
    assert!(
        !report["matched_go_rust_default_daemon_benchmark_recorded"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !report["true_rust_default_daemon_admitted"]
            .as_bool()
            .unwrap()
    );
}

#[test]
fn daemon_runner_identity_command_outputs_json() {
    let output = run_with_args_and_version(["identity"], "test-version");
    assert_eq!(output.exit_code, 0, "{}", output.stderr);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();
    assert_eq!(json["name"].as_str().unwrap(), "dae-daemon-optin");
    assert_eq!(json["version"].as_str().unwrap(), "test-version");
}

#[test]
fn daemon_runner_rejects_default_run_command() {
    let output = run_with_args_and_version(["run"], "test-version");
    assert_eq!(output.exit_code, 2);
    assert!(
        output
            .stderr
            .contains("unsupported dae-daemon-optin command")
    );
}

#[test]
fn stage150_lifecycle_smoke_uses_isolated_paths() {
    let root =
        std::env::temp_dir().join(format!("dae-stage150-daemon-test-{}", std::process::id()));
    let report = stage150_lifecycle_smoke_report(&root).unwrap();
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
    assert!(!report["default_switch_allowed"].as_bool().unwrap());
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn daemon_runner_stage150_lifecycle_command_outputs_json() {
    let root =
        std::env::temp_dir().join(format!("dae-stage150-runner-test-{}", std::process::id()));
    let output = run_with_args_and_version(
        [
            "stage150-lifecycle-smoke".to_owned(),
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
fn stage151_control_plane_owner_preflight_uses_isolated_paths() {
    let root =
        std::env::temp_dir().join(format!("dae-stage151-daemon-test-{}", std::process::id()));
    let report = stage151_control_plane_owner_preflight_report(&root).unwrap();
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
        report["control_plane_rollback_sequence_recorded"]
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
    assert!(!report["default_switch_allowed"].as_bool().unwrap());
    assert_eq!(report["reload_core"]["flip"].as_u64().unwrap(), 1);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn daemon_runner_stage151_control_plane_owner_command_outputs_json() {
    let root =
        std::env::temp_dir().join(format!("dae-stage151-runner-test-{}", std::process::id()));
    let output = run_with_args_and_version(
        [
            "stage151-control-plane-owner-preflight".to_owned(),
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
        !json["rust_default_control_plane_entrypoint_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["production_listener_bound"].as_bool().unwrap());
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn stage152_signal_control_plane_smoke_uses_isolated_paths() {
    let root =
        std::env::temp_dir().join(format!("dae-stage152-daemon-test-{}", std::process::id()));
    let report = stage152_signal_control_plane_smoke_report(&root).unwrap();
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
    assert!(!report["default_switch_allowed"].as_bool().unwrap());
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn daemon_runner_stage152_signal_control_plane_command_outputs_json() {
    let root =
        std::env::temp_dir().join(format!("dae-stage152-runner-test-{}", std::process::id()));
    let output = run_with_args_and_version(
        [
            "stage152-signal-control-plane-smoke".to_owned(),
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
        !json["rust_default_control_plane_entrypoint_admitted"]
            .as_bool()
            .unwrap()
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn stage153_run_entrypoint_preflight_composes_prior_smokes() {
    let root =
        std::env::temp_dir().join(format!("dae-stage153-daemon-test-{}", std::process::id()));
    let report = stage153_run_entrypoint_preflight_report(&root).unwrap();
    assert!(
        report["non_default_run_entrypoint_wrapper_available"]
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
    assert!(
        report["go_default_run_command_preserved"]
            .as_bool()
            .unwrap()
    );
    assert!(!report["production_run_command_replaced"].as_bool().unwrap());
    assert!(
        !report["rust_default_run_entrypoint_exists"]
            .as_bool()
            .unwrap()
    );
    assert!(!report["default_switch_allowed"].as_bool().unwrap());
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn daemon_runner_stage153_run_entrypoint_command_outputs_json() {
    let root =
        std::env::temp_dir().join(format!("dae-stage153-runner-test-{}", std::process::id()));
    let output = run_with_args_and_version(
        [
            "stage153-run-entrypoint-preflight".to_owned(),
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
    assert!(!json["production_run_command_replaced"].as_bool().unwrap());
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn stage156_default_run_identity_admits_optin_identity_only() {
    let root =
        std::env::temp_dir().join(format!("dae-stage156-daemon-test-{}", std::process::id()));
    let opts = Stage156DefaultRunIdentityOptions::under_root(&root);
    let report = stage156_default_run_identity_admission_report(&opts).unwrap();
    assert!(
        report["rust_default_run_identity_optin_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["rust_default_run_entrypoint_exists"]
            .as_bool()
            .unwrap()
    );
    assert!(report["config_corpus_loaded"].as_bool().unwrap());
    assert!(
        report["isolated_pid_progress_paths_validated"]
            .as_bool()
            .unwrap()
    );
    assert!(!report["production_run_command_replaced"].as_bool().unwrap());
    assert!(
        !report["rust_default_control_plane_entrypoint_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!report["benchmark_executable_now"].as_bool().unwrap());
    assert!(!report["default_switch_allowed"].as_bool().unwrap());
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn daemon_runner_stage156_default_run_identity_command_outputs_json() {
    let root =
        std::env::temp_dir().join(format!("dae-stage156-runner-test-{}", std::process::id()));
    let output = run_with_args_and_version(
        [
            "stage156-default-run-identity-admission".to_owned(),
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
    assert!(
        json["rust_default_run_identity_optin_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(json["run_shaped_flags_validated"].as_bool().unwrap());
    assert!(json["stage153_wrapper_reused"].as_bool().unwrap());
    assert!(
        json["stage153_wrapper"]["run_entrypoint_wrapper_composed"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["production_listener_bound"].as_bool().unwrap());
    let _ = std::fs::remove_dir_all(root);
}
