use super::*;

#[test]
fn stage152_signal_control_plane_read_only_fixture_matches() {
    let fixture = load("engine/runtime_stage152/rust_signal_control_plane_smoke_gate.json");
    let output = run_with_args(["runtime", "stage152-rust-signal-control-plane-smoke-gate"]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();

    assert_eq!(json, fixture);
    assert!(
        json["signal_control_plane_smoke_harness_available"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["rust_signal_control_plane_smoke_passed"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["production_signal_handler_installed"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
}

#[test]
fn stage152_signal_control_plane_execute_smoke_uses_isolated_paths() {
    let root = format!("/tmp/dae-stage152-cli-test-{}", std::process::id());
    let output = run_with_args([
        "runtime",
        "stage152-rust-signal-control-plane-smoke-gate",
        "--execute-smoke",
        "--root",
        &root,
    ]);
    assert_eq!(output.exit_code, 0, "{}", output.stderr);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();
    assert!(json["execute_smoke"].as_bool().unwrap());
    assert!(
        json["rust_signal_control_plane_smoke_passed"]
            .as_bool()
            .unwrap()
    );
    assert!(
        json["reload_signal_progress_owner_sequence_validated"]
            .as_bool()
            .unwrap()
    );
    assert!(
        json["suspend_signal_progress_sequence_validated"]
            .as_bool()
            .unwrap()
    );
    assert!(json["abort_file_one_shot_consumed"].as_bool().unwrap());
    assert!(
        json["smoke"]["isolated_pid_removed_on_stop"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(json["smoke"]["root"].as_str().unwrap(), root);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn stage152_runtime_rejects_bad_args() {
    let output = run_with_args([
        "runtime",
        "stage152-rust-signal-control-plane-smoke-gate",
        "--bad",
    ]);
    assert_ne!(output.exit_code, 0);
    assert!(output.stderr.contains("unsupported stage152 argument"));
}
