use super::*;

#[test]
fn stage150_daemon_lifecycle_read_only_fixture_matches() {
    let fixture = load("engine/runtime_stage150/rust_daemon_lifecycle_smoke_gate.json");
    let output = run_with_args(["runtime", "stage150-rust-daemon-lifecycle-smoke-gate"]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();

    assert_eq!(json, fixture);
    assert!(
        json["rust_daemon_lifecycle_smoke_harness_available"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["rust_daemon_lifecycle_smoke_passed"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["production_paths_mutated"].as_bool().unwrap());
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
}

#[test]
fn stage150_daemon_lifecycle_execute_smoke_uses_isolated_paths() {
    let root = format!("/tmp/dae-stage150-cli-test-{}", std::process::id());
    let output = run_with_args([
        "runtime",
        "stage150-rust-daemon-lifecycle-smoke-gate",
        "--execute-smoke",
        "--root",
        &root,
    ]);
    assert_eq!(output.exit_code, 0, "{}", output.stderr);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();
    assert!(json["execute_smoke"].as_bool().unwrap());
    assert!(
        json["rust_daemon_lifecycle_smoke_passed"]
            .as_bool()
            .unwrap()
    );
    assert!(
        json["isolated_pid_progress_paths_validated"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["production_paths_mutated"].as_bool().unwrap());
    assert_eq!(json["smoke"]["root"].as_str().unwrap(), root);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn stage150_runtime_rejects_bad_args() {
    let output = run_with_args([
        "runtime",
        "stage150-rust-daemon-lifecycle-smoke-gate",
        "--bad",
    ]);
    assert_ne!(output.exit_code, 0);
    assert!(output.stderr.contains("unsupported stage150 argument"));
}
