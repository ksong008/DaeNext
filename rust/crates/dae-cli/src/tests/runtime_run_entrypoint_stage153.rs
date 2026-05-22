use super::*;

#[test]
fn stage153_run_entrypoint_read_only_fixture_matches() {
    let fixture = load("engine/runtime_stage153/rust_run_entrypoint_preflight_gate.json");
    let output = run_with_args(["runtime", "stage153-rust-run-entrypoint-preflight-gate"]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();

    assert_eq!(json, fixture);
    assert!(
        json["run_entrypoint_preflight_harness_available"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["run_entrypoint_wrapper_composed"].as_bool().unwrap());
    assert!(
        !json["rust_default_run_entrypoint_exists"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
}

#[test]
fn stage153_run_entrypoint_execute_smoke_composes_prior_smokes() {
    let root = format!("/tmp/dae-stage153-cli-test-{}", std::process::id());
    let output = run_with_args([
        "runtime",
        "stage153-rust-run-entrypoint-preflight-gate",
        "--execute-smoke",
        "--root",
        &root,
    ]);
    assert_eq!(output.exit_code, 0, "{}", output.stderr);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();
    assert!(json["execute_smoke"].as_bool().unwrap());
    assert!(json["run_entrypoint_wrapper_composed"].as_bool().unwrap());
    assert!(
        json["smoke"]["composed_smokes"]["lifecycle"]["rust_daemon_lifecycle_smoke_passed"]
            .as_bool()
            .unwrap()
    );
    assert!(
        json["smoke"]["composed_smokes"]["signal_control_plane"]
            ["rust_signal_control_plane_smoke_passed"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["production_run_command_replaced"].as_bool().unwrap());
    assert_eq!(json["smoke"]["root"].as_str().unwrap(), root);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn stage153_runtime_rejects_bad_args() {
    let output = run_with_args([
        "runtime",
        "stage153-rust-run-entrypoint-preflight-gate",
        "--bad",
    ]);
    assert_ne!(output.exit_code, 0);
    assert!(output.stderr.contains("unsupported stage153 argument"));
}
