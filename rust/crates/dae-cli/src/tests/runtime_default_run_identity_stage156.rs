use super::*;

#[test]
fn stage156_default_run_identity_read_only_fixture_matches() {
    let fixture = load("engine/runtime_stage156/rust_default_run_identity_admission_gate.json");
    let output = run_with_args([
        "runtime",
        "stage156-rust-default-run-identity-admission-gate",
    ]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();

    assert_eq!(json, fixture);
    assert!(
        json["rust_default_run_identity_harness_available"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["execute_smoke"].as_bool().unwrap());
    assert!(
        !json["rust_default_run_identity_optin_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
}

#[test]
fn stage156_default_run_identity_execute_smoke_admits_optin_identity() {
    let root = std::env::temp_dir().join(format!("dae-stage156-cli-test-{}", std::process::id()));
    let output = run_with_args([
        "runtime",
        "stage156-rust-default-run-identity-admission-gate",
        "--execute-smoke",
        "--root",
        root.to_str().unwrap(),
    ]);
    assert_eq!(output.exit_code, 0, "{}", output.stderr);
    let json: Value = serde_json::from_str(&output.stdout).unwrap();
    assert!(json["execute_smoke"].as_bool().unwrap());
    assert!(
        json["rust_default_run_identity_optin_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        json["rust_default_run_entrypoint_exists"]
            .as_bool()
            .unwrap()
    );
    assert!(json["config_corpus_loaded"].as_bool().unwrap());
    assert!(json["smoke"]["stage153_wrapper_reused"].as_bool().unwrap());
    assert!(
        !json["rust_default_control_plane_entrypoint_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn stage156_runtime_rejects_bad_args() {
    let output = run_with_args([
        "runtime",
        "stage156-rust-default-run-identity-admission-gate",
        "--bad",
    ]);
    assert_ne!(output.exit_code, 0);
    assert!(output.stderr.contains("unsupported stage156 argument"));
}
