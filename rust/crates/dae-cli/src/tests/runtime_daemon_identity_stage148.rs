use super::*;

#[test]
fn stage148_daemon_identity_preflight_fixture_matches() {
    let fixture = load("engine/runtime_stage148/rust_daemon_identity_preflight_gate.json");
    let output = run_with_args(["runtime", "stage148-rust-daemon-identity-preflight-gate"]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();

    assert_eq!(json, fixture);
    assert!(json["blocked"].as_bool().unwrap());
    assert!(
        json["rust_daemon_identity_preflight_recorded"]
            .as_bool()
            .unwrap()
    );
    assert!(
        json["go_default_daemon_identity_preserved"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["rust_daemon_crate_manifest_exists"].as_bool().unwrap());
    assert!(!json["true_rust_daemon_binary_exists"].as_bool().unwrap());
    assert!(!json["benchmark_executable_now"].as_bool().unwrap());
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
}

#[test]
fn stage148_runtime_rejects_extra_args() {
    let output = run_with_args([
        "runtime",
        "stage148-rust-daemon-identity-preflight-gate",
        "--execute-smoke",
    ]);
    assert_ne!(output.exit_code, 0);
    assert!(output.stderr.contains("unsupported stage148 argument"));
}
