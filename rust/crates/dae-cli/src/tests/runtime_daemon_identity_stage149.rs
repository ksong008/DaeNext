use super::*;

#[test]
fn stage149_daemon_identity_scaffold_fixture_matches() {
    let fixture = load("engine/runtime_stage149/rust_daemon_identity_scaffold_gate.json");
    let output = run_with_args(["runtime", "stage149-rust-daemon-identity-scaffold-gate"]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();

    assert_eq!(json, fixture);
    assert!(json["rust_daemon_identity_scaffolded"].as_bool().unwrap());
    assert!(json["rust_daemon_crate_manifest_exists"].as_bool().unwrap());
    assert!(json["rust_daemon_optin_binary_exists"].as_bool().unwrap());
    assert!(
        !json["rust_default_run_entrypoint_exists"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["benchmark_executable_now"].as_bool().unwrap());
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
}

#[test]
fn stage149_runtime_rejects_extra_args() {
    let output = run_with_args([
        "runtime",
        "stage149-rust-daemon-identity-scaffold-gate",
        "--execute-smoke",
    ]);
    assert_ne!(output.exit_code, 0);
    assert!(output.stderr.contains("unsupported stage149 argument"));
}
