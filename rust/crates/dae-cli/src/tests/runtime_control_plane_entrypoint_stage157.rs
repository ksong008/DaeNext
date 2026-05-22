use super::*;

#[test]
fn stage157_control_plane_entrypoint_read_only_fixture_matches() {
    let fixture = load("engine/runtime_stage157/control_plane_entrypoint_admission_gate.json");
    let output = run_with_args([
        "runtime",
        "stage157-control-plane-entrypoint-admission-gate",
    ]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    let json: Value = serde_json::from_str(&output.stdout).unwrap();

    assert_eq!(json, fixture);
    assert!(
        json["control_plane_entrypoint_harness_available"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["execute_smoke"].as_bool().unwrap());
    assert!(
        !json["rust_default_control_plane_entrypoint_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
}

#[test]
fn stage157_control_plane_entrypoint_execute_smoke_admits_contract() {
    let root = std::env::temp_dir().join(format!("dae-stage157-cli-test-{}", std::process::id()));
    let output = run_with_args([
        "runtime",
        "stage157-control-plane-entrypoint-admission-gate",
        "--execute-smoke",
        "--root",
        root.to_str().unwrap(),
    ]);
    assert_eq!(output.exit_code, 0, "{}", output.stderr);
    let json: Value = serde_json::from_str(&output.stdout).unwrap();
    assert!(json["execute_smoke"].as_bool().unwrap());
    assert!(
        json["control_plane_entrypoint_optin_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        json["rust_default_control_plane_entrypoint_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(json["stage156_run_identity_reused"].as_bool().unwrap());
    assert!(json["stage151_owner_preflight_reused"].as_bool().unwrap());
    assert!(!json["production_listener_bound"].as_bool().unwrap());
    assert!(!json["ebpf_attached"].as_bool().unwrap());
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn stage157_runtime_rejects_bad_args() {
    let output = run_with_args([
        "runtime",
        "stage157-control-plane-entrypoint-admission-gate",
        "--bad",
    ]);
    assert_ne!(output.exit_code, 0);
    assert!(output.stderr.contains("unsupported stage157 argument"));
}
