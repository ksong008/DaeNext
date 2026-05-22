use super::*;

#[test]
fn stage151_control_plane_owner_read_only_fixture_matches() {
    let fixture = load("engine/runtime_stage151/rust_control_plane_owner_preflight_gate.json");
    let output = run_with_args([
        "runtime",
        "stage151-rust-control-plane-owner-preflight-gate",
    ]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();

    assert_eq!(json, fixture);
    assert!(
        json["rust_control_plane_owner_preflight_recorded"]
            .as_bool()
            .unwrap()
    );
    assert!(
        json["control_plane_reload_owner_sequence_recorded"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["rust_control_plane_owner_smoke_passed"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["production_listener_bound"].as_bool().unwrap());
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
}

#[test]
fn stage151_control_plane_owner_execute_smoke_uses_isolated_paths() {
    let root = format!("/tmp/dae-stage151-cli-test-{}", std::process::id());
    let output = run_with_args([
        "runtime",
        "stage151-rust-control-plane-owner-preflight-gate",
        "--execute-smoke",
        "--root",
        &root,
    ]);
    assert_eq!(output.exit_code, 0, "{}", output.stderr);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();
    assert!(json["execute_smoke"].as_bool().unwrap());
    assert!(
        json["rust_control_plane_owner_smoke_passed"]
            .as_bool()
            .unwrap()
    );
    assert!(
        json["isolated_control_plane_owner_paths_validated"]
            .as_bool()
            .unwrap()
    );
    assert!(
        json["smoke"]["listener_reuse_contract_recorded"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["smoke"]["ebpf_attached"].as_bool().unwrap());
    assert_eq!(json["smoke"]["root"].as_str().unwrap(), root);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn stage151_runtime_rejects_bad_args() {
    let output = run_with_args([
        "runtime",
        "stage151-rust-control-plane-owner-preflight-gate",
        "--bad",
    ]);
    assert_ne!(output.exit_code, 0);
    assert!(output.stderr.contains("unsupported stage151 argument"));
}
