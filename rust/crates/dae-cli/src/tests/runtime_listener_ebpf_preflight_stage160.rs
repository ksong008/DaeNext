use super::*;

#[test]
fn stage160_listener_ebpf_preflight_fixture_matches() {
    let fixture =
        load("engine/runtime_stage160/isolated_listener_ebpf_preflight_harness_gate.json");
    let output = run_with_args([
        "runtime",
        "stage160-isolated-listener-ebpf-preflight-harness-gate",
    ]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();

    assert_eq!(json, fixture);
    assert!(json["blocked"].as_bool().unwrap());
    assert!(
        json["isolated_listener_preflight_harness_available"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["tcp_udp_loopback_listener_smoke_passed"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["temporary_ebpf_attach_smoke_passed"]
            .as_bool()
            .unwrap()
    );
}

#[test]
fn stage160_listener_ebpf_preflight_execute_smoke_uses_temporary_scope() {
    let root = std::env::temp_dir().join(format!("dae-stage160-cli-test-{}", std::process::id()));
    let output = run_with_args([
        "runtime".to_owned(),
        "stage160-isolated-listener-ebpf-preflight-harness-gate".to_owned(),
        "--execute-smoke".to_owned(),
        "--root".to_owned(),
        root.display().to_string(),
    ]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();
    assert!(json["execute_smoke"].as_bool().unwrap());
    assert!(
        json["tcp_udp_loopback_listener_smoke_passed"]
            .as_bool()
            .unwrap()
    );
    assert!(json["temporary_bpf_pin_scope_validated"].as_bool().unwrap());
    assert!(json["rollback_cleanup_smoke_passed"].as_bool().unwrap());
    assert!(
        json["smoke"]["listener"]["tcp_udp_same_port"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["production_listener_bound"].as_bool().unwrap());
    assert!(!json["ebpf_attached"].as_bool().unwrap());
    assert!(
        !json["temporary_ebpf_attach_smoke_passed"]
            .as_bool()
            .unwrap()
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn stage160_runtime_rejects_bad_args() {
    let output = run_with_args([
        "runtime",
        "stage160-isolated-listener-ebpf-preflight-harness-gate",
        "--bad",
    ]);
    assert_ne!(output.exit_code, 0);
    assert!(output.stderr.contains("unsupported stage160 argument"));
}
