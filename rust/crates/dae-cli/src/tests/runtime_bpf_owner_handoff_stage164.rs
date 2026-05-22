use super::*;

#[test]
fn stage164_bpf_owner_handoff_smoke_fixture_matches() {
    let fixture =
        load("engine/runtime_stage164/non_production_bpf_owner_listener_handoff_smoke_gate.json");
    let output = run_with_args([
        "runtime",
        "stage164-non-production-bpf-owner-listener-handoff-smoke-gate",
    ]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();

    assert_eq!(json, fixture);
    assert!(json["blocked"].as_bool().unwrap());
    assert!(
        json["non_production_owner_handoff_harness_available"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["production_listener_bound"].as_bool().unwrap());
}

#[test]
fn stage164_bpf_owner_handoff_execute_smoke_is_environment_aware() {
    let output = run_with_args([
        "runtime",
        "stage164-non-production-bpf-owner-listener-handoff-smoke-gate",
        "--execute-smoke",
    ]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();
    if json["listen_socket_map_key_handoff_smoke_passed"]
        .as_bool()
        .unwrap()
    {
        assert_eq!(json["smoke"]["keys_updated"].as_array().unwrap().len(), 2);
        assert!(
            json["temporary_sockmap_cleanup_smoke_passed"]
                .as_bool()
                .unwrap()
        );
    } else {
        assert!(json["smoke_error"].as_str().is_some());
    }
    assert!(!json["production_tc_attach_smoke_passed"].as_bool().unwrap());
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
}

#[test]
fn stage164_runtime_rejects_bad_args() {
    let output = run_with_args([
        "runtime",
        "stage164-non-production-bpf-owner-listener-handoff-smoke-gate",
        "--bad",
    ]);
    assert_ne!(output.exit_code, 0);
    assert!(output.stderr.contains("unsupported stage164 argument"));
}
