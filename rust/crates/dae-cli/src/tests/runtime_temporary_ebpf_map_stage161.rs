use super::*;

#[test]
fn stage161_temporary_ebpf_map_fixture_matches() {
    let fixture = load("engine/runtime_stage161/temporary_ebpf_map_preflight_gate.json");
    let output = run_with_args(["runtime", "stage161-temporary-ebpf-map-preflight-gate"]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();

    assert_eq!(json, fixture);
    assert!(json["blocked"].as_bool().unwrap());
    assert!(
        json["temporary_ebpf_map_preflight_harness_available"]
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
fn stage161_temporary_ebpf_map_execute_smoke_is_environment_aware() {
    let output = run_with_args([
        "runtime",
        "stage161-temporary-ebpf-map-preflight-gate",
        "--execute-smoke",
    ]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();
    assert!(json["execute_smoke"].as_bool().unwrap());
    if json["temporary_ebpf_map_create_smoke_passed"]
        .as_bool()
        .unwrap()
    {
        assert!(
            json["temporary_ebpf_map_update_lookup_smoke_passed"]
                .as_bool()
                .unwrap()
        );
        assert!(
            json["temporary_ebpf_pin_reopen_smoke_passed"]
                .as_bool()
                .unwrap()
        );
        assert!(
            json["temporary_ebpf_pin_cleanup_smoke_passed"]
                .as_bool()
                .unwrap()
        );
        assert_eq!(json["smoke"]["value_read"].as_u64().unwrap(), 161);
        assert!(json["smoke"]["pin_removed"].as_bool().unwrap());
    } else {
        assert!(json["smoke_error"].as_str().is_some());
    }
    assert!(
        !json["temporary_ebpf_attach_smoke_passed"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
}

#[test]
fn stage161_runtime_rejects_bad_args() {
    let output = run_with_args([
        "runtime",
        "stage161-temporary-ebpf-map-preflight-gate",
        "--bad",
    ]);
    assert_ne!(output.exit_code, 0);
    assert!(output.stderr.contains("unsupported stage161 argument"));
}
