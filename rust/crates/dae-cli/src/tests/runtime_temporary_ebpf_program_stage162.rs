use super::*;

#[test]
fn stage162_temporary_ebpf_program_fixture_matches() {
    let fixture = load("engine/runtime_stage162/temporary_ebpf_program_attach_preflight_gate.json");
    let output = run_with_args([
        "runtime",
        "stage162-temporary-ebpf-program-attach-preflight-gate",
    ]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();

    assert_eq!(json, fixture);
    assert!(json["blocked"].as_bool().unwrap());
    assert!(
        json["temporary_ebpf_program_attach_harness_available"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["production_tc_attach_smoke_passed"].as_bool().unwrap());
}

#[test]
fn stage162_temporary_ebpf_program_execute_smoke_is_environment_aware() {
    let output = run_with_args([
        "runtime",
        "stage162-temporary-ebpf-program-attach-preflight-gate",
        "--execute-smoke",
    ]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();
    assert!(json["execute_smoke"].as_bool().unwrap());
    if json["temporary_ebpf_program_load_smoke_passed"]
        .as_bool()
        .unwrap()
    {
        assert!(
            json["temporary_ebpf_socket_attach_smoke_passed"]
                .as_bool()
                .unwrap()
        );
        assert!(
            json["temporary_ebpf_socket_detach_cleanup_smoke_passed"]
                .as_bool()
                .unwrap()
        );
        assert_eq!(json["smoke"]["instruction_count"].as_u64().unwrap(), 2);
    } else {
        assert!(json["smoke_error"].as_str().is_some());
    }
    assert!(!json["production_tc_attach_smoke_passed"].as_bool().unwrap());
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
}

#[test]
fn stage162_runtime_rejects_bad_args() {
    let output = run_with_args([
        "runtime",
        "stage162-temporary-ebpf-program-attach-preflight-gate",
        "--bad",
    ]);
    assert_ne!(output.exit_code, 0);
    assert!(output.stderr.contains("unsupported stage162 argument"));
}
