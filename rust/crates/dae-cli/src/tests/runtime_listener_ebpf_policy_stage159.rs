use super::*;

#[test]
fn stage159_listener_ebpf_policy_fixture_matches() {
    let fixture = load(
        "engine/runtime_stage159/production_listener_ebpf_benchmark_preflight_policy_gate.json",
    );
    let output = run_with_args([
        "runtime",
        "stage159-production-listener-ebpf-benchmark-preflight-policy-gate",
    ]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();

    assert_eq!(json, fixture);
    assert!(json["blocked"].as_bool().unwrap());
    assert!(
        json["production_equivalent_benchmark_policy_recorded"]
            .as_bool()
            .unwrap()
    );
    assert!(json["namespace_isolation_required"].as_bool().unwrap());
    assert!(json["temporary_bpf_pin_required"].as_bool().unwrap());
    assert!(!json["production_listener_bound"].as_bool().unwrap());
    assert!(!json["ebpf_attached"].as_bool().unwrap());
}

#[test]
fn stage159_runtime_rejects_bad_args() {
    let output = run_with_args([
        "runtime",
        "stage159-production-listener-ebpf-benchmark-preflight-policy-gate",
        "--bad",
    ]);
    assert_ne!(output.exit_code, 0);
    assert!(output.stderr.contains("unsupported stage159 argument"));
}
