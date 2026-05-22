use super::*;

#[test]
fn stage166_production_equivalent_benchmark_queue_fixture_matches() {
    let fixture = load(
        "engine/runtime_stage166/production_equivalent_listener_ebpf_benchmark_admission_queue_gate.json",
    );
    let output = run_with_args([
        "runtime",
        "stage166-production-equivalent-listener-ebpf-benchmark-admission-queue-gate",
    ]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();

    assert_eq!(json, fixture);
    assert!(json["blocked"].as_bool().unwrap());
    assert!(
        json["production_equivalent_benchmark_queue_recorded"]
            .as_bool()
            .unwrap()
    );
    assert!(
        json["stage165_reload_owner_handoff_smoke_carried"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["benchmark_executable_now"].as_bool().unwrap());
}

#[test]
fn stage166_runtime_rejects_bad_args() {
    let output = run_with_args([
        "runtime",
        "stage166-production-equivalent-listener-ebpf-benchmark-admission-queue-gate",
        "--bad",
    ]);
    assert_ne!(output.exit_code, 0);
    assert!(output.stderr.contains("unsupported stage166 argument"));
}
