use super::*;

#[test]
fn stage167_bounded_benchmark_harness_fixture_matches() {
    let fixture = load("engine/runtime_stage167/bounded_listener_ebpf_benchmark_harness_gate.json");
    let output = run_with_args([
        "runtime",
        "stage167-bounded-production-equivalent-listener-ebpf-benchmark-harness-gate",
    ]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();

    assert_eq!(json, fixture);
    assert!(
        json["bounded_production_equivalent_benchmark_harness_available"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["matched_go_rust_default_daemon_benchmark_recorded"]
            .as_bool()
            .unwrap()
    );
}

#[test]
fn stage167_bounded_benchmark_execute_records_metrics() {
    let root = std::env::temp_dir().join(format!(
        "dae-stage167-cli-test-{}-benchmark",
        std::process::id()
    ));
    let output = run_with_args([
        "runtime",
        "stage167-bounded-production-equivalent-listener-ebpf-benchmark-harness-gate",
        "--execute-benchmark",
        "--iterations",
        "2",
        "--root",
        &root.display().to_string(),
    ]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();
    assert!(json["bounded_benchmark_executable_now"].as_bool().unwrap());
    assert_eq!(json["benchmark"]["iterations"].as_u64().unwrap(), 2);
    assert!(json["benchmark"]["total_elapsed_ns"].as_u64().unwrap() > 0);
    assert!(
        !json["matched_go_rust_default_daemon_benchmark_recorded"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn stage167_runtime_rejects_bad_args() {
    let output = run_with_args([
        "runtime",
        "stage167-bounded-production-equivalent-listener-ebpf-benchmark-harness-gate",
        "--bad",
    ]);
    assert_ne!(output.exit_code, 0);
    assert!(output.stderr.contains("unsupported stage167 argument"));
}
