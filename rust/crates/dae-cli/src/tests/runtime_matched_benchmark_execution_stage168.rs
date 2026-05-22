use super::*;

#[test]
fn stage168_matched_benchmark_execution_fixture_matches() {
    let fixture =
        load("engine/runtime_stage168/matched_default_daemon_benchmark_execution_gate.json");
    let output = run_with_args([
        "runtime",
        "stage168-matched-default-daemon-benchmark-execution-gate",
    ]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();

    assert_eq!(json, fixture);
    assert!(json["blocked"].as_bool().unwrap());
    assert!(json["stage167_bounded_metrics_carried"].as_bool().unwrap());
    assert!(
        !json["matched_go_rust_default_daemon_benchmark_recorded"]
            .as_bool()
            .unwrap()
    );
}

#[test]
fn stage168_runtime_rejects_bad_args() {
    let output = run_with_args([
        "runtime",
        "stage168-matched-default-daemon-benchmark-execution-gate",
        "--bad",
    ]);
    assert_ne!(output.exit_code, 0);
    assert!(output.stderr.contains("unsupported stage168 argument"));
}
