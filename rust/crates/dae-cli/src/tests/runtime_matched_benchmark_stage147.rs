use super::*;

#[test]
fn stage147_matched_benchmark_readiness_fixture_matches() {
    let fixture =
        load("engine/runtime_stage147/matched_default_daemon_benchmark_readiness_gate.json");
    let output = run_with_args([
        "runtime",
        "stage147-matched-default-daemon-benchmark-readiness-gate",
    ]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();

    assert_eq!(json, fixture);
    assert!(json["blocked"].as_bool().unwrap());
    assert!(
        json["matched_default_daemon_benchmark_plan_recorded"]
            .as_bool()
            .unwrap()
    );
    assert!(
        json["benchmark_corpus_manifest_recorded"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["benchmark_executable_now"].as_bool().unwrap());
    assert!(!json["true_rust_daemon_binary_exists"].as_bool().unwrap());
    assert!(
        !json["matched_go_rust_default_daemon_benchmark_recorded"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
}

#[test]
fn stage147_runtime_rejects_extra_args() {
    let output = run_with_args([
        "runtime",
        "stage147-matched-default-daemon-benchmark-readiness-gate",
        "--execute-benchmark",
    ]);
    assert_ne!(output.exit_code, 0);
    assert!(output.stderr.contains("unsupported stage147 argument"));
}
