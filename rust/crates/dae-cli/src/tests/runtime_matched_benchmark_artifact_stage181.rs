use super::*;

#[test]
fn stage181_runtime_blocker_fixture_matches() {
    let fixture = load(
        "engine/runtime_stage181/matched_benchmark_reviewed_corpus_runtime_readiness_blocker_gate.json",
    );
    let output = run_with_args([
        "runtime",
        "stage181-matched-benchmark-reviewed-corpus-runtime-readiness-blocker-gate",
    ]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();

    assert_eq!(json, fixture);
    assert!(
        json["runtime_readiness_blocker_gate_recorded"]
            .as_bool()
            .unwrap()
    );
    assert!(json["stage180_queue_carried"].as_bool().unwrap());
    assert_eq!(json["blocker_groups"].as_array().unwrap().len(), 6);
    assert!(!json["reviewed_real_corpus_ready"].as_bool().unwrap());
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
}

#[test]
fn stage181_runtime_rejects_extra_args() {
    let output = run_with_args([
        "runtime",
        "stage181-matched-benchmark-reviewed-corpus-runtime-readiness-blocker-gate",
        "--bad",
    ]);
    assert_ne!(output.exit_code, 0);
    assert!(output.stderr.contains("unsupported stage181 argument"));
}
