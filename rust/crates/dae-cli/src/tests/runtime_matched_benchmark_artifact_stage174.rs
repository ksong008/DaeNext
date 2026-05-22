use super::*;

#[test]
fn stage174_real_corpus_materialization_queue_fixture_matches() {
    let fixture = load(
        "engine/runtime_stage174/matched_benchmark_real_corpus_materialization_queue_gate.json",
    );
    let output = run_with_args([
        "runtime",
        "stage174-matched-benchmark-real-corpus-materialization-queue-gate",
    ]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();

    assert_eq!(json, fixture);
    assert!(
        json["real_corpus_materialization_queue_recorded"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["real_benchmark_corpus_materialized"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["go_default_daemon_executed"].as_bool().unwrap());
}

#[test]
fn stage174_runtime_rejects_extra_args() {
    let output = run_with_args([
        "runtime",
        "stage174-matched-benchmark-real-corpus-materialization-queue-gate",
        "--bad",
    ]);
    assert_ne!(output.exit_code, 0);
    assert!(output.stderr.contains("unsupported stage174 argument"));
}
