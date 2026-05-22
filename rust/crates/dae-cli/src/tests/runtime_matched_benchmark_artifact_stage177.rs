use super::*;

#[test]
fn stage177_real_corpus_review_queue_fixture_matches() {
    let fixture = load(
        "engine/runtime_stage177/matched_benchmark_real_corpus_review_admission_queue_gate.json",
    );
    let output = run_with_args([
        "runtime",
        "stage177-matched-benchmark-real-corpus-review-admission-queue-gate",
    ]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();

    assert_eq!(json, fixture);
    assert!(
        json["real_corpus_review_admission_queue_recorded"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["reviewed_real_corpus_ready"].as_bool().unwrap());
    assert!(
        !json["real_benchmark_corpus_materialized"]
            .as_bool()
            .unwrap()
    );
}

#[test]
fn stage177_runtime_rejects_extra_args() {
    let output = run_with_args([
        "runtime",
        "stage177-matched-benchmark-real-corpus-review-admission-queue-gate",
        "--bad",
    ]);
    assert_ne!(output.exit_code, 0);
    assert!(output.stderr.contains("unsupported stage177 argument"));
}
