use super::*;

#[test]
fn stage180_readiness_queue_fixture_matches() {
    let fixture = load(
        "engine/runtime_stage180/matched_benchmark_reviewed_corpus_readiness_admission_queue_gate.json",
    );
    let output = run_with_args([
        "runtime",
        "stage180-matched-benchmark-reviewed-corpus-readiness-admission-queue-gate",
    ]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();

    assert_eq!(json, fixture);
    assert!(
        json["reviewed_corpus_readiness_admission_queue_recorded"]
            .as_bool()
            .unwrap()
    );
    assert!(
        json["stage179_verifier_evidence_carried"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["reviewed_real_corpus_ready"].as_bool().unwrap());
    assert!(
        !json["matched_go_rust_default_daemon_benchmark_recorded"]
            .as_bool()
            .unwrap()
    );
}

#[test]
fn stage180_runtime_rejects_extra_args() {
    let output = run_with_args([
        "runtime",
        "stage180-matched-benchmark-reviewed-corpus-readiness-admission-queue-gate",
        "--bad",
    ]);
    assert_ne!(output.exit_code, 0);
    assert!(output.stderr.contains("unsupported stage180 argument"));
}
