use super::*;

#[test]
fn stage176_real_corpus_candidate_verifier_fixture_matches() {
    let fixture = load(
        "engine/runtime_stage176/matched_benchmark_real_corpus_candidate_artifact_verifier.json",
    );
    let output = run_with_args([
        "runtime",
        "stage176-matched-benchmark-real-corpus-candidate-artifact-verifier",
    ]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();
    assert_eq!(json, fixture);
    assert!(
        json["real_corpus_candidate_artifact_verifier_available"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["candidate_digest_verified"].as_bool().unwrap());
}

#[test]
fn stage176_verifies_explicit_stage175_candidate_root() {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "dae-stage175-stage176-cli-test-{}-{now}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    let output = run_with_args([
        "runtime",
        "stage175-matched-benchmark-real-corpus-candidate-materializer-dry-run",
        "--materialize-candidate-dry-run",
        "--root",
        &root.display().to_string(),
    ]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    let output = run_with_args([
        "runtime",
        "stage176-matched-benchmark-real-corpus-candidate-artifact-verifier",
        "--verify-candidate-root",
        "--root",
        &root.display().to_string(),
    ]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();
    assert!(json["candidate_digest_verified"].as_bool().unwrap());
    assert!(
        json["candidate_review_boundary_verified"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        json["verification_result"]["verified_file_count"]
            .as_u64()
            .unwrap(),
        5
    );
    assert!(
        !json["real_benchmark_corpus_materialized"]
            .as_bool()
            .unwrap()
    );
    let _ = std::fs::remove_dir_all(root);
}
