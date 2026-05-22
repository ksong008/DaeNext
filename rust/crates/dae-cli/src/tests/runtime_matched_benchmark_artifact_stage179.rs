use super::*;

#[test]
fn stage179_reviewed_corpus_verifier_fixture_matches() {
    let fixture =
        load("engine/runtime_stage179/matched_benchmark_reviewed_corpus_artifact_verifier.json");
    let output = run_with_args([
        "runtime",
        "stage179-matched-benchmark-reviewed-corpus-artifact-verifier",
    ]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();

    assert_eq!(json, fixture);
    assert!(
        json["reviewed_corpus_artifact_verifier_available"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["reviewed_file_set_verified"].as_bool().unwrap());
    assert!(!json["reviewed_real_corpus_ready"].as_bool().unwrap());
    assert!(
        !json["real_benchmark_corpus_materialized"]
            .as_bool()
            .unwrap()
    );
}

#[test]
fn stage179_verifies_explicit_stage178_reviewed_root() {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "dae-stage178-stage179-cli-test-{}-{now}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    let output = run_with_args([
        "runtime",
        "stage178-matched-benchmark-reviewed-corpus-materializer-dry-run",
        "--materialize-reviewed-dry-run",
        "--root",
        &root.display().to_string(),
    ]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    let output = run_with_args([
        "runtime",
        "stage179-matched-benchmark-reviewed-corpus-artifact-verifier",
        "--verify-reviewed-root",
        "--root",
        &root.display().to_string(),
    ]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();
    assert!(json["reviewed_file_set_verified"].as_bool().unwrap());
    assert!(json["reviewed_digest_verified"].as_bool().unwrap());
    assert!(json["redaction_evidence_verified"].as_bool().unwrap());
    assert!(json["runtime_evidence_scope_verified"].as_bool().unwrap());
    assert!(json["command_binding_verified"].as_bool().unwrap());
    assert!(json["closed_benchmark_flags_verified"].as_bool().unwrap());
    assert_eq!(
        json["verification_result"]["verified_file_count"]
            .as_u64()
            .unwrap(),
        7
    );
    assert!(!json["reviewed_real_corpus_ready"].as_bool().unwrap());
    assert!(
        !json["real_benchmark_corpus_materialized"]
            .as_bool()
            .unwrap()
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn stage179_runtime_rejects_bad_args() {
    let output = run_with_args([
        "runtime",
        "stage179-matched-benchmark-reviewed-corpus-artifact-verifier",
        "--root",
        "/tmp/dae-stage178-missing-verify-flag",
    ]);
    assert_ne!(output.exit_code, 0);
    assert!(
        output
            .stderr
            .contains("--root requires --verify-reviewed-root")
    );

    let output = run_with_args([
        "runtime",
        "stage179-matched-benchmark-reviewed-corpus-artifact-verifier",
        "--bad",
    ]);
    assert_ne!(output.exit_code, 0);
    assert!(output.stderr.contains("unsupported stage179 argument"));
}
