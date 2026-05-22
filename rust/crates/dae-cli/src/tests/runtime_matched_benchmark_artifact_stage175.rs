use super::*;

#[test]
fn stage175_real_corpus_candidate_materializer_fixture_matches() {
    let fixture = load(
        "engine/runtime_stage175/matched_benchmark_real_corpus_candidate_materializer_dry_run.json",
    );
    let output = run_with_args([
        "runtime",
        "stage175-matched-benchmark-real-corpus-candidate-materializer-dry-run",
    ]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();

    assert_eq!(json, fixture);
    assert!(
        json["real_corpus_candidate_materializer_dry_run_available"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["candidate_manifest_written"].as_bool().unwrap());
    assert!(
        !json["real_benchmark_corpus_materialized"]
            .as_bool()
            .unwrap()
    );
}

#[test]
fn stage175_materializes_candidate_files_under_explicit_temp_root() {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "dae-stage175-cli-test-{}-{now}",
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
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();
    assert!(json["candidate_manifest_written"].as_bool().unwrap());
    assert!(json["candidate_digest_written"].as_bool().unwrap());
    assert_eq!(
        json["materialize_result"]["files_written_count"]
            .as_u64()
            .unwrap(),
        5
    );
    assert!(root.join("config/corpus.candidate.dae").is_file());
    assert!(root.join("shared/candidate-digests.json").is_file());
    assert!(root.join("review/materialization-contract.json").is_file());
    assert!(
        !json["real_benchmark_corpus_materialized"]
            .as_bool()
            .unwrap()
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn stage175_runtime_rejects_bad_args() {
    let output = run_with_args([
        "runtime",
        "stage175-matched-benchmark-real-corpus-candidate-materializer-dry-run",
        "--root",
        "/tmp/dae-stage175-missing-materialize-flag",
    ]);
    assert_ne!(output.exit_code, 0);
    assert!(
        output
            .stderr
            .contains("--root requires --materialize-candidate-dry-run")
    );

    let output = run_with_args([
        "runtime",
        "stage175-matched-benchmark-real-corpus-candidate-materializer-dry-run",
        "--bad",
    ]);
    assert_ne!(output.exit_code, 0);
    assert!(output.stderr.contains("unsupported stage175 argument"));
}
