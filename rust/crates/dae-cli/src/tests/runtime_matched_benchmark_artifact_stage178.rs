use super::*;

#[test]
fn stage178_reviewed_corpus_materializer_fixture_matches() {
    let fixture =
        load("engine/runtime_stage178/matched_benchmark_reviewed_corpus_materializer_dry_run.json");
    let output = run_with_args([
        "runtime",
        "stage178-matched-benchmark-reviewed-corpus-materializer-dry-run",
    ]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();

    assert_eq!(json, fixture);
    assert!(
        json["reviewed_corpus_artifact_dry_run_available"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["reviewed_corpus_artifact_written"].as_bool().unwrap());
    assert!(!json["reviewed_real_corpus_ready"].as_bool().unwrap());
    assert!(
        !json["real_benchmark_corpus_materialized"]
            .as_bool()
            .unwrap()
    );
}

#[test]
fn stage178_writes_reviewed_corpus_dry_run_files_under_explicit_temp_root() {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "dae-stage178-cli-test-{}-{now}",
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
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();
    assert!(json["reviewed_corpus_artifact_written"].as_bool().unwrap());
    assert!(json["reviewed_manifest_written"].as_bool().unwrap());
    assert!(json["reviewed_digest_written"].as_bool().unwrap());
    assert_eq!(
        json["materialize_result"]["files_written_count"]
            .as_u64()
            .unwrap(),
        7
    );
    assert!(root.join("manifest.json").is_file());
    assert!(root.join("config/corpus.reviewed.dae").is_file());
    assert!(root.join("shared/reviewed-corpus-digests.json").is_file());
    assert!(root.join("review/review-admission-evidence.json").is_file());
    assert!(root.join("commands/stage172-binding.json").is_file());
    assert!(!json["reviewed_real_corpus_ready"].as_bool().unwrap());
    assert!(
        !json["real_benchmark_corpus_materialized"]
            .as_bool()
            .unwrap()
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn stage178_runtime_rejects_bad_args() {
    let output = run_with_args([
        "runtime",
        "stage178-matched-benchmark-reviewed-corpus-materializer-dry-run",
        "--root",
        "/tmp/dae-stage178-missing-materialize-flag",
    ]);
    assert_ne!(output.exit_code, 0);
    assert!(
        output
            .stderr
            .contains("--root requires --materialize-reviewed-dry-run")
    );

    let output = run_with_args([
        "runtime",
        "stage178-matched-benchmark-reviewed-corpus-materializer-dry-run",
        "--bad",
    ]);
    assert_ne!(output.exit_code, 0);
    assert!(output.stderr.contains("unsupported stage178 argument"));
}
