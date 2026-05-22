use super::*;

#[test]
fn stage171_matched_benchmark_metadata_digest_fixture_matches() {
    let fixture =
        load("engine/runtime_stage171/matched_benchmark_metadata_corpus_digest_dry_run.json");
    let output = run_with_args([
        "runtime",
        "stage171-matched-benchmark-metadata-corpus-digest-dry-run",
    ]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();

    assert_eq!(json, fixture);
    assert!(json["host_metadata_dry_run_available"].as_bool().unwrap());
    assert!(json["corpus_digest_dry_run_available"].as_bool().unwrap());
    assert!(!json["host_metadata_snapshot_written"].as_bool().unwrap());
    assert!(
        !json["real_benchmark_corpus_materialized"]
            .as_bool()
            .unwrap()
    );
}

#[test]
fn stage171_populates_metadata_and_digest_files_in_explicit_temp_root() {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "dae-stage171-cli-test-{}-{now}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    let output = run_with_args([
        "runtime",
        "stage171-matched-benchmark-metadata-corpus-digest-dry-run",
        "--populate-dry-run",
        "--root",
        &root.display().to_string(),
    ]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();
    assert!(json["host_metadata_snapshot_written"].as_bool().unwrap());
    assert!(json["corpus_digest_written"].as_bool().unwrap());
    assert!(json["outbound_matrix_digest_written"].as_bool().unwrap());
    assert_eq!(
        json["populate_result"]["files_written_count"]
            .as_u64()
            .unwrap(),
        5
    );
    assert!(root.join("manifest.json").is_file());
    assert!(root.join("host/metadata.json").is_file());
    assert!(root.join("shared/corpus-digests.json").is_file());
    assert!(
        !json["real_benchmark_corpus_materialized"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["matched_go_rust_default_daemon_benchmark_recorded"]
            .as_bool()
            .unwrap()
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn stage171_runtime_rejects_bad_args() {
    let output = run_with_args([
        "runtime",
        "stage171-matched-benchmark-metadata-corpus-digest-dry-run",
        "--root",
        "/tmp/dae-stage171-missing-populate-flag",
    ]);
    assert_ne!(output.exit_code, 0);
    assert!(output.stderr.contains("--root requires --populate-dry-run"));

    let output = run_with_args([
        "runtime",
        "stage171-matched-benchmark-metadata-corpus-digest-dry-run",
        "--bad",
    ]);
    assert_ne!(output.exit_code, 0);
    assert!(output.stderr.contains("unsupported stage171 argument"));
}
