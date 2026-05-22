use super::*;

#[test]
fn stage170_matched_benchmark_artifact_writer_fixture_matches() {
    let fixture = load("engine/runtime_stage170/matched_benchmark_artifact_writer_dry_run.json");
    let output = run_with_args([
        "runtime",
        "stage170-matched-benchmark-artifact-writer-dry-run",
    ]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();

    assert_eq!(json, fixture);
    assert!(json["artifact_writer_dry_run_available"].as_bool().unwrap());
    assert!(!json["dry_run_artifact_files_written"].as_bool().unwrap());
    assert!(
        !json["matched_go_rust_default_daemon_benchmark_recorded"]
            .as_bool()
            .unwrap()
    );
}

#[test]
fn stage170_matched_benchmark_artifact_writer_writes_explicit_temp_root() {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "dae-stage170-cli-test-{}-{now}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    let output = run_with_args([
        "runtime",
        "stage170-matched-benchmark-artifact-writer-dry-run",
        "--write-dry-run",
        "--root",
        &root.display().to_string(),
    ]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();
    assert!(json["dry_run_artifact_files_written"].as_bool().unwrap());
    assert!(json["dry_run_manifest_written"].as_bool().unwrap());
    assert!(json["dry_run_file_count_verified"].as_bool().unwrap());
    assert_eq!(
        json["write_result"]["files_written_count"]
            .as_u64()
            .unwrap(),
        14
    );
    assert!(root.join("manifest.json").is_file());
    assert!(root.join("shared/bpf-map-snapshot.json").is_file());
    assert!(!json["go_default_daemon_executed"].as_bool().unwrap());
    assert!(!json["rust_optin_daemon_executed"].as_bool().unwrap());
    assert!(
        !json["matched_go_rust_default_daemon_benchmark_recorded"]
            .as_bool()
            .unwrap()
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn stage170_runtime_rejects_bad_args() {
    let output = run_with_args([
        "runtime",
        "stage170-matched-benchmark-artifact-writer-dry-run",
        "--root",
        "/tmp/dae-stage170-missing-write-flag",
    ]);
    assert_ne!(output.exit_code, 0);
    assert!(output.stderr.contains("--root requires --write-dry-run"));

    let output = run_with_args([
        "runtime",
        "stage170-matched-benchmark-artifact-writer-dry-run",
        "--bad",
    ]);
    assert_ne!(output.exit_code, 0);
    assert!(output.stderr.contains("unsupported stage170 argument"));
}
