use super::*;

#[test]
fn stage169_matched_benchmark_artifact_fixture_matches() {
    let fixture = load("engine/runtime_stage169/matched_benchmark_corpus_artifact_builder.json");
    let output = run_with_args([
        "runtime",
        "stage169-matched-benchmark-corpus-artifact-builder",
    ]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();

    assert_eq!(json, fixture);
    assert!(
        json["matched_benchmark_artifact_layout_materialized"]
            .as_bool()
            .unwrap()
    );
    assert!(json["command_plan_recorded"].as_bool().unwrap());
    assert!(json["blocked"].as_bool().unwrap());
    assert!(
        !json["artifact_files_written_to_runtime_dir"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["matched_go_rust_default_daemon_benchmark_recorded"]
            .as_bool()
            .unwrap()
    );
}

#[test]
fn stage169_runtime_rejects_bad_args() {
    let output = run_with_args([
        "runtime",
        "stage169-matched-benchmark-corpus-artifact-builder",
        "--bad",
    ]);
    assert_ne!(output.exit_code, 0);
    assert!(output.stderr.contains("unsupported stage169 argument"));
}
