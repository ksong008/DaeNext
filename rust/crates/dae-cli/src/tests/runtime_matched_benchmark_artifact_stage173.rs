use super::*;

#[test]
fn stage173_command_capture_artifact_verifier_fixture_matches() {
    let fixture =
        load("engine/runtime_stage173/matched_benchmark_command_capture_artifact_verifier.json");
    let output = run_with_args([
        "runtime",
        "stage173-matched-benchmark-command-capture-artifact-verifier",
    ]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();

    assert_eq!(json, fixture);
    assert!(
        json["command_capture_artifact_verifier_available"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["command_template_symmetry_verified"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["go_default_daemon_executed"].as_bool().unwrap());
}

#[test]
fn stage173_verifies_explicit_stage172_command_capture_root() {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "dae-stage172-stage173-cli-test-{}-{now}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    let output = run_with_args([
        "runtime",
        "stage172-matched-benchmark-command-capture-dry-run",
        "--write-dry-run",
        "--root",
        &root.display().to_string(),
    ]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);

    let output = run_with_args([
        "runtime",
        "stage173-matched-benchmark-command-capture-artifact-verifier",
        "--verify-dry-run-root",
        "--root",
        &root.display().to_string(),
    ]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();
    assert!(
        json["command_template_symmetry_verified"]
            .as_bool()
            .unwrap()
    );
    assert!(json["stage171_digest_input_verified"].as_bool().unwrap());
    assert!(json["rust_optin_blocker_verified"].as_bool().unwrap());
    assert_eq!(
        json["verification_result"]["verified_file_count"]
            .as_u64()
            .unwrap(),
        5
    );
    assert!(!json["go_default_daemon_executed"].as_bool().unwrap());
    assert!(!json["rust_optin_daemon_executed"].as_bool().unwrap());
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn stage173_runtime_rejects_bad_args() {
    let output = run_with_args([
        "runtime",
        "stage173-matched-benchmark-command-capture-artifact-verifier",
        "--root",
        "/tmp/dae-stage172-missing-verify-flag",
    ]);
    assert_ne!(output.exit_code, 0);
    assert!(
        output
            .stderr
            .contains("--root requires --verify-dry-run-root")
    );

    let output = run_with_args([
        "runtime",
        "stage173-matched-benchmark-command-capture-artifact-verifier",
        "--bad",
    ]);
    assert_ne!(output.exit_code, 0);
    assert!(output.stderr.contains("unsupported stage173 argument"));
}
