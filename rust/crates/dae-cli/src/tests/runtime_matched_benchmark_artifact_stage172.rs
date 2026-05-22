use super::*;

#[test]
fn stage172_command_capture_fixture_matches() {
    let fixture = load("engine/runtime_stage172/matched_benchmark_command_capture_dry_run.json");
    let output = run_with_args([
        "runtime",
        "stage172-matched-benchmark-command-capture-dry-run",
    ]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();

    assert_eq!(json, fixture);
    assert!(json["command_capture_dry_run_available"].as_bool().unwrap());
    assert!(
        !json["go_default_command_template_written"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["rust_production_dae_run_command_exists"]
            .as_bool()
            .unwrap()
    );
}

#[test]
fn stage172_writes_command_templates_under_explicit_temp_root() {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "dae-stage172-cli-test-{}-{now}",
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
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();
    assert!(
        json["go_default_command_template_written"]
            .as_bool()
            .unwrap()
    );
    assert!(
        json["rust_optin_command_template_written"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        json["write_result"]["files_written_count"]
            .as_u64()
            .unwrap(),
        5
    );
    assert!(root.join("go/command-template.json").is_file());
    assert!(root.join("rust/command-template.json").is_file());
    assert!(root.join("shared/stage171-digest-input.json").is_file());
    assert!(!json["go_default_daemon_executed"].as_bool().unwrap());
    assert!(!json["rust_optin_daemon_executed"].as_bool().unwrap());
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn stage172_runtime_rejects_bad_args() {
    let output = run_with_args([
        "runtime",
        "stage172-matched-benchmark-command-capture-dry-run",
        "--root",
        "/tmp/dae-stage172-missing-write-flag",
    ]);
    assert_ne!(output.exit_code, 0);
    assert!(output.stderr.contains("--root requires --write-dry-run"));

    let output = run_with_args([
        "runtime",
        "stage172-matched-benchmark-command-capture-dry-run",
        "--bad",
    ]);
    assert_ne!(output.exit_code, 0);
    assert!(output.stderr.contains("unsupported stage172 argument"));
}
