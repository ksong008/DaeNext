use super::*;

#[test]
fn stage183_corpus_command_admission_fixture_matches() {
    let fixture = load("engine/runtime_stage183/corpus_command_admission_binding_dry_run.json");
    let output = run_with_args([
        "runtime",
        "stage183-corpus-command-admission-binding-dry-run",
    ]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();

    assert_eq!(json, fixture);
    assert!(
        json["corpus_command_admission_binding_available"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["admission_bundle_written"].as_bool().unwrap());
    assert_eq!(json["closed_gates"].as_array().unwrap().len(), 6);
    assert!(!json["benchmark_executable_now"].as_bool().unwrap());
}

#[test]
fn stage183_writes_admission_bundle_under_explicit_temp_root() {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "dae-stage183-cli-test-{}-{now}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    let output = run_with_args([
        "runtime",
        "stage183-corpus-command-admission-binding-dry-run",
        "--write-admission-dry-run",
        "--root",
        &root.display().to_string(),
    ]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();

    assert!(json["admission_bundle_written"].as_bool().unwrap());
    assert_eq!(
        json["write_result"]["files_written_count"]
            .as_u64()
            .unwrap(),
        6
    );
    assert!(root.join("manifest.json").is_file());
    assert!(root.join("corpus/reviewed-corpus-binding.json").is_file());
    assert!(
        root.join("commands/go-default-command-template.json")
            .is_file()
    );
    assert!(
        root.join("commands/rust-optin-command-template.json")
            .is_file()
    );
    assert!(root.join("shared/gate-summary.json").is_file());
    assert!(root.join("next/stage184-daemon-smoke-input.json").is_file());
    assert!(!json["benchmark_executable_now"].as_bool().unwrap());
    assert!(
        !json["matched_go_rust_default_daemon_benchmark_recorded"]
            .as_bool()
            .unwrap()
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn stage183_runtime_rejects_bad_args() {
    let output = run_with_args([
        "runtime",
        "stage183-corpus-command-admission-binding-dry-run",
        "--root",
        "/tmp/dae-stage183-missing-write-flag",
    ]);
    assert_ne!(output.exit_code, 0);
    assert!(
        output
            .stderr
            .contains("--root requires --write-admission-dry-run")
    );

    let output = run_with_args([
        "runtime",
        "stage183-corpus-command-admission-binding-dry-run",
        "--bad",
    ]);
    assert_ne!(output.exit_code, 0);
    assert!(output.stderr.contains("unsupported stage183 argument"));
}
