use super::*;

#[test]
fn stage184_same_corpus_daemon_execution_fixture_matches() {
    let fixture = load("engine/runtime_stage184/same_corpus_daemon_execution_smoke.json");
    let output = run_with_args(["runtime", "stage184-same-corpus-daemon-execution-smoke"]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();

    assert_eq!(json, fixture);
    assert!(
        json["same_corpus_daemon_execution_smoke_available"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["stage183_bundle_verified"].as_bool().unwrap());
    assert_eq!(json["gate_summary"].as_array().unwrap().len(), 6);
    assert!(!json["benchmark_executable_now"].as_bool().unwrap());
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
}

#[test]
fn stage184_executes_same_corpus_identity_smoke_under_explicit_roots() {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let stage183_root = std::env::temp_dir().join(format!(
        "dae-stage183-cli-stage184-input-{}-{now}",
        std::process::id()
    ));
    let stage184_root = std::env::temp_dir().join(format!(
        "dae-stage184-cli-smoke-{}-{now}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&stage183_root);
    let _ = std::fs::remove_dir_all(&stage184_root);

    let stage183 = run_with_args([
        "runtime",
        "stage183-corpus-command-admission-binding-dry-run",
        "--write-admission-dry-run",
        "--root",
        &stage183_root.display().to_string(),
    ]);
    assert_eq!(stage183.exit_code, 0, "{}", stage183.stdout);
    assert_eq!(stage183.stderr, "");

    let output = run_with_args([
        "runtime",
        "stage184-same-corpus-daemon-execution-smoke",
        "--execute-smoke",
        "--root",
        &stage184_root.display().to_string(),
        "--stage183-root",
        &stage183_root.display().to_string(),
    ]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();

    assert!(json["execute_smoke"].as_bool().unwrap());
    assert!(json["stage183_bundle_verified"].as_bool().unwrap());
    assert!(json["go_default_identity_smoke_passed"].as_bool().unwrap());
    assert!(json["rust_optin_identity_smoke_passed"].as_bool().unwrap());
    assert_eq!(
        json["smoke_result"]["daemon_execution_gate"]
            .as_str()
            .unwrap(),
        "identity_smoke_passed"
    );
    assert_eq!(
        json["smoke_result"]["files_written_count"]
            .as_u64()
            .unwrap(),
        10
    );
    assert!(stage184_root.join("manifest.json").is_file());
    assert!(
        stage184_root
            .join("shared/stage183-reviewed-corpus-identity.dae")
            .is_file()
    );
    assert!(
        stage184_root
            .join("go/run/go-default-daemon-identity.json")
            .is_file()
    );
    assert!(stage184_root.join("go/run/dae-go.progress").is_file());
    assert!(
        stage184_root
            .join("rust/run/rust-optin-stage156-identity.json")
            .is_file()
    );
    assert!(!json["benchmark_executable_now"].as_bool().unwrap());
    assert!(
        !json["matched_go_rust_default_daemon_benchmark_recorded"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["production_dataplane_admitted"].as_bool().unwrap());
    assert!(!json["default_switch_allowed"].as_bool().unwrap());

    let stage156_root = json["smoke_result"]["root"].as_str().and_then(|_| {
        json["smoke_result"]
            .get("rust_stage156_root")
            .and_then(Value::as_str)
    });
    let _ = std::fs::remove_dir_all(&stage183_root);
    let _ = std::fs::remove_dir_all(&stage184_root);
    if let Some(root) = stage156_root {
        let _ = std::fs::remove_dir_all(root);
    }
}

#[test]
fn stage184_runtime_rejects_bad_args() {
    let output = run_with_args([
        "runtime",
        "stage184-same-corpus-daemon-execution-smoke",
        "--root",
        "/tmp/dae-stage184-missing-execute-flag",
    ]);
    assert_ne!(output.exit_code, 0);
    assert!(
        output
            .stderr
            .contains("--root/--stage183-root require --execute-smoke")
    );

    let output = run_with_args([
        "runtime",
        "stage184-same-corpus-daemon-execution-smoke",
        "--execute-smoke",
        "--root",
        "/tmp/dae-stage184-missing-stage183",
    ]);
    assert_ne!(output.exit_code, 0);
    assert!(output.stderr.contains("requires --stage183-root"));

    let output = run_with_args([
        "runtime",
        "stage184-same-corpus-daemon-execution-smoke",
        "--bad",
    ]);
    assert_ne!(output.exit_code, 0);
    assert!(output.stderr.contains("unsupported stage184 argument"));
}
