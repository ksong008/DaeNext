use super::*;

#[test]
fn stage187_matched_benchmark_readiness_fixture_matches() {
    let fixture = load("engine/runtime_stage187/matched_benchmark_readiness_gate.json");
    let output = run_with_args(["runtime", "stage187-matched-benchmark-readiness-gate"]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();

    assert_eq!(json, fixture);
    assert!(
        json["matched_benchmark_readiness_gate_available"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["stage186_parity_bundle_verified"].as_bool().unwrap());
    assert_eq!(json["gate_summary"].as_array().unwrap().len(), 6);
    assert!(!json["benchmark_readiness_admitted"].as_bool().unwrap());
    assert!(!json["benchmark_executable_now"].as_bool().unwrap());
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
}

#[test]
fn stage187_writes_readiness_gate_from_stage186_bundle() {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let stage183_root = std::env::temp_dir().join(format!(
        "dae-stage183-cli-stage187-input-{}-{now}",
        std::process::id()
    ));
    let stage184_root = std::env::temp_dir().join(format!(
        "dae-stage184-cli-stage187-input-{}-{now}",
        std::process::id()
    ));
    let stage185_root = std::env::temp_dir().join(format!(
        "dae-stage185-cli-stage187-input-{}-{now}",
        std::process::id()
    ));
    let stage186_root = std::env::temp_dir().join(format!(
        "dae-stage186-cli-stage187-input-{}-{now}",
        std::process::id()
    ));
    let stage187_root = std::env::temp_dir().join(format!(
        "dae-stage187-cli-readiness-{}-{now}",
        std::process::id()
    ));
    for root in [
        &stage183_root,
        &stage184_root,
        &stage185_root,
        &stage186_root,
        &stage187_root,
    ] {
        let _ = std::fs::remove_dir_all(root);
    }

    let stage183 = run_with_args([
        "runtime",
        "stage183-corpus-command-admission-binding-dry-run",
        "--write-admission-dry-run",
        "--root",
        &stage183_root.display().to_string(),
    ]);
    assert_eq!(stage183.exit_code, 0, "{}", stage183.stdout);
    assert_eq!(stage183.stderr, "");

    let stage184 = run_with_args([
        "runtime",
        "stage184-same-corpus-daemon-execution-smoke",
        "--execute-smoke",
        "--root",
        &stage184_root.display().to_string(),
        "--stage183-root",
        &stage183_root.display().to_string(),
    ]);
    assert_eq!(stage184.exit_code, 0, "{}", stage184.stdout);
    assert_eq!(stage184.stderr, "");
    let stage184_json: Value = serde_json::from_str(&stage184.stdout).unwrap();

    let stage185 = run_with_args([
        "runtime",
        "stage185-production-dataplane-listener-tc-ebpf-evidence-gate",
        "--write-evidence-gate",
        "--root",
        &stage185_root.display().to_string(),
        "--stage184-root",
        &stage184_root.display().to_string(),
    ]);
    assert_eq!(stage185.exit_code, 0, "{}", stage185.stdout);
    assert_eq!(stage185.stderr, "");

    let stage186 = run_with_args([
        "runtime",
        "stage186-reload-runtime-parity-evidence-gate",
        "--write-parity-gate",
        "--root",
        &stage186_root.display().to_string(),
        "--stage185-root",
        &stage185_root.display().to_string(),
    ]);
    assert_eq!(stage186.exit_code, 0, "{}", stage186.stdout);
    assert_eq!(stage186.stderr, "");

    let output = run_with_args([
        "runtime",
        "stage187-matched-benchmark-readiness-gate",
        "--write-readiness-gate",
        "--root",
        &stage187_root.display().to_string(),
        "--stage186-root",
        &stage186_root.display().to_string(),
    ]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();

    assert!(json["write_readiness_gate"].as_bool().unwrap());
    assert!(json["stage186_parity_bundle_verified"].as_bool().unwrap());
    assert!(json["hard_gate_checklist_written"].as_bool().unwrap());
    assert!(json["same_corpus_command_plan_written"].as_bool().unwrap());
    assert!(
        json["benchmark_execution_blockers_written"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        json["write_result"]["matched_benchmark_gate"]
            .as_str()
            .unwrap(),
        "closed"
    );
    assert_eq!(
        json["write_result"]["files_written_count"]
            .as_u64()
            .unwrap(),
        7
    );
    assert!(stage187_root.join("manifest.json").is_file());
    assert!(
        stage187_root
            .join("prior/stage186-parity-verification.json")
            .is_file()
    );
    assert!(
        stage187_root
            .join("benchmark/hard-gate-checklist.json")
            .is_file()
    );
    assert!(
        stage187_root
            .join("benchmark/same-corpus-command-plan.json")
            .is_file()
    );
    assert!(
        stage187_root
            .join("benchmark/execution-blockers.json")
            .is_file()
    );
    assert!(
        stage187_root
            .join("next/stage188-bounded-benchmark-execution-input.json")
            .is_file()
    );
    assert!(!json["production_dataplane_admitted"].as_bool().unwrap());
    assert!(!json["reload_runtime_parity_admitted"].as_bool().unwrap());
    assert!(!json["benchmark_readiness_admitted"].as_bool().unwrap());
    assert!(!json["benchmark_executable_now"].as_bool().unwrap());
    assert!(!json["default_switch_allowed"].as_bool().unwrap());

    let stage156_root = stage184_json["smoke_result"]["rust_stage156_root"]
        .as_str()
        .map(str::to_owned);
    for root in [
        &stage183_root,
        &stage184_root,
        &stage185_root,
        &stage186_root,
        &stage187_root,
    ] {
        let _ = std::fs::remove_dir_all(root);
    }
    if let Some(root) = stage156_root {
        let _ = std::fs::remove_dir_all(root);
    }
}

#[test]
fn stage187_runtime_rejects_bad_args() {
    let output = run_with_args([
        "runtime",
        "stage187-matched-benchmark-readiness-gate",
        "--root",
        "/tmp/dae-stage187-missing-write-flag",
    ]);
    assert_ne!(output.exit_code, 0);
    assert!(
        output
            .stderr
            .contains("--root/--stage186-root require --write-readiness-gate")
    );

    let output = run_with_args([
        "runtime",
        "stage187-matched-benchmark-readiness-gate",
        "--write-readiness-gate",
        "--root",
        "/tmp/dae-stage187-missing-stage186",
    ]);
    assert_ne!(output.exit_code, 0);
    assert!(output.stderr.contains("requires --stage186-root"));

    let output = run_with_args([
        "runtime",
        "stage187-matched-benchmark-readiness-gate",
        "--bad",
    ]);
    assert_ne!(output.exit_code, 0);
    assert!(output.stderr.contains("unsupported stage187 argument"));
}
