use super::*;

#[test]
fn stage188_bounded_benchmark_hard_gate_fixture_matches() {
    let fixture = load("engine/runtime_stage188/bounded_benchmark_hard_gate_resolution.json");
    let output = run_with_args(["runtime", "stage188-bounded-benchmark-hard-gate-resolution"]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();

    assert_eq!(json, fixture);
    assert!(
        json["bounded_benchmark_hard_gate_resolution_available"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["stage187_readiness_bundle_verified"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(json["gate_summary"].as_array().unwrap().len(), 6);
    assert!(!json["hard_gates_resolved"].as_bool().unwrap());
    assert!(!json["benchmark_executable_now"].as_bool().unwrap());
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
}

#[test]
fn stage188_writes_resolution_from_stage187_bundle() {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let stage183_root = std::env::temp_dir().join(format!(
        "dae-stage183-cli-stage188-input-{}-{now}",
        std::process::id()
    ));
    let stage184_root = std::env::temp_dir().join(format!(
        "dae-stage184-cli-stage188-input-{}-{now}",
        std::process::id()
    ));
    let stage185_root = std::env::temp_dir().join(format!(
        "dae-stage185-cli-stage188-input-{}-{now}",
        std::process::id()
    ));
    let stage186_root = std::env::temp_dir().join(format!(
        "dae-stage186-cli-stage188-input-{}-{now}",
        std::process::id()
    ));
    let stage187_root = std::env::temp_dir().join(format!(
        "dae-stage187-cli-stage188-input-{}-{now}",
        std::process::id()
    ));
    let stage188_root = std::env::temp_dir().join(format!(
        "dae-stage188-cli-resolution-{}-{now}",
        std::process::id()
    ));
    for root in [
        &stage183_root,
        &stage184_root,
        &stage185_root,
        &stage186_root,
        &stage187_root,
        &stage188_root,
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

    let stage187 = run_with_args([
        "runtime",
        "stage187-matched-benchmark-readiness-gate",
        "--write-readiness-gate",
        "--root",
        &stage187_root.display().to_string(),
        "--stage186-root",
        &stage186_root.display().to_string(),
    ]);
    assert_eq!(stage187.exit_code, 0, "{}", stage187.stdout);
    assert_eq!(stage187.stderr, "");

    let output = run_with_args([
        "runtime",
        "stage188-bounded-benchmark-hard-gate-resolution",
        "--write-resolution",
        "--root",
        &stage188_root.display().to_string(),
        "--stage187-root",
        &stage187_root.display().to_string(),
    ]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();

    assert!(json["write_resolution"].as_bool().unwrap());
    assert!(
        json["stage187_readiness_bundle_verified"]
            .as_bool()
            .unwrap()
    );
    assert!(
        json["production_dataplane_execution_queue_written"]
            .as_bool()
            .unwrap()
    );
    assert!(
        json["reload_runtime_parity_execution_queue_written"]
            .as_bool()
            .unwrap()
    );
    assert!(
        json["benchmark_admission_blockers_written"]
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
    assert!(stage188_root.join("manifest.json").is_file());
    assert!(
        stage188_root
            .join("prior/stage187-readiness-verification.json")
            .is_file()
    );
    assert!(
        stage188_root
            .join("resolution/production-dataplane-execution-queue.json")
            .is_file()
    );
    assert!(
        stage188_root
            .join("resolution/reload-runtime-parity-execution-queue.json")
            .is_file()
    );
    assert!(
        stage188_root
            .join("resolution/benchmark-admission-blockers.json")
            .is_file()
    );
    assert!(
        stage188_root
            .join("next/stage189-production-dataplane-execution-input.json")
            .is_file()
    );
    assert!(!json["hard_gates_resolved"].as_bool().unwrap());
    assert!(!json["production_dataplane_admitted"].as_bool().unwrap());
    assert!(!json["reload_runtime_parity_admitted"].as_bool().unwrap());
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
        &stage188_root,
    ] {
        let _ = std::fs::remove_dir_all(root);
    }
    if let Some(root) = stage156_root {
        let _ = std::fs::remove_dir_all(root);
    }
}

#[test]
fn stage188_runtime_rejects_bad_args() {
    let output = run_with_args([
        "runtime",
        "stage188-bounded-benchmark-hard-gate-resolution",
        "--root",
        "/tmp/dae-stage188-missing-write-flag",
    ]);
    assert_ne!(output.exit_code, 0);
    assert!(
        output
            .stderr
            .contains("--root/--stage187-root require --write-resolution")
    );

    let output = run_with_args([
        "runtime",
        "stage188-bounded-benchmark-hard-gate-resolution",
        "--write-resolution",
        "--root",
        "/tmp/dae-stage188-missing-stage187",
    ]);
    assert_ne!(output.exit_code, 0);
    assert!(output.stderr.contains("requires --stage187-root"));

    let output = run_with_args([
        "runtime",
        "stage188-bounded-benchmark-hard-gate-resolution",
        "--bad",
    ]);
    assert_ne!(output.exit_code, 0);
    assert!(output.stderr.contains("unsupported stage188 argument"));
}
