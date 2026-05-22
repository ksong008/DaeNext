use super::*;

#[test]
fn stage190_live_reload_runtime_parity_fixture_matches() {
    let fixture =
        load("engine/runtime_stage190/live_reload_runtime_parity_execution_evidence_gate.json");
    let output = run_with_args([
        "runtime",
        "stage190-live-reload-runtime-parity-execution-evidence-gate",
    ]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();

    assert_eq!(json, fixture);
    assert!(
        json["live_reload_runtime_parity_execution_evidence_gate_available"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["stage189_dataplane_bundle_verified"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(json["gate_summary"].as_array().unwrap().len(), 6);
    assert!(!json["reload_runtime_parity_admitted"].as_bool().unwrap());
    assert!(!json["benchmark_executable_now"].as_bool().unwrap());
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
}

#[test]
fn stage190_writes_reload_runtime_gap_from_stage189_bundle() {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let stage183_root = std::env::temp_dir().join(format!(
        "dae-stage183-cli-stage190-input-{}-{now}",
        std::process::id()
    ));
    let stage184_root = std::env::temp_dir().join(format!(
        "dae-stage184-cli-stage190-input-{}-{now}",
        std::process::id()
    ));
    let stage185_root = std::env::temp_dir().join(format!(
        "dae-stage185-cli-stage190-input-{}-{now}",
        std::process::id()
    ));
    let stage186_root = std::env::temp_dir().join(format!(
        "dae-stage186-cli-stage190-input-{}-{now}",
        std::process::id()
    ));
    let stage187_root = std::env::temp_dir().join(format!(
        "dae-stage187-cli-stage190-input-{}-{now}",
        std::process::id()
    ));
    let stage188_root = std::env::temp_dir().join(format!(
        "dae-stage188-cli-stage190-input-{}-{now}",
        std::process::id()
    ));
    let stage189_root = std::env::temp_dir().join(format!(
        "dae-stage189-cli-stage190-input-{}-{now}",
        std::process::id()
    ));
    let stage190_root = std::env::temp_dir().join(format!(
        "dae-stage190-cli-evidence-{}-{now}",
        std::process::id()
    ));
    for root in [
        &stage183_root,
        &stage184_root,
        &stage185_root,
        &stage186_root,
        &stage187_root,
        &stage188_root,
        &stage189_root,
        &stage190_root,
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

    let stage188 = run_with_args([
        "runtime",
        "stage188-bounded-benchmark-hard-gate-resolution",
        "--write-resolution",
        "--root",
        &stage188_root.display().to_string(),
        "--stage187-root",
        &stage187_root.display().to_string(),
    ]);
    assert_eq!(stage188.exit_code, 0, "{}", stage188.stdout);
    assert_eq!(stage188.stderr, "");

    let stage189 = run_with_args([
        "runtime",
        "stage189-production-dataplane-execution-evidence-gate",
        "--write-evidence",
        "--root",
        &stage189_root.display().to_string(),
        "--stage188-root",
        &stage188_root.display().to_string(),
    ]);
    assert_eq!(stage189.exit_code, 0, "{}", stage189.stdout);
    assert_eq!(stage189.stderr, "");

    let output = run_with_args([
        "runtime",
        "stage190-live-reload-runtime-parity-execution-evidence-gate",
        "--write-evidence",
        "--root",
        &stage190_root.display().to_string(),
        "--stage189-root",
        &stage189_root.display().to_string(),
    ]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();

    assert!(json["write_evidence"].as_bool().unwrap());
    assert!(
        json["stage189_dataplane_bundle_verified"]
            .as_bool()
            .unwrap()
    );
    assert!(json["listener_reuse_gap_written"].as_bool().unwrap());
    assert!(json["bpf_owner_transfer_gap_written"].as_bool().unwrap());
    assert!(
        json["dns_cache_migration_guard_gap_written"]
            .as_bool()
            .unwrap()
    );
    assert!(
        json["bounded_close_runtime_overview_gap_written"]
            .as_bool()
            .unwrap()
    );
    assert!(
        json["stage191_bounded_benchmark_input_written"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        json["write_result"]["reload_runtime_parity_gate"]
            .as_str()
            .unwrap(),
        "execution_gap_recorded"
    );
    assert_eq!(
        json["write_result"]["files_written_count"]
            .as_u64()
            .unwrap(),
        8
    );
    assert!(stage190_root.join("manifest.json").is_file());
    assert!(
        stage190_root
            .join("prior/stage189-dataplane-verification.json")
            .is_file()
    );
    assert!(
        stage190_root
            .join("reload/listener-reuse-execution-gap.json")
            .is_file()
    );
    assert!(
        stage190_root
            .join("reload/bpf-owner-transfer-execution-gap.json")
            .is_file()
    );
    assert!(
        stage190_root
            .join("reload/dns-cache-migration-guard-gap.json")
            .is_file()
    );
    assert!(
        stage190_root
            .join("runtime/bounded-close-runtime-overview-gap.json")
            .is_file()
    );
    assert!(
        stage190_root
            .join("next/stage191-bounded-benchmark-execution-input.json")
            .is_file()
    );
    assert!(!json["hard_gates_resolved"].as_bool().unwrap());
    assert!(!json["production_dataplane_admitted"].as_bool().unwrap());
    assert!(!json["live_reload_executed"].as_bool().unwrap());
    assert!(!json["production_listener_reused"].as_bool().unwrap());
    assert!(!json["production_bpf_owner_transferred"].as_bool().unwrap());
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
        &stage189_root,
        &stage190_root,
    ] {
        let _ = std::fs::remove_dir_all(root);
    }
    if let Some(root) = stage156_root {
        let _ = std::fs::remove_dir_all(root);
    }
}

#[test]
fn stage190_runtime_rejects_bad_args() {
    let output = run_with_args([
        "runtime",
        "stage190-live-reload-runtime-parity-execution-evidence-gate",
        "--root",
        "/tmp/dae-stage190-missing-write-flag",
    ]);
    assert_ne!(output.exit_code, 0);
    assert!(
        output
            .stderr
            .contains("--root/--stage189-root require --write-evidence")
    );

    let output = run_with_args([
        "runtime",
        "stage190-live-reload-runtime-parity-execution-evidence-gate",
        "--write-evidence",
        "--root",
        "/tmp/dae-stage190-missing-stage189",
    ]);
    assert_ne!(output.exit_code, 0);
    assert!(output.stderr.contains("requires --stage189-root"));

    let output = run_with_args([
        "runtime",
        "stage190-live-reload-runtime-parity-execution-evidence-gate",
        "--bad",
    ]);
    assert_ne!(output.exit_code, 0);
    assert!(output.stderr.contains("unsupported stage190 argument"));
}
