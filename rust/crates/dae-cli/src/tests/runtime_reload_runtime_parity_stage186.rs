use super::*;

#[test]
fn stage186_reload_runtime_parity_fixture_matches() {
    let fixture = load("engine/runtime_stage186/reload_runtime_parity_evidence_gate.json");
    let output = run_with_args(["runtime", "stage186-reload-runtime-parity-evidence-gate"]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();

    assert_eq!(json, fixture);
    assert!(
        json["reload_runtime_parity_gate_available"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["stage185_evidence_verified"].as_bool().unwrap());
    assert_eq!(json["gate_summary"].as_array().unwrap().len(), 6);
    assert!(!json["reload_runtime_parity_admitted"].as_bool().unwrap());
    assert!(!json["benchmark_executable_now"].as_bool().unwrap());
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
}

#[test]
fn stage186_writes_parity_gate_from_stage185_bundle() {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let stage183_root = std::env::temp_dir().join(format!(
        "dae-stage183-cli-stage186-input-{}-{now}",
        std::process::id()
    ));
    let stage184_root = std::env::temp_dir().join(format!(
        "dae-stage184-cli-stage186-input-{}-{now}",
        std::process::id()
    ));
    let stage185_root = std::env::temp_dir().join(format!(
        "dae-stage185-cli-stage186-input-{}-{now}",
        std::process::id()
    ));
    let stage186_root = std::env::temp_dir().join(format!(
        "dae-stage186-cli-parity-{}-{now}",
        std::process::id()
    ));
    for root in [
        &stage183_root,
        &stage184_root,
        &stage185_root,
        &stage186_root,
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

    let output = run_with_args([
        "runtime",
        "stage186-reload-runtime-parity-evidence-gate",
        "--write-parity-gate",
        "--root",
        &stage186_root.display().to_string(),
        "--stage185-root",
        &stage185_root.display().to_string(),
    ]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();

    assert!(json["write_parity_gate"].as_bool().unwrap());
    assert!(json["stage185_evidence_verified"].as_bool().unwrap());
    assert!(
        json["reload_runtime_parity_contract_written"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        json["write_result"]["reload_runtime_parity_gate"]
            .as_str()
            .unwrap(),
        "contract_prepared"
    );
    assert_eq!(
        json["write_result"]["files_written_count"]
            .as_u64()
            .unwrap(),
        8
    );
    assert!(stage186_root.join("manifest.json").is_file());
    assert!(
        stage186_root
            .join("prior/stage185-evidence-verification.json")
            .is_file()
    );
    assert!(
        stage186_root
            .join("runtime/listener-reuse-contract.json")
            .is_file()
    );
    assert!(
        stage186_root
            .join("runtime/bpf-owner-transfer-contract.json")
            .is_file()
    );
    assert!(
        stage186_root
            .join("runtime/dns-cache-migration-guard.json")
            .is_file()
    );
    assert!(
        stage186_root
            .join("runtime/bounded-close-runtime-overview-contract.json")
            .is_file()
    );
    assert!(
        stage186_root
            .join("next/stage187-matched-benchmark-readiness-input.json")
            .is_file()
    );
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
    ] {
        let _ = std::fs::remove_dir_all(root);
    }
    if let Some(root) = stage156_root {
        let _ = std::fs::remove_dir_all(root);
    }
}

#[test]
fn stage186_runtime_rejects_bad_args() {
    let output = run_with_args([
        "runtime",
        "stage186-reload-runtime-parity-evidence-gate",
        "--root",
        "/tmp/dae-stage186-missing-write-flag",
    ]);
    assert_ne!(output.exit_code, 0);
    assert!(
        output
            .stderr
            .contains("--root/--stage185-root require --write-parity-gate")
    );

    let output = run_with_args([
        "runtime",
        "stage186-reload-runtime-parity-evidence-gate",
        "--write-parity-gate",
        "--root",
        "/tmp/dae-stage186-missing-stage185",
    ]);
    assert_ne!(output.exit_code, 0);
    assert!(output.stderr.contains("requires --stage185-root"));

    let output = run_with_args([
        "runtime",
        "stage186-reload-runtime-parity-evidence-gate",
        "--bad",
    ]);
    assert_ne!(output.exit_code, 0);
    assert!(output.stderr.contains("unsupported stage186 argument"));
}
