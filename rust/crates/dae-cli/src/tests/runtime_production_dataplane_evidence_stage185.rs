use super::*;

#[test]
fn stage185_production_dataplane_evidence_fixture_matches() {
    let fixture =
        load("engine/runtime_stage185/production_dataplane_listener_tc_ebpf_evidence_gate.json");
    let output = run_with_args([
        "runtime",
        "stage185-production-dataplane-listener-tc-ebpf-evidence-gate",
    ]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();

    assert_eq!(json, fixture);
    assert!(
        json["production_dataplane_evidence_gate_available"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["stage184_smoke_verified"].as_bool().unwrap());
    assert_eq!(json["gate_summary"].as_array().unwrap().len(), 6);
    assert!(!json["production_dataplane_admitted"].as_bool().unwrap());
    assert!(!json["benchmark_executable_now"].as_bool().unwrap());
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
}

#[test]
fn stage185_writes_evidence_gate_from_stage184_smoke() {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let stage183_root = std::env::temp_dir().join(format!(
        "dae-stage183-cli-stage185-input-{}-{now}",
        std::process::id()
    ));
    let stage184_root = std::env::temp_dir().join(format!(
        "dae-stage184-cli-stage185-input-{}-{now}",
        std::process::id()
    ));
    let stage185_root = std::env::temp_dir().join(format!(
        "dae-stage185-cli-evidence-{}-{now}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&stage183_root);
    let _ = std::fs::remove_dir_all(&stage184_root);
    let _ = std::fs::remove_dir_all(&stage185_root);

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

    let output = run_with_args([
        "runtime",
        "stage185-production-dataplane-listener-tc-ebpf-evidence-gate",
        "--write-evidence-gate",
        "--root",
        &stage185_root.display().to_string(),
        "--stage184-root",
        &stage184_root.display().to_string(),
    ]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();

    assert!(json["write_evidence_gate"].as_bool().unwrap());
    assert!(json["stage184_smoke_verified"].as_bool().unwrap());
    assert!(
        json["production_dataplane_evidence_contract_written"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        json["write_result"]["production_dataplane_gate"]
            .as_str()
            .unwrap(),
        "evidence_contract_prepared"
    );
    assert_eq!(
        json["write_result"]["files_written_count"]
            .as_u64()
            .unwrap(),
        7
    );
    assert!(stage185_root.join("manifest.json").is_file());
    assert!(
        stage185_root
            .join("prior/stage184-smoke-verification.json")
            .is_file()
    );
    assert!(
        stage185_root
            .join("dataplane/listener-socket-map-contract.json")
            .is_file()
    );
    assert!(
        stage185_root
            .join("dataplane/tc-ebpf-attach-contract.json")
            .is_file()
    );
    assert!(
        stage185_root
            .join("dataplane/bpf-owner-handoff-contract.json")
            .is_file()
    );
    assert!(
        stage185_root
            .join("next/stage186-reload-runtime-parity-input.json")
            .is_file()
    );
    assert!(!json["production_listener_bound"].as_bool().unwrap());
    assert!(!json["listen_socket_map_written"].as_bool().unwrap());
    assert!(!json["production_tc_attach_smoke_passed"].as_bool().unwrap());
    assert!(!json["ebpf_attached"].as_bool().unwrap());
    assert!(!json["production_dataplane_admitted"].as_bool().unwrap());
    assert!(!json["benchmark_executable_now"].as_bool().unwrap());
    assert!(!json["default_switch_allowed"].as_bool().unwrap());

    let stage156_root = stage184_json["smoke_result"]["rust_stage156_root"]
        .as_str()
        .map(str::to_owned);
    let _ = std::fs::remove_dir_all(&stage183_root);
    let _ = std::fs::remove_dir_all(&stage184_root);
    let _ = std::fs::remove_dir_all(&stage185_root);
    if let Some(root) = stage156_root {
        let _ = std::fs::remove_dir_all(root);
    }
}

#[test]
fn stage185_runtime_rejects_bad_args() {
    let output = run_with_args([
        "runtime",
        "stage185-production-dataplane-listener-tc-ebpf-evidence-gate",
        "--root",
        "/tmp/dae-stage185-missing-write-flag",
    ]);
    assert_ne!(output.exit_code, 0);
    assert!(
        output
            .stderr
            .contains("--root/--stage184-root require --write-evidence-gate")
    );

    let output = run_with_args([
        "runtime",
        "stage185-production-dataplane-listener-tc-ebpf-evidence-gate",
        "--write-evidence-gate",
        "--root",
        "/tmp/dae-stage185-missing-stage184",
    ]);
    assert_ne!(output.exit_code, 0);
    assert!(output.stderr.contains("requires --stage184-root"));

    let output = run_with_args([
        "runtime",
        "stage185-production-dataplane-listener-tc-ebpf-evidence-gate",
        "--bad",
    ]);
    assert_ne!(output.exit_code, 0);
    assert!(output.stderr.contains("unsupported stage185 argument"));
}
