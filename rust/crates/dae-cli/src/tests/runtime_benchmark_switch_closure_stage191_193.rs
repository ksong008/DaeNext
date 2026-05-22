use super::*;

#[test]
fn stage191_benchmark_admission_input_fixture_matches() {
    let fixture =
        load("engine/runtime_stage191/bounded_same_corpus_benchmark_admission_input_gate.json");
    let output = run_with_args([
        "runtime",
        "stage191-bounded-same-corpus-benchmark-admission-input-gate",
    ]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();

    assert_eq!(json, fixture);
    assert!(
        json["bounded_same_corpus_benchmark_admission_input_gate_available"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["stage190_reload_runtime_bundle_verified"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(json["gate_summary"].as_array().unwrap().len(), 6);
    assert!(!json["benchmark_executable_now"].as_bool().unwrap());
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
    assert!(!json["product_chain_switch_allowed"].as_bool().unwrap());
}

#[test]
fn stage192_switch_recertification_input_fixture_matches() {
    let fixture =
        load("engine/runtime_stage192/default_product_switch_recertification_input_gate.json");
    let output = run_with_args([
        "runtime",
        "stage192-default-product-switch-recertification-input-gate",
    ]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();

    assert_eq!(json, fixture);
    assert!(
        json["default_product_switch_recertification_input_gate_available"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["stage191_benchmark_admission_bundle_verified"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(json["gate_summary"].as_array().unwrap().len(), 6);
    assert!(!json["benchmark_executable_now"].as_bool().unwrap());
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
    assert!(!json["product_chain_switch_allowed"].as_bool().unwrap());
}

#[test]
fn stage193_switch_hard_gate_closure_fixture_matches() {
    let fixture = load("engine/runtime_stage193/default_product_switch_hard_gate_closure.json");
    let output = run_with_args([
        "runtime",
        "stage193-default-product-switch-hard-gate-closure",
    ]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();

    assert_eq!(json, fixture);
    assert!(
        json["default_product_switch_hard_gate_closure_available"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["stage192_recertification_bundle_verified"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(json["gate_summary"].as_array().unwrap().len(), 6);
    assert!(!json["benchmark_executable_now"].as_bool().unwrap());
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
    assert!(!json["product_chain_switch_allowed"].as_bool().unwrap());
}

#[test]
fn stage191_193_writer_chain_closes_benchmark_and_switch_gates() {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let stage183_root = stage_root("stage183", "stage191-input", now);
    let stage184_root = stage_root("stage184", "stage191-input", now);
    let stage185_root = stage_root("stage185", "stage191-input", now);
    let stage186_root = stage_root("stage186", "stage191-input", now);
    let stage187_root = stage_root("stage187", "stage191-input", now);
    let stage188_root = stage_root("stage188", "stage191-input", now);
    let stage189_root = stage_root("stage189", "stage191-input", now);
    let stage190_root = stage_root("stage190", "stage191-input", now);
    let stage191_root = stage_root("stage191", "cli-admission", now);
    let stage192_root = stage_root("stage192", "cli-recertification", now);
    let stage193_root = stage_root("stage193", "cli-closure", now);
    for root in [
        &stage183_root,
        &stage184_root,
        &stage185_root,
        &stage186_root,
        &stage187_root,
        &stage188_root,
        &stage189_root,
        &stage190_root,
        &stage191_root,
        &stage192_root,
        &stage193_root,
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

    let stage190 = run_with_args([
        "runtime",
        "stage190-live-reload-runtime-parity-execution-evidence-gate",
        "--write-evidence",
        "--root",
        &stage190_root.display().to_string(),
        "--stage189-root",
        &stage189_root.display().to_string(),
    ]);
    assert_eq!(stage190.exit_code, 0, "{}", stage190.stdout);
    assert_eq!(stage190.stderr, "");

    let stage191 = run_with_args([
        "runtime",
        "stage191-bounded-same-corpus-benchmark-admission-input-gate",
        "--write-admission-input",
        "--root",
        &stage191_root.display().to_string(),
        "--stage190-root",
        &stage190_root.display().to_string(),
    ]);
    assert_eq!(stage191.exit_code, 0, "{}", stage191.stdout);
    assert_eq!(stage191.stderr, "");
    let stage191_json: Value = serde_json::from_str(&stage191.stdout).unwrap();
    assert!(stage191_json["write_admission_input"].as_bool().unwrap());
    assert!(
        stage191_json["stage190_reload_runtime_bundle_verified"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        stage191_json["write_result"]["files_written_count"]
            .as_u64()
            .unwrap(),
        7
    );
    assert!(stage191_root.join("manifest.json").is_file());
    assert!(
        stage191_root
            .join("benchmark/production-dataplane-blocker.json")
            .is_file()
    );
    assert!(
        stage191_root
            .join("benchmark/reload-runtime-parity-blocker.json")
            .is_file()
    );
    assert!(
        stage191_root
            .join("benchmark/matched-benchmark-command-blocker.json")
            .is_file()
    );
    assert!(
        stage191_root
            .join("next/stage192-default-product-switch-recertification-input.json")
            .is_file()
    );

    let stage192 = run_with_args([
        "runtime",
        "stage192-default-product-switch-recertification-input-gate",
        "--write-recertification-input",
        "--root",
        &stage192_root.display().to_string(),
        "--stage191-root",
        &stage191_root.display().to_string(),
    ]);
    assert_eq!(stage192.exit_code, 0, "{}", stage192.stdout);
    assert_eq!(stage192.stderr, "");
    let stage192_json: Value = serde_json::from_str(&stage192.stdout).unwrap();
    assert!(
        stage192_json["write_recertification_input"]
            .as_bool()
            .unwrap()
    );
    assert!(
        stage192_json["stage191_benchmark_admission_bundle_verified"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        stage192_json["write_result"]["files_written_count"]
            .as_u64()
            .unwrap(),
        7
    );
    assert!(
        stage192_root
            .join("switch/default-daemon-switch-blocker.json")
            .is_file()
    );
    assert!(
        stage192_root
            .join("switch/product-chain-switch-blocker.json")
            .is_file()
    );
    assert!(
        stage192_root
            .join("next/stage193-default-product-switch-hard-gate-input.json")
            .is_file()
    );

    let stage193 = run_with_args([
        "runtime",
        "stage193-default-product-switch-hard-gate-closure",
        "--write-hard-gate-closure",
        "--root",
        &stage193_root.display().to_string(),
        "--stage192-root",
        &stage192_root.display().to_string(),
    ]);
    assert_eq!(stage193.exit_code, 0, "{}", stage193.stdout);
    assert_eq!(stage193.stderr, "");
    let stage193_json: Value = serde_json::from_str(&stage193.stdout).unwrap();
    assert!(stage193_json["write_hard_gate_closure"].as_bool().unwrap());
    assert!(
        stage193_json["stage192_recertification_bundle_verified"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        stage193_json["write_result"]["files_written_count"]
            .as_u64()
            .unwrap(),
        7
    );
    assert!(
        stage193_root
            .join("closure/default-switch-hard-gate-summary.json")
            .is_file()
    );
    assert!(
        stage193_root
            .join("closure/product-chain-hard-gate-summary.json")
            .is_file()
    );
    assert!(
        stage193_root
            .join("next/stage194-true-production-execution-implementation-input.json")
            .is_file()
    );

    for json in [&stage191_json, &stage192_json, &stage193_json] {
        assert!(!json["hard_gates_resolved"].as_bool().unwrap());
        assert!(!json["production_dataplane_admitted"].as_bool().unwrap());
        assert!(!json["reload_runtime_parity_admitted"].as_bool().unwrap());
        assert!(!json["benchmark_executable_now"].as_bool().unwrap());
        assert!(
            !json["matched_go_rust_default_daemon_benchmark_recorded"]
                .as_bool()
                .unwrap()
        );
        assert!(!json["default_switch_allowed"].as_bool().unwrap());
        assert!(!json["product_chain_switch_allowed"].as_bool().unwrap());
    }

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
        &stage191_root,
        &stage192_root,
        &stage193_root,
    ] {
        let _ = std::fs::remove_dir_all(root);
    }
    if let Some(root) = stage156_root {
        let _ = std::fs::remove_dir_all(root);
    }
}

#[test]
fn stage191_193_runtime_rejects_bad_args() {
    let output = run_with_args([
        "runtime",
        "stage191-bounded-same-corpus-benchmark-admission-input-gate",
        "--root",
        "/tmp/dae-stage191-missing-write-flag",
    ]);
    assert_ne!(output.exit_code, 0);
    assert!(
        output
            .stderr
            .contains("--root/--stage190-root require --write-admission-input")
    );

    let output = run_with_args([
        "runtime",
        "stage192-default-product-switch-recertification-input-gate",
        "--write-recertification-input",
        "--root",
        "/tmp/dae-stage192-missing-stage191",
    ]);
    assert_ne!(output.exit_code, 0);
    assert!(output.stderr.contains("requires --stage191-root"));

    let output = run_with_args([
        "runtime",
        "stage193-default-product-switch-hard-gate-closure",
        "--bad",
    ]);
    assert_ne!(output.exit_code, 0);
    assert!(output.stderr.contains("unsupported stage193 argument"));
}

fn stage_root(stage: &str, label: &str, now: u128) -> PathBuf {
    std::env::temp_dir().join(format!(
        "dae-{stage}-cli-{label}-{}-{now}",
        std::process::id()
    ))
}
