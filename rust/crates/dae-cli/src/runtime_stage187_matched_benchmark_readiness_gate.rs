use std::fs;
use std::path::Path;

use serde_json::{Value, json};

use crate::runner::RunnerOutput;

enum Stage187Mode<'a> {
    ReadOnly,
    WriteReadinessGate {
        root: &'a str,
        stage186_root: &'a str,
    },
}

pub(crate) fn run_stage187_matched_benchmark_readiness_gate(args: &[String]) -> RunnerOutput {
    match parse_stage187_args(args) {
        Ok(Stage187Mode::ReadOnly) => RunnerOutput::ok(format!("{}\n", stage187_report(None))),
        Ok(Stage187Mode::WriteReadinessGate {
            root,
            stage186_root,
        }) => match write_stage187_readiness_gate(root, stage186_root) {
            Ok(result) => RunnerOutput::ok(format!("{}\n", stage187_report(Some(result)))),
            Err(err) => RunnerOutput::stdout_error(err),
        },
        Err(err) => RunnerOutput::usage(err),
    }
}

fn parse_stage187_args(args: &[String]) -> Result<Stage187Mode<'_>, String> {
    let mut write = false;
    let mut root = None;
    let mut stage186_root = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--write-readiness-gate" => write = true,
            "--root" => {
                let Some(value) = iter.next() else {
                    return Err("stage187 --root requires a value".to_string());
                };
                root = Some(value.as_str());
            }
            _ if arg.starts_with("--root=") => root = arg.split_once('=').map(|(_, value)| value),
            "--stage186-root" => {
                let Some(value) = iter.next() else {
                    return Err("stage187 --stage186-root requires a value".to_string());
                };
                stage186_root = Some(value.as_str());
            }
            _ if arg.starts_with("--stage186-root=") => {
                stage186_root = arg.split_once('=').map(|(_, value)| value);
            }
            _ => return Err(format!("unsupported stage187 argument: {arg}")),
        }
    }
    match (write, root, stage186_root) {
        (false, None, None) => Ok(Stage187Mode::ReadOnly),
        (false, Some(_), _) | (false, _, Some(_)) => {
            Err("stage187 --root/--stage186-root require --write-readiness-gate".to_string())
        }
        (true, Some(root), Some(stage186_root)) => Ok(Stage187Mode::WriteReadinessGate {
            root,
            stage186_root,
        }),
        (true, None, _) => Err("stage187 --write-readiness-gate requires --root".to_string()),
        (true, _, None) => {
            Err("stage187 --write-readiness-gate requires --stage186-root".to_string())
        }
    }
}

fn stage187_report(write_result: Option<Value>) -> Value {
    let written = write_result.is_some();
    let mut report = json!({
        "name": "stage187-matched-benchmark-readiness-gate",
        "stage": "stage187",
        "prior_gate": "stage186-reload-runtime-parity-evidence-gate",
        "evidence_class": "explicit-temp-root-matched-benchmark-readiness-contract-gate",
        "read_only": !written,
        "write_readiness_gate": written,
        "artifact_root_policy": "explicit /tmp/dae-stage187* root only",
        "stage186_root_policy": "explicit /tmp/dae-stage186* root containing Stage186 reload/runtime parity evidence bundle",
        "benchmark_executable_now": false,
        "matched_go_rust_default_daemon_benchmark_recorded": false,
        "true_rust_default_daemon_admitted": false,
        "default_switch_allowed": false,
        "product_chain_switch_allowed": false
    });
    for key in [
        "matched_benchmark_readiness_gate_available",
        "stage186_parity_bundle_required",
        "stage186_evidence_verifier_available",
        "hard_gate_checklist_available",
        "same_corpus_command_plan_available",
        "execution_blocker_queue_available",
        "go_default_path_preserved",
        "go_fallback_required",
        "benchmark_exclusion_checked",
    ] {
        report[key] = json!(true);
    }
    for key in [
        "stage186_parity_bundle_verified",
        "stage184_185_evidence_carried_by_stage186",
        "hard_gate_checklist_written",
        "same_corpus_command_plan_written",
        "benchmark_execution_blockers_written",
        "stage188_bounded_benchmark_input_written",
    ] {
        report[key] = json!(written);
    }
    for key in [
        "rust_production_dae_run_command_admitted",
        "production_listener_bound",
        "listen_socket_map_written",
        "production_tc_attach_smoke_passed",
        "ebpf_attached",
        "production_dataplane_admitted",
        "live_reload_executed",
        "production_listener_reused",
        "production_bpf_owner_transferred",
        "production_dns_cache_migrated",
        "reload_runtime_parity_admitted",
        "benchmark_readiness_admitted",
        "bounded_benchmark_executed",
        "default_path_mutation_allowed",
    ] {
        report[key] = json!(false);
    }
    report["stage186_required_files"] = json!(stage186_files());
    report["stage187_expected_files"] = json!(stage187_files());
    report["readiness_rows"] = readiness_rows(written);
    report["gate_summary"] = gate_summary();
    report["gate_decision"] = json!(
        "Stage187 verifies the explicit Stage186 reload/runtime parity evidence bundle and writes a matched benchmark readiness gate. Because Stage185 and Stage186 are still evidence contracts rather than real production dataplane and live reload admissions, Stage187 keeps benchmark execution and default/product switches closed"
    );
    report["remaining_blockers"] = remaining_blockers();
    report["next_admission_queue"] = json!([
        {
            "stage": "stage188",
            "target": "bounded same-corpus benchmark hard-gate resolution",
            "required_output": "resolve production dataplane and reload/runtime hard gates before executing any matched Go/Rust default daemon benchmark"
        }
    ]);
    report["validation_commands"] = json!([
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage187/matched_benchmark_readiness_gate.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage187_matched_benchmark_readiness_gate.json",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage187-matched-benchmark-readiness-gate",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage183-corpus-command-admission-binding-dry-run --write-admission-dry-run --root /tmp/dae-stage183-stage187-input",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage184-same-corpus-daemon-execution-smoke --execute-smoke --root /tmp/dae-stage184-stage187-input --stage183-root /tmp/dae-stage183-stage187-input",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage185-production-dataplane-listener-tc-ebpf-evidence-gate --write-evidence-gate --root /tmp/dae-stage185-stage187-input --stage184-root /tmp/dae-stage184-stage187-input",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage186-reload-runtime-parity-evidence-gate --write-parity-gate --root /tmp/dae-stage186-stage187-input --stage185-root /tmp/dae-stage185-stage187-input",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage187-matched-benchmark-readiness-gate --write-readiness-gate --root /tmp/dae-stage187-matched-benchmark-readiness --stage186-root /tmp/dae-stage186-stage187-input",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage187 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage187 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage186 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli -p dae-product -q",
        "cargo fmt --manifest-path rust/Cargo.toml --all -- --check",
        "git diff --check"
    ]);
    report["source"] = json!([
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage187",
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage186",
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage185",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.4",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.5",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.8"
    ]);
    if let Some(result) = write_result {
        report["write_result"] = result;
    }
    report
}

fn write_stage187_readiness_gate(root: &str, stage186_root: &str) -> Result<Value, String> {
    let root_path = Path::new(root);
    let stage186_path = Path::new(stage186_root);
    validate_stage187_root(root_path)?;
    validate_stage186_root(stage186_path)?;
    if root_path.exists() {
        return Err(format!(
            "stage187 root already exists, remove it first: {}",
            root_path.display()
        ));
    }
    if !stage186_path.is_dir() {
        return Err(format!(
            "stage186 root does not exist or is not a directory: {}",
            stage186_path.display()
        ));
    }

    let stage186_verification = verify_stage186_bundle(stage186_path)?;
    fs::create_dir_all(root_path).map_err(|err| format!("create stage187 root failed: {err}"))?;

    write_json(
        root_path,
        "prior/stage186-parity-verification.json",
        &stage186_verification,
    )?;
    write_json(
        root_path,
        "benchmark/hard-gate-checklist.json",
        &hard_gate_checklist(),
    )?;
    write_json(
        root_path,
        "benchmark/same-corpus-command-plan.json",
        &same_corpus_command_plan(),
    )?;
    write_json(
        root_path,
        "benchmark/execution-blockers.json",
        &execution_blockers(),
    )?;
    write_json(
        root_path,
        "shared/gate-summary.json",
        &json!({ "gates": gate_summary() }),
    )?;
    write_json(
        root_path,
        "next/stage188-bounded-benchmark-execution-input.json",
        &json!({
            "stage": "stage187",
            "next_stage": "stage188",
            "stage186_parity_bundle_verified": true,
            "stage187_readiness_gate_written": true,
            "production_dataplane_admitted": false,
            "reload_runtime_parity_admitted": false,
            "benchmark_executable_now": false,
            "bounded_benchmark_execution_allowed": false,
            "requires_real_production_dataplane_execution": true,
            "requires_live_reload_runtime_parity_execution": true,
            "requires_same_corpus_go_rust_daemon_benchmark": true
        }),
    )?;

    let manifest = json!({
        "stage": "stage187",
        "bundle": "matched-benchmark-readiness-gate",
        "root": path_string(root_path),
        "stage186_root": path_string(stage186_path),
        "expected_file_count": stage187_files().len(),
        "files_written_count": stage187_files().len(),
        "missing_files": [],
        "stage186_verification": stage186_verification,
        "hard_gate_checklist_written": true,
        "same_corpus_command_plan_written": true,
        "benchmark_execution_blockers_written": true,
        "stage188_bounded_benchmark_input_written": true,
        "production_dataplane_admitted": false,
        "reload_runtime_parity_admitted": false,
        "benchmark_readiness_admitted": false,
        "benchmark_executable_now": false,
        "matched_go_rust_default_daemon_benchmark_recorded": false,
        "default_switch_allowed": false
    });
    write_json(root_path, "manifest.json", &manifest)?;

    let missing = stage187_files()
        .iter()
        .filter(|relative| !root_path.join(relative).is_file())
        .copied()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(format!(
            "stage187 readiness gate missing files after write: {missing:?}"
        ));
    }

    Ok(json!({
        "root": path_string(root_path),
        "stage186_root": path_string(stage186_path),
        "expected_file_count": stage187_files().len(),
        "files_written_count": stage187_files().len(),
        "missing_files": [],
        "stage186_parity_bundle_verified": true,
        "stage184_185_evidence_carried_by_stage186": true,
        "hard_gate_checklist_written": true,
        "same_corpus_command_plan_written": true,
        "benchmark_execution_blockers_written": true,
        "stage188_bounded_benchmark_input_written": true,
        "matched_benchmark_gate": "closed",
        "production_dataplane_admitted": false,
        "reload_runtime_parity_admitted": false,
        "benchmark_readiness_admitted": false,
        "benchmark_executable_now": false,
        "matched_go_rust_default_daemon_benchmark_recorded": false,
        "default_switch_allowed": false
    }))
}

fn verify_stage186_bundle(stage186_root: &Path) -> Result<Value, String> {
    let missing = stage186_files()
        .iter()
        .filter(|relative| !stage186_root.join(relative).is_file())
        .copied()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(format!(
            "stage186 parity bundle missing required files: {missing:?}"
        ));
    }

    let manifest = read_json(stage186_root, "manifest.json")?;
    expect_str(
        &manifest,
        "stage",
        "stage186",
        "stage186 manifest stage mismatch",
    )?;
    expect_bool(
        &manifest,
        "reload_runtime_parity_contract_written",
        true,
        "stage186 reload/runtime parity contract not written",
    )?;
    expect_bool(
        &manifest,
        "benchmark_readiness_input_written",
        true,
        "stage186 benchmark-readiness input not written",
    )?;
    expect_bool(
        &manifest,
        "production_dataplane_admitted",
        false,
        "stage186 unexpectedly admitted production dataplane",
    )?;
    expect_bool(
        &manifest,
        "reload_runtime_parity_admitted",
        false,
        "stage186 unexpectedly admitted reload/runtime parity",
    )?;
    expect_bool(
        &manifest,
        "benchmark_executable_now",
        false,
        "stage186 unexpectedly allowed benchmark execution",
    )?;
    expect_bool(
        &manifest,
        "matched_go_rust_default_daemon_benchmark_recorded",
        false,
        "stage186 unexpectedly recorded matched benchmark",
    )?;
    expect_bool(
        &manifest,
        "default_switch_allowed",
        false,
        "stage186 unexpectedly allowed default switch",
    )?;

    let gate_summary = read_json(stage186_root, "shared/gate-summary.json")?;
    for (gate, status) in [
        ("corpus_gate", "prepared_for_daemon_smoke"),
        ("rust_production_command_gate", "closed"),
        ("daemon_execution_gate", "identity_smoke_passed"),
        ("production_dataplane_gate", "evidence_contract_prepared"),
        ("matched_benchmark_gate", "closed"),
        ("default_product_switch_gate", "closed"),
    ] {
        expect_gate_status(&gate_summary, gate, status)?;
    }

    let next = read_json(
        stage186_root,
        "next/stage187-matched-benchmark-readiness-input.json",
    )?;
    for key in [
        "stage185_evidence_verified",
        "reload_runtime_parity_contract_written",
        "requires_benchmark_readiness_gate",
        "requires_real_production_dataplane_execution",
        "requires_same_corpus_go_rust_daemon_benchmark",
    ] {
        expect_bool(
            &next,
            key,
            true,
            "stage186 next-stage input missing required flag",
        )?;
    }
    for key in [
        "production_dataplane_admitted",
        "reload_runtime_parity_admitted",
        "benchmark_executable_now",
    ] {
        expect_bool(
            &next,
            key,
            false,
            "stage186 next-stage input unexpectedly opened a hard gate",
        )?;
    }

    Ok(json!({
        "stage186_root": path_string(stage186_root),
        "required_files_verified": true,
        "required_file_count": stage186_files().len(),
        "stage186_parity_contract_carried": true,
        "stage184_185_evidence_carried_by_stage186": true,
        "production_dataplane_gate": "evidence_contract_prepared",
        "matched_benchmark_gate": "closed",
        "production_dataplane_admitted": false,
        "reload_runtime_parity_admitted": false,
        "benchmark_executable_now": false,
        "default_switch_allowed": false
    }))
}

fn hard_gate_checklist() -> Value {
    json!({
        "stage": "stage187",
        "checklist": [
            {
                "gate": "production_dataplane_admitted",
                "required_for_benchmark": true,
                "actual": false,
                "blocker": "Stage185 wrote evidence contracts only; no production listener, sockmap, tc, or eBPF attach executed"
            },
            {
                "gate": "reload_runtime_parity_admitted",
                "required_for_benchmark": true,
                "actual": false,
                "blocker": "Stage186 wrote reload/runtime parity contracts only; no live listener reuse, BPF owner transfer, DNS cache migration, or RuntimeOverview parity executed"
            },
            {
                "gate": "rust_production_dae_run_command_admitted",
                "required_for_benchmark": true,
                "actual": false,
                "blocker": "Rust production dae run command remains closed"
            },
            {
                "gate": "matched_go_rust_default_daemon_benchmark_recorded",
                "required_for_default_switch": true,
                "actual": false,
                "blocker": "No matched default daemon benchmark has executed"
            }
        ],
        "benchmark_executable_now": false,
        "benchmark_readiness_admitted": false
    })
}

fn same_corpus_command_plan() -> Value {
    json!({
        "stage": "stage187",
        "corpus": {
            "source": "Stage183 reviewed corpus binding carried through Stage184-186",
            "same_host_required": true,
            "same_config_required": true,
            "same_outbound_matrix_required": true
        },
        "go_default_daemon": {
            "owner": "daenew Go default path",
            "command_identity": "dae run --config <matched-corpus-config>",
            "default_path_preserved": true
        },
        "rust_candidate_daemon": {
            "owner": "daex Rust opt-in path",
            "command_identity": "<rust-daemon-optin> run --config <matched-corpus-config>",
            "production_command_admitted": false
        },
        "metrics_required": [
            "startup ready latency",
            "TCP proxy latency and throughput",
            "UDP proxy latency, loss, and throughput",
            "DNS latency and cache behavior",
            "reload success and rollback latency",
            "RuntimeOverview, RSS, CPU, and file descriptor counts"
        ],
        "execution_allowed_now": false
    })
}

fn execution_blockers() -> Value {
    json!({
        "stage": "stage187",
        "blockers": remaining_blockers(),
        "benchmark_executable_now": false,
        "bounded_benchmark_executed": false,
        "default_switch_allowed": false,
        "product_chain_switch_allowed": false
    })
}

fn readiness_rows(written: bool) -> Value {
    let status = if written {
        "readiness-contract-written"
    } else {
        "requires-explicit-stage187-writer"
    };
    json!([
        {
            "area": "Stage186 evidence verification",
            "status": status,
            "evidence": "Stage187 verifies the explicit Stage186 file set, manifest, gate summary, and next-stage benchmark input",
            "boundary": "verification of contracts is not live dataplane or reload/runtime admission",
            "closed_flag": "benchmark_executable_now=false"
        },
        {
            "area": "same-corpus command plan",
            "status": status,
            "evidence": "Stage187 records the Go default and Rust opt-in same-corpus command plan",
            "boundary": "Rust production command remains closed",
            "closed_flag": "rust_production_dae_run_command_admitted=false"
        },
        {
            "area": "hard benchmark gates",
            "status": status,
            "evidence": "Stage187 records production dataplane and reload/runtime hard gates as required before benchmark execution",
            "boundary": "Stage185/186 contract evidence does not open benchmark execution",
            "closed_flag": "benchmark_readiness_admitted=false"
        },
        {
            "area": "default/product safety",
            "status": "closed-preserved",
            "evidence": "Stage187 preserves default/product switch closure until matched benchmark data exists",
            "boundary": "no default path mutation",
            "closed_flag": "default_switch_allowed=false"
        }
    ])
}

fn gate_summary() -> Value {
    json!([
        {
            "gate": "corpus_gate",
            "status": "prepared_for_daemon_smoke",
            "opens_after": "Stage183 reviewed corpus binding remains carried through Stage184-187"
        },
        {
            "gate": "rust_production_command_gate",
            "status": "closed",
            "opens_after": "production-shaped Rust dae run command identity is admitted"
        },
        {
            "gate": "daemon_execution_gate",
            "status": "identity_smoke_passed",
            "opens_after": "Stage184 same-corpus identity smoke has passed but is not benchmark admission"
        },
        {
            "gate": "production_dataplane_gate",
            "status": "evidence_contract_prepared",
            "opens_after": "real production listener bind, listen_socket_map write, tc attach, eBPF attach, and owner handoff evidence pass"
        },
        {
            "gate": "matched_benchmark_gate",
            "status": "closed",
            "opens_after": "production dataplane and reload/runtime parity pass with a same-corpus Go/Rust default daemon benchmark"
        },
        {
            "gate": "default_product_switch_gate",
            "status": "closed",
            "opens_after": "matched benchmark results and default/product recertification pass"
        }
    ])
}

fn remaining_blockers() -> Value {
    json!([
        "production Rust dae run command remains closed",
        "production listener bind and listen_socket_map mutation have not executed",
        "production tc attach and eBPF object load/ownership have not executed",
        "live reload/runtime parity has not executed against production resources",
        "matched Go/Rust default daemon benchmark has not executed",
        "default daemon and product-chain switches remain closed"
    ])
}

fn read_json(root: &Path, relative: &str) -> Result<Value, String> {
    let path = root.join(relative);
    let content = fs::read_to_string(&path)
        .map_err(|err| format!("read {} failed: {err}", path.display()))?;
    serde_json::from_str(&content).map_err(|err| format!("parse {} failed: {err}", path.display()))
}

fn write_json(root: &Path, relative: &str, value: &Value) -> Result<(), String> {
    let path = root.join(relative);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| format!("create stage187 parent {} failed: {err}", parent.display()))?;
    }
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|err| format!("encode stage187 file {} failed: {err}", path.display()))?;
    fs::write(&path, bytes)
        .map_err(|err| format!("write stage187 file {} failed: {err}", path.display()))
}

fn expect_str(value: &Value, key: &str, expected: &str, message: &str) -> Result<(), String> {
    match value.get(key).and_then(Value::as_str) {
        Some(actual) if actual == expected => Ok(()),
        Some(actual) => Err(format!("{message}: expected {expected}, got {actual}")),
        None => Err(format!("{message}: missing {key}")),
    }
}

fn expect_bool(value: &Value, key: &str, expected: bool, message: &str) -> Result<(), String> {
    match value.get(key).and_then(Value::as_bool) {
        Some(actual) if actual == expected => Ok(()),
        Some(actual) => Err(format!("{message}: expected {expected}, got {actual}")),
        None => Err(format!("{message}: missing {key}")),
    }
}

fn expect_gate_status(value: &Value, gate: &str, expected: &str) -> Result<(), String> {
    let status = value
        .get("gates")
        .and_then(Value::as_array)
        .and_then(|gates| {
            gates.iter().find_map(|entry| {
                (entry.get("gate").and_then(Value::as_str) == Some(gate))
                    .then(|| entry.get("status").and_then(Value::as_str))
                    .flatten()
            })
        });
    if status == Some(expected) {
        return Ok(());
    }
    Err(format!(
        "stage186 gate {gate} mismatch: expected {expected}, got {status:?}"
    ))
}

fn validate_stage187_root(path: &Path) -> Result<(), String> {
    if !path.is_absolute() {
        return Err("stage187 root must be absolute".to_string());
    }
    if !path.to_string_lossy().starts_with("/tmp/dae-stage187") {
        return Err("stage187 root must be under /tmp/dae-stage187*".to_string());
    }
    Ok(())
}

fn validate_stage186_root(path: &Path) -> Result<(), String> {
    if !path.is_absolute() {
        return Err("stage186 root must be absolute".to_string());
    }
    if !path.to_string_lossy().starts_with("/tmp/dae-stage186") {
        return Err("stage186 root must be under /tmp/dae-stage186*".to_string());
    }
    Ok(())
}

fn stage186_files() -> Vec<&'static str> {
    vec![
        "manifest.json",
        "prior/stage185-evidence-verification.json",
        "runtime/listener-reuse-contract.json",
        "runtime/bpf-owner-transfer-contract.json",
        "runtime/dns-cache-migration-guard.json",
        "runtime/bounded-close-runtime-overview-contract.json",
        "shared/gate-summary.json",
        "next/stage187-matched-benchmark-readiness-input.json",
    ]
}

fn stage187_files() -> Vec<&'static str> {
    vec![
        "manifest.json",
        "prior/stage186-parity-verification.json",
        "benchmark/hard-gate-checklist.json",
        "benchmark/same-corpus-command-plan.json",
        "benchmark/execution-blockers.json",
        "shared/gate-summary.json",
        "next/stage188-bounded-benchmark-execution-input.json",
    ]
}

fn path_string(path: &Path) -> String {
    path.display().to_string()
}
