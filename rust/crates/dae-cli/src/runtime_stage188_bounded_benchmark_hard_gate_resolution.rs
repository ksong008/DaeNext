use std::fs;
use std::path::Path;

use serde_json::{Value, json};

use crate::runner::RunnerOutput;

enum Stage188Mode<'a> {
    ReadOnly,
    WriteResolution {
        root: &'a str,
        stage187_root: &'a str,
    },
}

pub(crate) fn run_stage188_bounded_benchmark_hard_gate_resolution(args: &[String]) -> RunnerOutput {
    match parse_stage188_args(args) {
        Ok(Stage188Mode::ReadOnly) => RunnerOutput::ok(format!("{}\n", stage188_report(None))),
        Ok(Stage188Mode::WriteResolution {
            root,
            stage187_root,
        }) => match write_stage188_resolution(root, stage187_root) {
            Ok(result) => RunnerOutput::ok(format!("{}\n", stage188_report(Some(result)))),
            Err(err) => RunnerOutput::stdout_error(err),
        },
        Err(err) => RunnerOutput::usage(err),
    }
}

fn parse_stage188_args(args: &[String]) -> Result<Stage188Mode<'_>, String> {
    let mut write = false;
    let mut root = None;
    let mut stage187_root = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--write-resolution" => write = true,
            "--root" => {
                let Some(value) = iter.next() else {
                    return Err("stage188 --root requires a value".to_string());
                };
                root = Some(value.as_str());
            }
            _ if arg.starts_with("--root=") => root = arg.split_once('=').map(|(_, value)| value),
            "--stage187-root" => {
                let Some(value) = iter.next() else {
                    return Err("stage188 --stage187-root requires a value".to_string());
                };
                stage187_root = Some(value.as_str());
            }
            _ if arg.starts_with("--stage187-root=") => {
                stage187_root = arg.split_once('=').map(|(_, value)| value);
            }
            _ => return Err(format!("unsupported stage188 argument: {arg}")),
        }
    }
    match (write, root, stage187_root) {
        (false, None, None) => Ok(Stage188Mode::ReadOnly),
        (false, Some(_), _) | (false, _, Some(_)) => {
            Err("stage188 --root/--stage187-root require --write-resolution".to_string())
        }
        (true, Some(root), Some(stage187_root)) => Ok(Stage188Mode::WriteResolution {
            root,
            stage187_root,
        }),
        (true, None, _) => Err("stage188 --write-resolution requires --root".to_string()),
        (true, _, None) => Err("stage188 --write-resolution requires --stage187-root".to_string()),
    }
}

fn stage188_report(write_result: Option<Value>) -> Value {
    let written = write_result.is_some();
    let mut report = json!({
        "name": "stage188-bounded-benchmark-hard-gate-resolution",
        "stage": "stage188",
        "prior_gate": "stage187-matched-benchmark-readiness-gate",
        "evidence_class": "explicit-temp-root-bounded-benchmark-hard-gate-resolution",
        "read_only": !written,
        "write_resolution": written,
        "artifact_root_policy": "explicit /tmp/dae-stage188* root only",
        "stage187_root_policy": "explicit /tmp/dae-stage187* root containing Stage187 matched benchmark readiness bundle",
        "benchmark_executable_now": false,
        "matched_go_rust_default_daemon_benchmark_recorded": false,
        "true_rust_default_daemon_admitted": false,
        "default_switch_allowed": false,
        "product_chain_switch_allowed": false
    });
    for key in [
        "bounded_benchmark_hard_gate_resolution_available",
        "stage187_readiness_bundle_required",
        "stage187_bundle_verifier_available",
        "production_dataplane_execution_queue_available",
        "reload_runtime_parity_execution_queue_available",
        "benchmark_admission_blocker_queue_available",
        "go_default_path_preserved",
        "go_fallback_required",
        "benchmark_exclusion_checked",
    ] {
        report[key] = json!(true);
    }
    for key in [
        "stage187_readiness_bundle_verified",
        "production_dataplane_execution_queue_written",
        "reload_runtime_parity_execution_queue_written",
        "benchmark_admission_blockers_written",
        "stage189_execution_input_written",
    ] {
        report[key] = json!(written);
    }
    for key in [
        "hard_gates_resolved",
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
    report["stage187_required_files"] = json!(stage187_files());
    report["stage188_expected_files"] = json!(stage188_files());
    report["resolution_rows"] = resolution_rows(written);
    report["gate_summary"] = gate_summary();
    report["gate_decision"] = json!(
        "Stage188 verifies the explicit Stage187 readiness bundle and writes hard-gate resolution queues. It does not execute production dataplane, live reload/runtime parity, bounded benchmark, matched benchmark, or default/product switching"
    );
    report["remaining_blockers"] = remaining_blockers();
    report["next_admission_queue"] = json!([
        {
            "stage": "stage189",
            "target": "production dataplane execution evidence",
            "required_output": "execute and verify production listener bind, listen_socket_map write, tc/eBPF attach, and BPF owner handoff before benchmark execution"
        },
        {
            "stage": "stage190",
            "target": "live reload/runtime parity execution evidence",
            "required_output": "execute listener reuse, BPF owner transfer, DNS cache migration guard, bounded close, and RuntimeOverview parity before benchmark execution"
        }
    ]);
    report["validation_commands"] = json!([
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage188/bounded_benchmark_hard_gate_resolution.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage188_bounded_benchmark_hard_gate_resolution.json",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage188-bounded-benchmark-hard-gate-resolution",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage183-corpus-command-admission-binding-dry-run --write-admission-dry-run --root /tmp/dae-stage183-stage188-input",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage184-same-corpus-daemon-execution-smoke --execute-smoke --root /tmp/dae-stage184-stage188-input --stage183-root /tmp/dae-stage183-stage188-input",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage185-production-dataplane-listener-tc-ebpf-evidence-gate --write-evidence-gate --root /tmp/dae-stage185-stage188-input --stage184-root /tmp/dae-stage184-stage188-input",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage186-reload-runtime-parity-evidence-gate --write-parity-gate --root /tmp/dae-stage186-stage188-input --stage185-root /tmp/dae-stage185-stage188-input",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage187-matched-benchmark-readiness-gate --write-readiness-gate --root /tmp/dae-stage187-stage188-input --stage186-root /tmp/dae-stage186-stage188-input",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage188-bounded-benchmark-hard-gate-resolution --write-resolution --root /tmp/dae-stage188-hard-gate-resolution --stage187-root /tmp/dae-stage187-stage188-input",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage188 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage188 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage187 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli -p dae-product -q",
        "cargo fmt --manifest-path rust/Cargo.toml --all -- --check",
        "git diff --check"
    ]);
    report["source"] = json!([
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage188",
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage187",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.4",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.5",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.8"
    ]);
    if let Some(result) = write_result {
        report["write_result"] = result;
    }
    report
}

fn write_stage188_resolution(root: &str, stage187_root: &str) -> Result<Value, String> {
    let root_path = Path::new(root);
    let stage187_path = Path::new(stage187_root);
    validate_stage188_root(root_path)?;
    validate_stage187_root(stage187_path)?;
    if root_path.exists() {
        return Err(format!(
            "stage188 root already exists, remove it first: {}",
            root_path.display()
        ));
    }
    if !stage187_path.is_dir() {
        return Err(format!(
            "stage187 root does not exist or is not a directory: {}",
            stage187_path.display()
        ));
    }

    let stage187_verification = verify_stage187_bundle(stage187_path)?;
    fs::create_dir_all(root_path).map_err(|err| format!("create stage188 root failed: {err}"))?;

    write_json(
        root_path,
        "prior/stage187-readiness-verification.json",
        &stage187_verification,
    )?;
    write_json(
        root_path,
        "resolution/production-dataplane-execution-queue.json",
        &production_dataplane_execution_queue(),
    )?;
    write_json(
        root_path,
        "resolution/reload-runtime-parity-execution-queue.json",
        &reload_runtime_parity_execution_queue(),
    )?;
    write_json(
        root_path,
        "resolution/benchmark-admission-blockers.json",
        &benchmark_admission_blockers(),
    )?;
    write_json(
        root_path,
        "shared/gate-summary.json",
        &json!({ "gates": gate_summary() }),
    )?;
    write_json(
        root_path,
        "next/stage189-production-dataplane-execution-input.json",
        &json!({
            "stage": "stage188",
            "next_stage": "stage189",
            "stage187_readiness_bundle_verified": true,
            "stage188_hard_gate_resolution_written": true,
            "production_dataplane_execution_required": true,
            "reload_runtime_parity_execution_required": true,
            "benchmark_executable_now": false,
            "bounded_benchmark_execution_allowed": false,
            "default_switch_allowed": false
        }),
    )?;

    let manifest = json!({
        "stage": "stage188",
        "bundle": "bounded-benchmark-hard-gate-resolution",
        "root": path_string(root_path),
        "stage187_root": path_string(stage187_path),
        "expected_file_count": stage188_files().len(),
        "files_written_count": stage188_files().len(),
        "missing_files": [],
        "stage187_verification": stage187_verification,
        "production_dataplane_execution_queue_written": true,
        "reload_runtime_parity_execution_queue_written": true,
        "benchmark_admission_blockers_written": true,
        "stage189_execution_input_written": true,
        "hard_gates_resolved": false,
        "production_dataplane_admitted": false,
        "reload_runtime_parity_admitted": false,
        "benchmark_readiness_admitted": false,
        "benchmark_executable_now": false,
        "matched_go_rust_default_daemon_benchmark_recorded": false,
        "default_switch_allowed": false
    });
    write_json(root_path, "manifest.json", &manifest)?;

    let missing = stage188_files()
        .iter()
        .filter(|relative| !root_path.join(relative).is_file())
        .copied()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(format!(
            "stage188 resolution bundle missing files after write: {missing:?}"
        ));
    }

    Ok(json!({
        "root": path_string(root_path),
        "stage187_root": path_string(stage187_path),
        "expected_file_count": stage188_files().len(),
        "files_written_count": stage188_files().len(),
        "missing_files": [],
        "stage187_readiness_bundle_verified": true,
        "production_dataplane_execution_queue_written": true,
        "reload_runtime_parity_execution_queue_written": true,
        "benchmark_admission_blockers_written": true,
        "stage189_execution_input_written": true,
        "hard_gates_resolved": false,
        "matched_benchmark_gate": "closed",
        "production_dataplane_admitted": false,
        "reload_runtime_parity_admitted": false,
        "benchmark_executable_now": false,
        "matched_go_rust_default_daemon_benchmark_recorded": false,
        "default_switch_allowed": false
    }))
}

fn verify_stage187_bundle(stage187_root: &Path) -> Result<Value, String> {
    let missing = stage187_files()
        .iter()
        .filter(|relative| !stage187_root.join(relative).is_file())
        .copied()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(format!(
            "stage187 readiness bundle missing required files: {missing:?}"
        ));
    }

    let manifest = read_json(stage187_root, "manifest.json")?;
    expect_str(
        &manifest,
        "stage",
        "stage187",
        "stage187 manifest stage mismatch",
    )?;
    for key in [
        "hard_gate_checklist_written",
        "same_corpus_command_plan_written",
        "benchmark_execution_blockers_written",
        "stage188_bounded_benchmark_input_written",
    ] {
        expect_bool(
            &manifest,
            key,
            true,
            "stage187 manifest missing required written flag",
        )?;
    }
    for key in [
        "production_dataplane_admitted",
        "reload_runtime_parity_admitted",
        "benchmark_readiness_admitted",
        "benchmark_executable_now",
        "matched_go_rust_default_daemon_benchmark_recorded",
        "default_switch_allowed",
    ] {
        expect_bool(
            &manifest,
            key,
            false,
            "stage187 manifest unexpectedly opened a hard gate",
        )?;
    }

    let gate_summary = read_json(stage187_root, "shared/gate-summary.json")?;
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

    let hard_gates = read_json(stage187_root, "benchmark/hard-gate-checklist.json")?;
    expect_bool(
        &hard_gates,
        "benchmark_executable_now",
        false,
        "stage187 hard-gate checklist unexpectedly opened benchmark execution",
    )?;
    expect_bool(
        &hard_gates,
        "benchmark_readiness_admitted",
        false,
        "stage187 hard-gate checklist unexpectedly admitted benchmark readiness",
    )?;

    let next = read_json(
        stage187_root,
        "next/stage188-bounded-benchmark-execution-input.json",
    )?;
    for key in [
        "stage186_parity_bundle_verified",
        "stage187_readiness_gate_written",
        "requires_real_production_dataplane_execution",
        "requires_live_reload_runtime_parity_execution",
        "requires_same_corpus_go_rust_daemon_benchmark",
    ] {
        expect_bool(
            &next,
            key,
            true,
            "stage187 next-stage input missing required flag",
        )?;
    }
    for key in [
        "production_dataplane_admitted",
        "reload_runtime_parity_admitted",
        "benchmark_executable_now",
        "bounded_benchmark_execution_allowed",
    ] {
        expect_bool(
            &next,
            key,
            false,
            "stage187 next-stage input unexpectedly opened a hard gate",
        )?;
    }

    Ok(json!({
        "stage187_root": path_string(stage187_root),
        "required_files_verified": true,
        "required_file_count": stage187_files().len(),
        "stage187_readiness_bundle_verified": true,
        "hard_gate_checklist_verified": true,
        "production_dataplane_gate": "evidence_contract_prepared",
        "matched_benchmark_gate": "closed",
        "production_dataplane_admitted": false,
        "reload_runtime_parity_admitted": false,
        "benchmark_executable_now": false,
        "default_switch_allowed": false
    }))
}

fn production_dataplane_execution_queue() -> Value {
    json!({
        "stage": "stage188",
        "queue": "production dataplane execution evidence",
        "required_steps": [
            "bind production-shaped TCP and UDP listener",
            "write listen_socket_map key 0 for TCP listener fd",
            "write listen_socket_map key 1 for UDP conn fd",
            "attach tc programs on LAN/WAN/dae0 equivalents",
            "prove eBPF object load, ownership, and cleanup",
            "record rollback and resource cleanup evidence"
        ],
        "source": "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.5",
        "production_dataplane_admitted": false,
        "benchmark_executable_now": false
    })
}

fn reload_runtime_parity_execution_queue() -> Value {
    json!({
        "stage": "stage188",
        "queue": "live reload/runtime parity execution evidence",
        "required_steps": [
            "old control plane EjectBpf",
            "new control plane build and InjectBpf",
            "current pointer swap before old close",
            "old ServeResult returns reusable listener",
            "new Serve reuses old listener and reaches ready",
            "DNS cache migrates only when DNS config is exactly equal",
            "Close observes bounded 2s shutdown behavior",
            "RuntimeOverview exposes active listener, BPF owner, DNS cache, and reload state"
        ],
        "source": "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.4,15.5,15.8",
        "reload_runtime_parity_admitted": false,
        "benchmark_executable_now": false
    })
}

fn benchmark_admission_blockers() -> Value {
    json!({
        "stage": "stage188",
        "blockers": remaining_blockers(),
        "benchmark_executable_now": false,
        "bounded_benchmark_executed": false,
        "matched_go_rust_default_daemon_benchmark_recorded": false,
        "default_switch_allowed": false,
        "product_chain_switch_allowed": false
    })
}

fn resolution_rows(written: bool) -> Value {
    let status = if written {
        "resolution-queue-written"
    } else {
        "requires-explicit-stage188-writer"
    };
    json!([
        {
            "area": "Stage187 readiness verification",
            "status": status,
            "evidence": "Stage188 verifies the explicit Stage187 readiness bundle, manifest, hard-gate checklist, gate summary, and Stage188 input",
            "boundary": "readiness verification is not benchmark execution",
            "closed_flag": "benchmark_executable_now=false"
        },
        {
            "area": "production dataplane hard gate",
            "status": status,
            "evidence": "Stage188 writes the production listener, listen_socket_map, tc/eBPF, owner handoff, and cleanup execution queue",
            "boundary": "does not bind production listener or attach eBPF",
            "closed_flag": "production_dataplane_admitted=false"
        },
        {
            "area": "reload/runtime parity hard gate",
            "status": status,
            "evidence": "Stage188 writes the live reload listener reuse, BPF owner transfer, DNS migration guard, bounded close, and RuntimeOverview execution queue",
            "boundary": "does not execute live reload/runtime parity",
            "closed_flag": "reload_runtime_parity_admitted=false"
        },
        {
            "area": "benchmark/default safety",
            "status": "closed-preserved",
            "evidence": "Stage188 keeps matched benchmark and default/product switches closed until hard gates have real execution evidence",
            "boundary": "no benchmark data recorded",
            "closed_flag": "matched_go_rust_default_daemon_benchmark_recorded=false"
        }
    ])
}

fn gate_summary() -> Value {
    json!([
        {
            "gate": "corpus_gate",
            "status": "prepared_for_daemon_smoke",
            "opens_after": "Stage183 reviewed corpus binding remains carried through Stage184-188"
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
            .map_err(|err| format!("create stage188 parent {} failed: {err}", parent.display()))?;
    }
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|err| format!("encode stage188 file {} failed: {err}", path.display()))?;
    fs::write(&path, bytes)
        .map_err(|err| format!("write stage188 file {} failed: {err}", path.display()))
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
        "stage187 gate {gate} mismatch: expected {expected}, got {status:?}"
    ))
}

fn validate_stage188_root(path: &Path) -> Result<(), String> {
    if !path.is_absolute() {
        return Err("stage188 root must be absolute".to_string());
    }
    if !path.to_string_lossy().starts_with("/tmp/dae-stage188") {
        return Err("stage188 root must be under /tmp/dae-stage188*".to_string());
    }
    Ok(())
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

fn stage188_files() -> Vec<&'static str> {
    vec![
        "manifest.json",
        "prior/stage187-readiness-verification.json",
        "resolution/production-dataplane-execution-queue.json",
        "resolution/reload-runtime-parity-execution-queue.json",
        "resolution/benchmark-admission-blockers.json",
        "shared/gate-summary.json",
        "next/stage189-production-dataplane-execution-input.json",
    ]
}

fn path_string(path: &Path) -> String {
    path.display().to_string()
}
