use std::fs;
use std::path::Path;

use serde_json::{Value, json};

use crate::runner::RunnerOutput;

enum Stage186Mode<'a> {
    ReadOnly,
    WriteParityGate {
        root: &'a str,
        stage185_root: &'a str,
    },
}

pub(crate) fn run_stage186_reload_runtime_parity_gate(args: &[String]) -> RunnerOutput {
    match parse_stage186_args(args) {
        Ok(Stage186Mode::ReadOnly) => RunnerOutput::ok(format!("{}\n", stage186_report(None))),
        Ok(Stage186Mode::WriteParityGate {
            root,
            stage185_root,
        }) => match write_stage186_parity_gate(root, stage185_root) {
            Ok(result) => RunnerOutput::ok(format!("{}\n", stage186_report(Some(result)))),
            Err(err) => RunnerOutput::stdout_error(err),
        },
        Err(err) => RunnerOutput::usage(err),
    }
}

fn parse_stage186_args(args: &[String]) -> Result<Stage186Mode<'_>, String> {
    let mut write = false;
    let mut root = None;
    let mut stage185_root = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--write-parity-gate" => write = true,
            "--root" => {
                let Some(value) = iter.next() else {
                    return Err("stage186 --root requires a value".to_string());
                };
                root = Some(value.as_str());
            }
            _ if arg.starts_with("--root=") => root = arg.split_once('=').map(|(_, value)| value),
            "--stage185-root" => {
                let Some(value) = iter.next() else {
                    return Err("stage186 --stage185-root requires a value".to_string());
                };
                stage185_root = Some(value.as_str());
            }
            _ if arg.starts_with("--stage185-root=") => {
                stage185_root = arg.split_once('=').map(|(_, value)| value);
            }
            _ => return Err(format!("unsupported stage186 argument: {arg}")),
        }
    }
    match (write, root, stage185_root) {
        (false, None, None) => Ok(Stage186Mode::ReadOnly),
        (false, Some(_), _) | (false, _, Some(_)) => {
            Err("stage186 --root/--stage185-root require --write-parity-gate".to_string())
        }
        (true, Some(root), Some(stage185_root)) => Ok(Stage186Mode::WriteParityGate {
            root,
            stage185_root,
        }),
        (true, None, _) => Err("stage186 --write-parity-gate requires --root".to_string()),
        (true, _, None) => Err("stage186 --write-parity-gate requires --stage185-root".to_string()),
    }
}

fn stage186_report(write_result: Option<Value>) -> Value {
    let written = write_result.is_some();
    let mut report = json!({
        "name": "stage186-reload-runtime-parity-evidence-gate",
        "stage": "stage186",
        "prior_gate": "stage185-production-dataplane-listener-tc-ebpf-evidence-gate",
        "evidence_class": "explicit-temp-root-reload-runtime-parity-evidence-contract-gate",
        "read_only": !written,
        "write_parity_gate": written,
        "artifact_root_policy": "explicit /tmp/dae-stage186* root only",
        "stage185_root_policy": "explicit /tmp/dae-stage185* root containing Stage185 dataplane evidence bundle",
        "benchmark_executable_now": false,
        "matched_go_rust_default_daemon_benchmark_recorded": false,
        "true_rust_default_daemon_admitted": false,
        "default_switch_allowed": false,
        "product_chain_switch_allowed": false
    });
    for key in [
        "reload_runtime_parity_gate_available",
        "stage185_evidence_bundle_required",
        "listener_reuse_contract_available",
        "bpf_owner_transfer_contract_available",
        "dns_cache_migration_guard_available",
        "bounded_close_contract_available",
        "runtime_overview_parity_contract_available",
        "go_default_path_preserved",
        "go_fallback_required",
        "benchmark_exclusion_checked",
    ] {
        report[key] = json!(true);
    }
    for key in [
        "stage185_evidence_verified",
        "stage185_dataplane_contract_carried",
        "reload_runtime_parity_contract_written",
        "benchmark_readiness_input_written",
    ] {
        report[key] = json!(written);
    }
    for key in [
        "live_reload_executed",
        "production_listener_reused",
        "production_bpf_owner_transferred",
        "production_dns_cache_migrated",
        "runtime_overview_parity_admitted",
        "production_listener_bound",
        "listen_socket_map_written",
        "production_tc_attach_smoke_passed",
        "ebpf_attached",
        "production_dataplane_admitted",
        "reload_runtime_parity_admitted",
        "real_benchmark_corpus_materialized",
        "default_path_mutation_allowed",
    ] {
        report[key] = json!(false);
    }
    report["stage185_required_files"] = json!(stage185_files());
    report["stage186_expected_files"] = json!(stage186_files());
    report["reload_runtime_rows"] = reload_runtime_rows(written);
    report["gate_summary"] = gate_summary(written);
    report["gate_decision"] = json!(
        "Stage186 verifies the explicit Stage185 dataplane evidence bundle and writes a reload/runtime parity evidence contract. It records listener reuse, BPF owner transfer, DNS cache migration guard, bounded close, and RuntimeOverview parity requirements, but does not execute live reload, mutate production listener/BPF state, run matched benchmark, or switch default/product paths"
    );
    report["remaining_blockers"] = json!([
        "production Rust dae run command remains closed",
        "production listener bind and listen_socket_map mutation have not executed",
        "production tc attach and eBPF object load/ownership have not executed",
        "live reload/runtime parity has not executed against production resources",
        "matched Go/Rust default daemon benchmark has not executed",
        "default daemon and product-chain switches remain closed"
    ]);
    report["next_admission_queue"] = json!([
        {
            "stage": "stage187",
            "target": "matched benchmark readiness gate",
            "required_output": "consume Stage184-186 evidence, confirm all hard gates required for benchmark are present, and only then allow a bounded same-corpus Go/Rust daemon benchmark plan"
        }
    ]);
    report["validation_commands"] = json!([
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage186/reload_runtime_parity_evidence_gate.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage186_reload_runtime_parity_evidence_gate.json",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage186-reload-runtime-parity-evidence-gate",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage183-corpus-command-admission-binding-dry-run --write-admission-dry-run --root /tmp/dae-stage183-stage186-input",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage184-same-corpus-daemon-execution-smoke --execute-smoke --root /tmp/dae-stage184-stage186-input --stage183-root /tmp/dae-stage183-stage186-input",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage185-production-dataplane-listener-tc-ebpf-evidence-gate --write-evidence-gate --root /tmp/dae-stage185-stage186-input --stage184-root /tmp/dae-stage184-stage186-input",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage186-reload-runtime-parity-evidence-gate --write-parity-gate --root /tmp/dae-stage186-reload-runtime-parity --stage185-root /tmp/dae-stage185-stage186-input",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage186 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage186 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage185 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli -p dae-product -q",
        "cargo fmt --manifest-path rust/Cargo.toml --all -- --check",
        "git diff --check"
    ]);
    report["source"] = json!([
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

fn write_stage186_parity_gate(root: &str, stage185_root: &str) -> Result<Value, String> {
    let root_path = Path::new(root);
    let stage185_path = Path::new(stage185_root);
    validate_stage186_root(root_path)?;
    validate_stage185_root(stage185_path)?;
    if root_path.exists() {
        return Err(format!(
            "stage186 root already exists, remove it first: {}",
            root_path.display()
        ));
    }
    if !stage185_path.is_dir() {
        return Err(format!(
            "stage185 root does not exist or is not a directory: {}",
            stage185_path.display()
        ));
    }

    let stage185_verification = verify_stage185_bundle(stage185_path)?;
    fs::create_dir_all(root_path).map_err(|err| format!("create stage186 root failed: {err}"))?;

    write_json(
        root_path,
        "prior/stage185-evidence-verification.json",
        &stage185_verification,
    )?;
    write_json(
        root_path,
        "runtime/listener-reuse-contract.json",
        &listener_reuse_contract(),
    )?;
    write_json(
        root_path,
        "runtime/bpf-owner-transfer-contract.json",
        &bpf_owner_transfer_contract(),
    )?;
    write_json(
        root_path,
        "runtime/dns-cache-migration-guard.json",
        &dns_cache_migration_guard(),
    )?;
    write_json(
        root_path,
        "runtime/bounded-close-runtime-overview-contract.json",
        &bounded_close_runtime_overview_contract(),
    )?;
    write_json(
        root_path,
        "shared/gate-summary.json",
        &json!({ "gates": gate_summary(true) }),
    )?;
    write_json(
        root_path,
        "next/stage187-matched-benchmark-readiness-input.json",
        &json!({
            "stage": "stage186",
            "next_stage": "stage187",
            "stage185_evidence_verified": true,
            "reload_runtime_parity_contract_written": true,
            "production_dataplane_admitted": false,
            "reload_runtime_parity_admitted": false,
            "benchmark_executable_now": false,
            "requires_benchmark_readiness_gate": true,
            "requires_real_production_dataplane_execution": true,
            "requires_same_corpus_go_rust_daemon_benchmark": true
        }),
    )?;

    let manifest = json!({
        "stage": "stage186",
        "bundle": "reload-runtime-parity-evidence-gate",
        "root": path_string(root_path),
        "stage185_root": path_string(stage185_path),
        "expected_file_count": stage186_files().len(),
        "files_written_count": stage186_files().len(),
        "missing_files": [],
        "stage185_verification": stage185_verification,
        "reload_runtime_parity_contract_written": true,
        "benchmark_readiness_input_written": true,
        "live_reload_executed": false,
        "production_listener_reused": false,
        "production_bpf_owner_transferred": false,
        "production_dns_cache_migrated": false,
        "runtime_overview_parity_admitted": false,
        "production_dataplane_admitted": false,
        "reload_runtime_parity_admitted": false,
        "benchmark_executable_now": false,
        "matched_go_rust_default_daemon_benchmark_recorded": false,
        "default_switch_allowed": false
    });
    write_json(root_path, "manifest.json", &manifest)?;

    let missing = stage186_files()
        .iter()
        .filter(|relative| !root_path.join(relative).is_file())
        .copied()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(format!(
            "stage186 parity gate missing files after write: {missing:?}"
        ));
    }

    Ok(json!({
        "root": path_string(root_path),
        "stage185_root": path_string(stage185_path),
        "expected_file_count": stage186_files().len(),
        "files_written_count": stage186_files().len(),
        "missing_files": [],
        "stage185_evidence_verified": true,
        "stage185_dataplane_contract_carried": true,
        "reload_runtime_parity_contract_written": true,
        "benchmark_readiness_input_written": true,
        "production_dataplane_gate": "evidence_contract_prepared",
        "reload_runtime_parity_gate": "contract_prepared",
        "production_dataplane_admitted": false,
        "reload_runtime_parity_admitted": false,
        "benchmark_executable_now": false,
        "matched_go_rust_default_daemon_benchmark_recorded": false,
        "default_switch_allowed": false
    }))
}

fn verify_stage185_bundle(stage185_root: &Path) -> Result<Value, String> {
    let missing = stage185_files()
        .iter()
        .filter(|relative| !stage185_root.join(relative).is_file())
        .copied()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(format!(
            "stage185 evidence bundle missing required files: {missing:?}"
        ));
    }

    let manifest = read_json(stage185_root, "manifest.json")?;
    expect_str(
        &manifest,
        "stage",
        "stage185",
        "stage185 manifest stage mismatch",
    )?;
    expect_bool(
        &manifest,
        "production_dataplane_evidence_contract_written",
        true,
        "stage185 dataplane evidence contract not written",
    )?;
    expect_bool(
        &manifest,
        "production_dataplane_admitted",
        false,
        "stage185 unexpectedly admitted production dataplane",
    )?;

    let gate_summary = read_json(stage185_root, "shared/gate-summary.json")?;
    let gate_status = gate_summary
        .get("gates")
        .and_then(Value::as_array)
        .and_then(|gates| {
            gates.iter().find_map(|gate| {
                (gate.get("gate").and_then(Value::as_str) == Some("production_dataplane_gate"))
                    .then(|| gate.get("status").and_then(Value::as_str))
                    .flatten()
            })
        });
    if gate_status != Some("evidence_contract_prepared") {
        return Err(format!(
            "stage185 production_dataplane_gate mismatch: expected evidence_contract_prepared, got {:?}",
            gate_status
        ));
    }

    let next = read_json(
        stage185_root,
        "next/stage186-reload-runtime-parity-input.json",
    )?;
    for key in [
        "requires_reload_runtime_parity",
        "requires_listener_reuse",
        "requires_bpf_owner_transfer",
        "requires_dns_cache_migration_guard",
        "requires_runtime_overview_parity",
    ] {
        expect_bool(
            &next,
            key,
            true,
            "stage185 next-stage input missing required flag",
        )?;
    }

    Ok(json!({
        "stage185_root": path_string(stage185_root),
        "required_files_verified": true,
        "required_file_count": stage185_files().len(),
        "stage185_dataplane_contract_carried": true,
        "production_dataplane_gate": "evidence_contract_prepared",
        "production_dataplane_admitted": false,
        "reload_runtime_input_verified": true,
        "benchmark_executable_now": false,
        "default_switch_allowed": false
    }))
}

fn listener_reuse_contract() -> Value {
    json!({
        "stage": "stage186",
        "contract": "reload listener reuse parity",
        "source": "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.4,15.5",
        "required_sequence": [
            "old control plane Close causes old Serve loop to return ServeResult",
            "old ServeResult must carry reusable listener",
            "new control plane calls startServe with the old listener",
            "reload does not close and re-listen production port",
            "reload callback fires only after new Serve ready"
        ],
        "live_reload_executed": false,
        "production_listener_reused": false,
        "reload_runtime_parity_admitted": false
    })
}

fn bpf_owner_transfer_contract() -> Value {
    json!({
        "stage": "stage186",
        "contract": "linear BPF owner transfer parity",
        "source": "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.4,15.8",
        "required_sequence": [
            "old control plane EjectBpf",
            "new control plane build with ejected object",
            "new control plane InjectBpf",
            "current pointer swap",
            "old control plane Close after swap",
            "rollback closes or returns ejected BPF on failure"
        ],
        "production_bpf_owner_transferred": false,
        "rollback_contract_recorded": true,
        "reload_runtime_parity_admitted": false
    })
}

fn dns_cache_migration_guard() -> Value {
    json!({
        "stage": "stage186",
        "contract": "DNS cache migration guard",
        "source": "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.4,15.8",
        "migration_allowed_when": "old and new DNS config are exactly equal",
        "migration_forbidden_when": "DNS config changes in any field",
        "same_dns_bind_guard": "old DNS listener must stop before new control plane binds the same dns.bind",
        "production_dns_cache_migrated": false,
        "reload_runtime_parity_admitted": false
    })
}

fn bounded_close_runtime_overview_contract() -> Value {
    json!({
        "stage": "stage186",
        "contract": "bounded close and RuntimeOverview parity",
        "source": "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.5,15.8",
        "bounded_close": {
            "control_plane_serve_shutdown_grace_time": "2s",
            "close_order": [
                "cancel context",
                "Serve loop exits",
                "defer funcs execute in reverse order",
                "core closes"
            ]
        },
        "runtime_overview_requirements": [
            "current control plane pointer reflects the active owner after reload",
            "listener reuse state is observable",
            "BPF ownership state is observable",
            "DNS cache migration guard state is observable",
            "reload progress reaches done only after new Serve ready"
        ],
        "runtime_overview_parity_admitted": false,
        "reload_runtime_parity_admitted": false
    })
}

fn reload_runtime_rows(written: bool) -> Value {
    let status = if written {
        "contract-written"
    } else {
        "requires-explicit-stage186-writer"
    };
    json!([
        {
            "area": "listener reuse",
            "status": status,
            "evidence": "Stage186 records old ServeResult listener reuse and forbids close/listen reload behavior",
            "boundary": "does not execute live production reload",
            "closed_flag": "production_listener_reused=false"
        },
        {
            "area": "BPF owner transfer",
            "status": status,
            "evidence": "Stage186 records old EjectBpf -> new InjectBpf -> current swap -> old close sequence",
            "boundary": "does not transfer a real production BPF object",
            "closed_flag": "production_bpf_owner_transferred=false"
        },
        {
            "area": "DNS cache migration guard",
            "status": status,
            "evidence": "Stage186 records DNS cache migration only when DNS configs are exactly equal",
            "boundary": "does not migrate a live DNS cache",
            "closed_flag": "production_dns_cache_migrated=false"
        },
        {
            "area": "bounded close and RuntimeOverview",
            "status": status,
            "evidence": "Stage186 records 2s bounded close and RuntimeOverview parity requirements",
            "boundary": "RuntimeOverview parity is not admitted until live evidence exists",
            "closed_flag": "runtime_overview_parity_admitted=false"
        },
        {
            "area": "benchmark/default safety",
            "status": "closed-preserved",
            "evidence": "Stage186 writes benchmark-readiness input while keeping benchmark/default closed",
            "boundary": "reload/runtime parity contract is not matched benchmark data",
            "closed_flag": "benchmark_executable_now=false"
        }
    ])
}

fn gate_summary(_written: bool) -> Value {
    json!([
        {
            "gate": "corpus_gate",
            "status": "prepared_for_daemon_smoke",
            "opens_after": "Stage183 reviewed corpus binding remains carried through Stage184-186"
        },
        {
            "gate": "rust_production_command_gate",
            "status": "closed",
            "opens_after": "production-shaped Rust dae run command identity is proven beyond Stage156 opt-in"
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
            "opens_after": "same-corpus Go/Rust default daemon benchmark executes after dataplane and reload/runtime parity pass"
        },
        {
            "gate": "default_product_switch_gate",
            "status": "closed",
            "opens_after": "matched benchmark results and default/product recertification pass"
        }
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
            .map_err(|err| format!("create stage186 parent {} failed: {err}", parent.display()))?;
    }
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|err| format!("encode stage186 file {} failed: {err}", path.display()))?;
    fs::write(&path, bytes)
        .map_err(|err| format!("write stage186 file {} failed: {err}", path.display()))
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

fn validate_stage186_root(path: &Path) -> Result<(), String> {
    if !path.is_absolute() {
        return Err("stage186 root must be absolute".to_string());
    }
    if !path.to_string_lossy().starts_with("/tmp/dae-stage186") {
        return Err("stage186 root must be under /tmp/dae-stage186*".to_string());
    }
    Ok(())
}

fn validate_stage185_root(path: &Path) -> Result<(), String> {
    if !path.is_absolute() {
        return Err("stage185 root must be absolute".to_string());
    }
    if !path.to_string_lossy().starts_with("/tmp/dae-stage185") {
        return Err("stage185 root must be under /tmp/dae-stage185*".to_string());
    }
    Ok(())
}

fn stage185_files() -> Vec<&'static str> {
    vec![
        "manifest.json",
        "prior/stage184-smoke-verification.json",
        "dataplane/listener-socket-map-contract.json",
        "dataplane/tc-ebpf-attach-contract.json",
        "dataplane/bpf-owner-handoff-contract.json",
        "shared/gate-summary.json",
        "next/stage186-reload-runtime-parity-input.json",
    ]
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

fn path_string(path: &Path) -> String {
    path.display().to_string()
}
