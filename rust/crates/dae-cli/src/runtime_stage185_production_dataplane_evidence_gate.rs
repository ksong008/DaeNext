use std::fs;
use std::path::Path;

use serde_json::{Value, json};

use crate::runner::RunnerOutput;

enum Stage185Mode<'a> {
    ReadOnly,
    WriteEvidenceGate {
        root: &'a str,
        stage184_root: &'a str,
    },
}

pub(crate) fn run_stage185_production_dataplane_evidence_gate(args: &[String]) -> RunnerOutput {
    match parse_stage185_args(args) {
        Ok(Stage185Mode::ReadOnly) => RunnerOutput::ok(format!("{}\n", stage185_report(None))),
        Ok(Stage185Mode::WriteEvidenceGate {
            root,
            stage184_root,
        }) => match write_stage185_evidence_gate(root, stage184_root) {
            Ok(result) => RunnerOutput::ok(format!("{}\n", stage185_report(Some(result)))),
            Err(err) => RunnerOutput::stdout_error(err),
        },
        Err(err) => RunnerOutput::usage(err),
    }
}

fn parse_stage185_args(args: &[String]) -> Result<Stage185Mode<'_>, String> {
    let mut write = false;
    let mut root = None;
    let mut stage184_root = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--write-evidence-gate" => write = true,
            "--root" => {
                let Some(value) = iter.next() else {
                    return Err("stage185 --root requires a value".to_string());
                };
                root = Some(value.as_str());
            }
            _ if arg.starts_with("--root=") => root = arg.split_once('=').map(|(_, value)| value),
            "--stage184-root" => {
                let Some(value) = iter.next() else {
                    return Err("stage185 --stage184-root requires a value".to_string());
                };
                stage184_root = Some(value.as_str());
            }
            _ if arg.starts_with("--stage184-root=") => {
                stage184_root = arg.split_once('=').map(|(_, value)| value);
            }
            _ => return Err(format!("unsupported stage185 argument: {arg}")),
        }
    }
    match (write, root, stage184_root) {
        (false, None, None) => Ok(Stage185Mode::ReadOnly),
        (false, Some(_), _) | (false, _, Some(_)) => {
            Err("stage185 --root/--stage184-root require --write-evidence-gate".to_string())
        }
        (true, Some(root), Some(stage184_root)) => Ok(Stage185Mode::WriteEvidenceGate {
            root,
            stage184_root,
        }),
        (true, None, _) => Err("stage185 --write-evidence-gate requires --root".to_string()),
        (true, _, None) => {
            Err("stage185 --write-evidence-gate requires --stage184-root".to_string())
        }
    }
}

fn stage185_report(write_result: Option<Value>) -> Value {
    let written = write_result.is_some();
    let mut report = json!({
        "name": "stage185-production-dataplane-listener-tc-ebpf-evidence-gate",
        "stage": "stage185",
        "prior_gate": "stage184-same-corpus-daemon-execution-smoke",
        "evidence_class": "explicit-temp-root-production-dataplane-evidence-contract-gate",
        "read_only": !written,
        "write_evidence_gate": written,
        "artifact_root_policy": "explicit /tmp/dae-stage185* root only",
        "stage184_root_policy": "explicit /tmp/dae-stage184* root containing Stage184 same-corpus smoke evidence",
        "benchmark_executable_now": false,
        "matched_go_rust_default_daemon_benchmark_recorded": false,
        "true_rust_default_daemon_admitted": false,
        "default_switch_allowed": false,
        "product_chain_switch_allowed": false
    });
    for key in [
        "production_dataplane_evidence_gate_available",
        "stage184_explicit_smoke_required",
        "listener_socket_map_contract_available",
        "tc_ebpf_attach_contract_available",
        "bpf_owner_handoff_contract_available",
        "go_default_path_preserved",
        "go_fallback_required",
        "benchmark_exclusion_checked",
    ] {
        report[key] = json!(true);
    }
    for key in [
        "stage184_smoke_verified",
        "stage184_daemon_execution_gate_carried",
        "go_rust_identity_smoke_carried",
        "production_dataplane_evidence_contract_written",
        "stage186_reload_runtime_input_written",
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
        "reload_runtime_parity_admitted",
        "real_benchmark_corpus_materialized",
        "default_path_mutation_allowed",
    ] {
        report[key] = json!(false);
    }
    report["stage184_required_files"] = json!(stage184_files());
    report["stage185_expected_files"] = json!(stage185_files());
    report["dataplane_contract_rows"] = dataplane_contract_rows(written);
    report["gate_summary"] = gate_summary(written);
    report["gate_decision"] = json!(
        "Stage185 verifies Stage184 explicit same-corpus identity smoke and writes a production dataplane listener/tc/eBPF evidence contract. It does not bind production listeners, write the production listen_socket_map, attach tc/eBPF programs, admit production dataplane, record matched benchmark data, or switch default/product paths"
    );
    report["remaining_blockers"] = json!([
        "production Rust dae run command remains closed",
        "production listener bind and listen_socket_map mutation have not executed",
        "production tc attach and eBPF object load/ownership have not executed",
        "reload listener reuse, BPF owner transfer, DNS cache migration, bounded close, and RuntimeOverview parity are still missing",
        "matched Go/Rust default daemon benchmark has not executed",
        "default daemon and product-chain switches remain closed"
    ]);
    report["next_admission_queue"] = json!([
        {
            "stage": "stage186",
            "target": "reload/runtime parity evidence gate",
            "required_output": "consume Stage185 dataplane evidence contract and prove listener reuse, BPF owner transfer, DNS cache migration guard, bounded close, and RuntimeOverview parity before benchmark"
        }
    ]);
    report["validation_commands"] = json!([
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage185/production_dataplane_listener_tc_ebpf_evidence_gate.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage185_production_dataplane_listener_tc_ebpf_evidence_gate.json",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage185-production-dataplane-listener-tc-ebpf-evidence-gate",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage183-corpus-command-admission-binding-dry-run --write-admission-dry-run --root /tmp/dae-stage183-stage185-input",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage184-same-corpus-daemon-execution-smoke --execute-smoke --root /tmp/dae-stage184-stage185-input --stage183-root /tmp/dae-stage183-stage185-input",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage185-production-dataplane-listener-tc-ebpf-evidence-gate --write-evidence-gate --root /tmp/dae-stage185-production-dataplane-evidence --stage184-root /tmp/dae-stage184-stage185-input",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage185 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage185 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage184 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli -p dae-product -q",
        "cargo fmt --manifest-path rust/Cargo.toml --all -- --check",
        "git diff --check"
    ]);
    report["source"] = json!([
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage185",
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage184",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.5",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:22.2",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:22.6",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:22.8",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:22.12"
    ]);
    if let Some(result) = write_result {
        report["write_result"] = result;
    }
    report
}

fn write_stage185_evidence_gate(root: &str, stage184_root: &str) -> Result<Value, String> {
    let root_path = Path::new(root);
    let stage184_path = Path::new(stage184_root);
    validate_stage185_root(root_path)?;
    validate_stage184_root(stage184_path)?;
    if root_path.exists() {
        return Err(format!(
            "stage185 root already exists, remove it first: {}",
            root_path.display()
        ));
    }
    if !stage184_path.is_dir() {
        return Err(format!(
            "stage184 root does not exist or is not a directory: {}",
            stage184_path.display()
        ));
    }

    let stage184_verification = verify_stage184_smoke(stage184_path)?;
    fs::create_dir_all(root_path).map_err(|err| format!("create stage185 root failed: {err}"))?;

    write_json(
        root_path,
        "prior/stage184-smoke-verification.json",
        &stage184_verification,
    )?;
    write_json(
        root_path,
        "dataplane/listener-socket-map-contract.json",
        &listener_socket_map_contract(),
    )?;
    write_json(
        root_path,
        "dataplane/tc-ebpf-attach-contract.json",
        &tc_ebpf_attach_contract(),
    )?;
    write_json(
        root_path,
        "dataplane/bpf-owner-handoff-contract.json",
        &bpf_owner_handoff_contract(),
    )?;
    write_json(
        root_path,
        "shared/gate-summary.json",
        &json!({ "gates": gate_summary(true) }),
    )?;
    write_json(
        root_path,
        "next/stage186-reload-runtime-parity-input.json",
        &json!({
            "stage": "stage185",
            "next_stage": "stage186",
            "stage184_smoke_verified": true,
            "production_dataplane_evidence_contract_written": true,
            "production_dataplane_admitted": false,
            "requires_reload_runtime_parity": true,
            "requires_listener_reuse": true,
            "requires_bpf_owner_transfer": true,
            "requires_dns_cache_migration_guard": true,
            "requires_runtime_overview_parity": true,
            "benchmark_executable_now": false
        }),
    )?;

    let manifest = json!({
        "stage": "stage185",
        "bundle": "production-dataplane-listener-tc-ebpf-evidence-gate",
        "root": path_string(root_path),
        "stage184_root": path_string(stage184_path),
        "expected_file_count": stage185_files().len(),
        "files_written_count": stage185_files().len(),
        "missing_files": [],
        "stage184_verification": stage184_verification,
        "production_dataplane_evidence_contract_written": true,
        "production_listener_bound": false,
        "listen_socket_map_written": false,
        "production_tc_attach_smoke_passed": false,
        "ebpf_attached": false,
        "production_dataplane_admitted": false,
        "benchmark_executable_now": false,
        "matched_go_rust_default_daemon_benchmark_recorded": false,
        "default_switch_allowed": false
    });
    write_json(root_path, "manifest.json", &manifest)?;

    let missing = stage185_files()
        .iter()
        .filter(|relative| !root_path.join(relative).is_file())
        .copied()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(format!(
            "stage185 evidence gate missing files after write: {missing:?}"
        ));
    }

    Ok(json!({
        "root": path_string(root_path),
        "stage184_root": path_string(stage184_path),
        "expected_file_count": stage185_files().len(),
        "files_written_count": stage185_files().len(),
        "missing_files": [],
        "stage184_smoke_verified": true,
        "stage184_daemon_execution_gate_carried": true,
        "go_rust_identity_smoke_carried": true,
        "production_dataplane_evidence_contract_written": true,
        "stage186_reload_runtime_input_written": true,
        "production_dataplane_gate": "evidence_contract_prepared",
        "production_dataplane_admitted": false,
        "benchmark_executable_now": false,
        "matched_go_rust_default_daemon_benchmark_recorded": false,
        "default_switch_allowed": false
    }))
}

fn verify_stage184_smoke(stage184_root: &Path) -> Result<Value, String> {
    let missing = stage184_files()
        .iter()
        .filter(|relative| !stage184_root.join(relative).is_file())
        .copied()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(format!(
            "stage184 smoke bundle missing required files: {missing:?}"
        ));
    }

    let manifest = read_json(stage184_root, "manifest.json")?;
    expect_str(
        &manifest,
        "stage",
        "stage184",
        "stage184 manifest stage mismatch",
    )?;
    expect_str(
        &manifest,
        "daemon_execution_gate",
        "identity_smoke_passed",
        "stage184 daemon gate mismatch",
    )?;
    expect_bool(
        &manifest,
        "same_corpus_identity_smoke_passed",
        true,
        "stage184 same corpus smoke not passed",
    )?;
    expect_bool(
        &manifest,
        "production_dataplane_admitted",
        false,
        "stage184 unexpectedly admitted production dataplane",
    )?;

    let summary = read_json(stage184_root, "shared/same-corpus-execution-smoke.json")?;
    expect_bool(
        &summary,
        "go_default_identity_smoke_passed",
        true,
        "stage184 Go identity smoke not passed",
    )?;
    expect_bool(
        &summary,
        "rust_optin_identity_smoke_passed",
        true,
        "stage184 Rust identity smoke not passed",
    )?;

    let go = read_json(stage184_root, "go/run/go-default-daemon-identity.json")?;
    expect_bool(
        &go,
        "start_stop_identity_smoke_passed",
        true,
        "stage184 Go start/stop identity smoke not passed",
    )?;
    let rust = read_json(stage184_root, "rust/run/rust-optin-stage156-identity.json")?;
    expect_bool(
        &rust,
        "start_stop_identity_smoke_passed",
        true,
        "stage184 Rust start/stop identity smoke not passed",
    )?;

    Ok(json!({
        "stage184_root": path_string(stage184_root),
        "required_files_verified": true,
        "required_file_count": stage184_files().len(),
        "stage184_daemon_execution_gate_carried": true,
        "same_corpus_identity_smoke_passed": true,
        "go_default_identity_smoke_passed": true,
        "rust_optin_identity_smoke_passed": true,
        "production_dataplane_admitted": false,
        "benchmark_executable_now": false,
        "default_switch_allowed": false
    }))
}

fn listener_socket_map_contract() -> Value {
    json!({
        "stage": "stage185",
        "contract": "production listener and listen_socket_map evidence",
        "source": "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.5,22.8",
        "required_listener_sequence": [
            "create TCP listener with tproxy control",
            "create UDP listener with tproxy control",
            "write listen_socket_map key 0 with TCP listener fd",
            "write listen_socket_map key 1 with UDP socket fd",
            "signal ready only after both sockmap writes succeed"
        ],
        "listen_socket_map": [
            { "key": 0, "socket": "tcp-listener-fd" },
            { "key": 1, "socket": "udp-socket-fd" }
        ],
        "production_listener_bound": false,
        "listen_socket_map_written": false,
        "ready_signal_allowed": false
    })
}

fn tc_ebpf_attach_contract() -> Value {
    json!({
        "stage": "stage185",
        "contract": "production tc and eBPF attach evidence",
        "source": "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:22.2,22.6,22.8",
        "required_attach_rows": [
            {
                "area": "new control plane boot",
                "required_order": "netns setup before BPF load, BPF load before LAN/WAN/dae0 attach, routing map after matcher build",
                "verified_now": false
            },
            {
                "area": "LAN/WAN tc attach",
                "required_order": "clsact qdisc, handle/priority parity, L2/L3 program selection, reload flip safety",
                "verified_now": false
            },
            {
                "area": "dae0/dae0peer tc attach",
                "required_order": "dae0peer ingress in daens and dae0 ingress in host netns with matching handles",
                "verified_now": false
            },
            {
                "area": "pinned maps",
                "required_order": "preserve tgid_pname_map, routing_tuples_map, cookie_pid_map pin behavior and do not pin domain_routing_map",
                "verified_now": false
            }
        ],
        "production_tc_attach_smoke_passed": false,
        "ebpf_attached": false,
        "production_dataplane_admitted": false
    })
}

fn bpf_owner_handoff_contract() -> Value {
    json!({
        "stage": "stage185",
        "contract": "BPF owner handoff evidence boundary",
        "source": "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:22.12",
        "required_reload_sequence": [
            "old control plane EjectBpf",
            "new control plane builds with reused BPF object",
            "new control plane InjectBpf",
            "current pointer swaps only after new control plane is valid",
            "old control plane Close does not close ejected BPF",
            "new owner restores BPF Close into its lifecycle"
        ],
        "owner_transfer_verified_now": false,
        "reload_runtime_parity_admitted": false,
        "stage186_required": true
    })
}

fn dataplane_contract_rows(written: bool) -> Value {
    let status = if written {
        "contract-written"
    } else {
        "requires-explicit-stage185-writer"
    };
    json!([
        {
            "area": "production listener and listen_socket_map",
            "status": status,
            "evidence": "Stage185 records TCP key 0 and UDP key 1 sockmap contract from daenew",
            "boundary": "does not bind production listener or write production sockmap",
            "closed_flag": "production_listener_bound=false"
        },
        {
            "area": "tc/eBPF attach",
            "status": status,
            "evidence": "Stage185 records netns, BPF load, LAN/WAN/dae0 attach, handle, priority, and pinning contract",
            "boundary": "does not load production BPF object or attach tc hooks",
            "closed_flag": "ebpf_attached=false"
        },
        {
            "area": "BPF owner handoff",
            "status": status,
            "evidence": "Stage185 records EjectBpf/InjectBpf owner transfer contract for Stage186",
            "boundary": "does not prove reload/runtime parity yet",
            "closed_flag": "reload_runtime_parity_admitted=false"
        },
        {
            "area": "benchmark/default safety",
            "status": "closed-preserved",
            "evidence": "Stage185 carries Stage184 identity smoke while keeping benchmark and default switch closed",
            "boundary": "dataplane evidence contract is not matched benchmark data",
            "closed_flag": "benchmark_executable_now=false"
        }
    ])
}

fn gate_summary(written: bool) -> Value {
    let dataplane_status = if written {
        "evidence_contract_prepared"
    } else {
        "requires_explicit_stage185_evidence"
    };
    json!([
        {
            "gate": "corpus_gate",
            "status": "prepared_for_daemon_smoke",
            "opens_after": "Stage183 reviewed corpus binding remains carried through Stage184/185"
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
            "status": dataplane_status,
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
            .map_err(|err| format!("create stage185 parent {} failed: {err}", parent.display()))?;
    }
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|err| format!("encode stage185 file {} failed: {err}", path.display()))?;
    fs::write(&path, bytes)
        .map_err(|err| format!("write stage185 file {} failed: {err}", path.display()))
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

fn validate_stage185_root(path: &Path) -> Result<(), String> {
    if !path.is_absolute() {
        return Err("stage185 root must be absolute".to_string());
    }
    if !path.to_string_lossy().starts_with("/tmp/dae-stage185") {
        return Err("stage185 root must be under /tmp/dae-stage185*".to_string());
    }
    Ok(())
}

fn validate_stage184_root(path: &Path) -> Result<(), String> {
    if !path.is_absolute() {
        return Err("stage184 root must be absolute".to_string());
    }
    if !path.to_string_lossy().starts_with("/tmp/dae-stage184") {
        return Err("stage184 root must be under /tmp/dae-stage184*".to_string());
    }
    Ok(())
}

fn stage184_files() -> Vec<&'static str> {
    vec![
        "manifest.json",
        "shared/stage183-reviewed-corpus-identity.dae",
        "shared/same-corpus-execution-smoke.json",
        "shared/gate-summary.json",
        "go/run/go-default-daemon-identity.json",
        "go/run/dae-go.pid",
        "go/run/dae-go.progress",
        "go/log/dae-go.log",
        "rust/run/rust-optin-stage156-identity.json",
        "rust/log/dae-rust.log",
    ]
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

fn path_string(path: &Path) -> String {
    path.display().to_string()
}
