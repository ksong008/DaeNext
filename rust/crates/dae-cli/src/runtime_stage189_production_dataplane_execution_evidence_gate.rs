use std::fs;
use std::path::Path;

use serde_json::{Value, json};

use crate::runner::RunnerOutput;

enum Stage189Mode<'a> {
    ReadOnly,
    WriteEvidence {
        root: &'a str,
        stage188_root: &'a str,
    },
}

pub(crate) fn run_stage189_production_dataplane_execution_evidence_gate(
    args: &[String],
) -> RunnerOutput {
    match parse_stage189_args(args) {
        Ok(Stage189Mode::ReadOnly) => RunnerOutput::ok(format!("{}\n", stage189_report(None))),
        Ok(Stage189Mode::WriteEvidence {
            root,
            stage188_root,
        }) => match write_stage189_evidence(root, stage188_root) {
            Ok(result) => RunnerOutput::ok(format!("{}\n", stage189_report(Some(result)))),
            Err(err) => RunnerOutput::stdout_error(err),
        },
        Err(err) => RunnerOutput::usage(err),
    }
}

fn parse_stage189_args(args: &[String]) -> Result<Stage189Mode<'_>, String> {
    let mut write = false;
    let mut root = None;
    let mut stage188_root = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--write-evidence" => write = true,
            "--root" => {
                let Some(value) = iter.next() else {
                    return Err("stage189 --root requires a value".to_string());
                };
                root = Some(value.as_str());
            }
            _ if arg.starts_with("--root=") => root = arg.split_once('=').map(|(_, value)| value),
            "--stage188-root" => {
                let Some(value) = iter.next() else {
                    return Err("stage189 --stage188-root requires a value".to_string());
                };
                stage188_root = Some(value.as_str());
            }
            _ if arg.starts_with("--stage188-root=") => {
                stage188_root = arg.split_once('=').map(|(_, value)| value);
            }
            _ => return Err(format!("unsupported stage189 argument: {arg}")),
        }
    }
    match (write, root, stage188_root) {
        (false, None, None) => Ok(Stage189Mode::ReadOnly),
        (false, Some(_), _) | (false, _, Some(_)) => {
            Err("stage189 --root/--stage188-root require --write-evidence".to_string())
        }
        (true, Some(root), Some(stage188_root)) => Ok(Stage189Mode::WriteEvidence {
            root,
            stage188_root,
        }),
        (true, None, _) => Err("stage189 --write-evidence requires --root".to_string()),
        (true, _, None) => Err("stage189 --write-evidence requires --stage188-root".to_string()),
    }
}

fn stage189_report(write_result: Option<Value>) -> Value {
    let written = write_result.is_some();
    let mut report = json!({
        "name": "stage189-production-dataplane-execution-evidence-gate",
        "stage": "stage189",
        "prior_gate": "stage188-bounded-benchmark-hard-gate-resolution",
        "evidence_class": "explicit-temp-root-production-dataplane-execution-evidence-gap",
        "read_only": !written,
        "write_evidence": written,
        "artifact_root_policy": "explicit /tmp/dae-stage189* root only",
        "stage188_root_policy": "explicit /tmp/dae-stage188* root containing Stage188 hard-gate resolution bundle",
        "benchmark_executable_now": false,
        "matched_go_rust_default_daemon_benchmark_recorded": false,
        "true_rust_default_daemon_admitted": false,
        "default_switch_allowed": false,
        "product_chain_switch_allowed": false
    });
    for key in [
        "production_dataplane_execution_evidence_gate_available",
        "stage188_resolution_bundle_required",
        "stage188_bundle_verifier_available",
        "listener_sockmap_gap_available",
        "tc_ebpf_attach_gap_available",
        "netns_dae0_gap_available",
        "bpf_owner_handoff_gap_available",
        "go_default_path_preserved",
        "go_fallback_required",
        "benchmark_exclusion_checked",
    ] {
        report[key] = json!(true);
    }
    for key in [
        "stage188_resolution_bundle_verified",
        "listener_sockmap_gap_written",
        "tc_ebpf_attach_gap_written",
        "netns_dae0_gap_written",
        "bpf_owner_handoff_gap_written",
        "stage190_reload_runtime_input_written",
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
        "netns_setup_executed",
        "dae0_attach_executed",
        "bpf_owner_handoff_executed",
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
    report["stage188_required_files"] = json!(stage188_files());
    report["stage189_expected_files"] = json!(stage189_files());
    report["dataplane_gap_rows"] = dataplane_gap_rows(written);
    report["gate_summary"] = gate_summary();
    report["gate_decision"] = json!(
        "Stage189 verifies the explicit Stage188 hard-gate resolution bundle and records production dataplane execution gaps. It does not bind production listeners, write production listen_socket_map entries, attach tc/eBPF programs, execute netns/dae0 setup, transfer production BPF ownership, run benchmark, or switch default/product paths"
    );
    report["remaining_blockers"] = remaining_blockers();
    report["next_admission_queue"] = json!([
        {
            "stage": "stage190",
            "target": "live reload/runtime parity execution evidence",
            "required_output": "execute listener reuse, BPF owner transfer, DNS cache migration guard, bounded close, and RuntimeOverview parity only after production dataplane evidence is admitted"
        },
        {
            "stage": "stage191",
            "target": "bounded same-corpus default daemon benchmark",
            "required_output": "run matched Go/Rust default daemon benchmark only after production dataplane and live reload/runtime parity pass"
        }
    ]);
    report["validation_commands"] = json!([
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage189/production_dataplane_execution_evidence_gate.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage189_production_dataplane_execution_evidence_gate.json",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage189-production-dataplane-execution-evidence-gate",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage183-corpus-command-admission-binding-dry-run --write-admission-dry-run --root /tmp/dae-stage183-stage189-input",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage184-same-corpus-daemon-execution-smoke --execute-smoke --root /tmp/dae-stage184-stage189-input --stage183-root /tmp/dae-stage183-stage189-input",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage185-production-dataplane-listener-tc-ebpf-evidence-gate --write-evidence-gate --root /tmp/dae-stage185-stage189-input --stage184-root /tmp/dae-stage184-stage189-input",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage186-reload-runtime-parity-evidence-gate --write-parity-gate --root /tmp/dae-stage186-stage189-input --stage185-root /tmp/dae-stage185-stage189-input",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage187-matched-benchmark-readiness-gate --write-readiness-gate --root /tmp/dae-stage187-stage189-input --stage186-root /tmp/dae-stage186-stage189-input",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage188-bounded-benchmark-hard-gate-resolution --write-resolution --root /tmp/dae-stage188-stage189-input --stage187-root /tmp/dae-stage187-stage189-input",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage189-production-dataplane-execution-evidence-gate --write-evidence --root /tmp/dae-stage189-production-dataplane-evidence --stage188-root /tmp/dae-stage188-stage189-input",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage189 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage189 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage188 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli -p dae-product -q",
        "cargo fmt --manifest-path rust/Cargo.toml --all -- --check",
        "git diff --check"
    ]);
    report["source"] = json!([
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage189",
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage188",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.5",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:22.2",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:22.8",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:22.12"
    ]);
    if let Some(result) = write_result {
        report["write_result"] = result;
    }
    report
}

fn write_stage189_evidence(root: &str, stage188_root: &str) -> Result<Value, String> {
    let root_path = Path::new(root);
    let stage188_path = Path::new(stage188_root);
    validate_stage189_root(root_path)?;
    validate_stage188_root(stage188_path)?;
    if root_path.exists() {
        return Err(format!(
            "stage189 root already exists, remove it first: {}",
            root_path.display()
        ));
    }
    if !stage188_path.is_dir() {
        return Err(format!(
            "stage188 root does not exist or is not a directory: {}",
            stage188_path.display()
        ));
    }

    let stage188_verification = verify_stage188_bundle(stage188_path)?;
    fs::create_dir_all(root_path).map_err(|err| format!("create stage189 root failed: {err}"))?;

    write_json(
        root_path,
        "prior/stage188-resolution-verification.json",
        &stage188_verification,
    )?;
    write_json(
        root_path,
        "dataplane/listener-sockmap-execution-gap.json",
        &listener_sockmap_execution_gap(),
    )?;
    write_json(
        root_path,
        "dataplane/tc-ebpf-attach-execution-gap.json",
        &tc_ebpf_attach_execution_gap(),
    )?;
    write_json(
        root_path,
        "dataplane/netns-dae0-execution-gap.json",
        &netns_dae0_execution_gap(),
    )?;
    write_json(
        root_path,
        "dataplane/bpf-owner-handoff-execution-gap.json",
        &bpf_owner_handoff_execution_gap(),
    )?;
    write_json(
        root_path,
        "shared/gate-summary.json",
        &json!({ "gates": gate_summary() }),
    )?;
    write_json(
        root_path,
        "next/stage190-live-reload-runtime-parity-input.json",
        &json!({
            "stage": "stage189",
            "next_stage": "stage190",
            "stage188_resolution_bundle_verified": true,
            "production_dataplane_execution_gap_recorded": true,
            "requires_real_production_listener_sockmap_execution": true,
            "requires_real_tc_ebpf_attach_execution": true,
            "requires_real_netns_dae0_execution": true,
            "requires_real_bpf_owner_handoff_execution": true,
            "production_dataplane_admitted": false,
            "reload_runtime_parity_execution_allowed": false,
            "benchmark_executable_now": false,
            "bounded_benchmark_execution_allowed": false,
            "default_switch_allowed": false
        }),
    )?;

    let manifest = json!({
        "stage": "stage189",
        "bundle": "production-dataplane-execution-evidence-gap",
        "root": path_string(root_path),
        "stage188_root": path_string(stage188_path),
        "expected_file_count": stage189_files().len(),
        "files_written_count": stage189_files().len(),
        "missing_files": [],
        "stage188_verification": stage188_verification,
        "listener_sockmap_gap_written": true,
        "tc_ebpf_attach_gap_written": true,
        "netns_dae0_gap_written": true,
        "bpf_owner_handoff_gap_written": true,
        "stage190_reload_runtime_input_written": true,
        "hard_gates_resolved": false,
        "production_listener_bound": false,
        "listen_socket_map_written": false,
        "production_tc_attach_smoke_passed": false,
        "ebpf_attached": false,
        "netns_setup_executed": false,
        "dae0_attach_executed": false,
        "bpf_owner_handoff_executed": false,
        "production_dataplane_admitted": false,
        "reload_runtime_parity_admitted": false,
        "benchmark_executable_now": false,
        "matched_go_rust_default_daemon_benchmark_recorded": false,
        "default_switch_allowed": false
    });
    write_json(root_path, "manifest.json", &manifest)?;

    let missing = stage189_files()
        .iter()
        .filter(|relative| !root_path.join(relative).is_file())
        .copied()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(format!(
            "stage189 evidence bundle missing files after write: {missing:?}"
        ));
    }

    Ok(json!({
        "root": path_string(root_path),
        "stage188_root": path_string(stage188_path),
        "expected_file_count": stage189_files().len(),
        "files_written_count": stage189_files().len(),
        "missing_files": [],
        "stage188_resolution_bundle_verified": true,
        "listener_sockmap_gap_written": true,
        "tc_ebpf_attach_gap_written": true,
        "netns_dae0_gap_written": true,
        "bpf_owner_handoff_gap_written": true,
        "stage190_reload_runtime_input_written": true,
        "production_dataplane_gate": "execution_gap_recorded",
        "hard_gates_resolved": false,
        "production_dataplane_admitted": false,
        "reload_runtime_parity_admitted": false,
        "benchmark_executable_now": false,
        "matched_go_rust_default_daemon_benchmark_recorded": false,
        "default_switch_allowed": false
    }))
}

fn verify_stage188_bundle(stage188_root: &Path) -> Result<Value, String> {
    let missing = stage188_files()
        .iter()
        .filter(|relative| !stage188_root.join(relative).is_file())
        .copied()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(format!(
            "stage188 resolution bundle missing required files: {missing:?}"
        ));
    }

    let manifest = read_json(stage188_root, "manifest.json")?;
    expect_str(
        &manifest,
        "stage",
        "stage188",
        "stage188 manifest stage mismatch",
    )?;
    for key in [
        "production_dataplane_execution_queue_written",
        "reload_runtime_parity_execution_queue_written",
        "benchmark_admission_blockers_written",
        "stage189_execution_input_written",
    ] {
        expect_bool(
            &manifest,
            key,
            true,
            "stage188 manifest missing required written flag",
        )?;
    }
    for key in [
        "hard_gates_resolved",
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
            "stage188 manifest unexpectedly opened a hard gate",
        )?;
    }

    let gate_summary = read_json(stage188_root, "shared/gate-summary.json")?;
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

    let dataplane_queue = read_json(
        stage188_root,
        "resolution/production-dataplane-execution-queue.json",
    )?;
    expect_bool(
        &dataplane_queue,
        "production_dataplane_admitted",
        false,
        "stage188 production dataplane queue unexpectedly admitted dataplane",
    )?;
    expect_bool(
        &dataplane_queue,
        "benchmark_executable_now",
        false,
        "stage188 production dataplane queue unexpectedly opened benchmark",
    )?;

    let next = read_json(
        stage188_root,
        "next/stage189-production-dataplane-execution-input.json",
    )?;
    for key in [
        "stage187_readiness_bundle_verified",
        "stage188_hard_gate_resolution_written",
        "production_dataplane_execution_required",
        "reload_runtime_parity_execution_required",
    ] {
        expect_bool(
            &next,
            key,
            true,
            "stage188 next-stage input missing required flag",
        )?;
    }
    for key in [
        "benchmark_executable_now",
        "bounded_benchmark_execution_allowed",
        "default_switch_allowed",
    ] {
        expect_bool(
            &next,
            key,
            false,
            "stage188 next-stage input unexpectedly opened a hard gate",
        )?;
    }

    Ok(json!({
        "stage188_root": path_string(stage188_root),
        "required_files_verified": true,
        "required_file_count": stage188_files().len(),
        "stage188_resolution_bundle_verified": true,
        "production_dataplane_execution_queue_verified": true,
        "stage189_execution_input_verified": true,
        "production_dataplane_gate": "evidence_contract_prepared",
        "production_dataplane_admitted": false,
        "benchmark_executable_now": false,
        "default_switch_allowed": false
    }))
}

fn listener_sockmap_execution_gap() -> Value {
    json!({
        "stage": "stage189",
        "gap": "production listener and listen_socket_map execution",
        "required_evidence": [
            "bind production-shaped TCP listener with tproxy socket options",
            "bind production-shaped UDP listener with tproxy socket options",
            "write TCP listener fd to listen_socket_map key 0 before ready",
            "write UDP conn fd to listen_socket_map key 1 before ready",
            "record bounded cleanup if either map write fails"
        ],
        "current_rust_evidence": [
            "Stage160 is an isolated listener/eBPF harness and does not mutate production listen_socket_map",
            "Stage185 records the listener/socket-map evidence contract only",
            "Stage188 records the production dataplane execution queue only"
        ],
        "production_listener_bound": false,
        "listen_socket_map_written": false,
        "production_dataplane_admitted": false,
        "source": "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.5"
    })
}

fn tc_ebpf_attach_execution_gap() -> Value {
    json!({
        "stage": "stage189",
        "gap": "production tc/eBPF attach execution",
        "required_evidence": [
            "load production eBPF object with production-compatible parameters",
            "attach tc programs on LAN/WAN/dae0/dae0peer equivalents in the audited order",
            "record attach ownership and cleanup handles",
            "prove rollback removes temporary production-equivalent attachments"
        ],
        "current_rust_evidence": [
            "Stage161 only proves temporary eBPF map preflight",
            "Stage162 only proves temporary socket-filter attach",
            "Stage185 records tc/eBPF attach contract only",
            "Stage188 records tc/eBPF execution queue only"
        ],
        "production_tc_attach_smoke_passed": false,
        "ebpf_attached": false,
        "production_dataplane_admitted": false,
        "source": "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:22.2,22.8"
    })
}

fn netns_dae0_execution_gap() -> Value {
    json!({
        "stage": "stage189",
        "gap": "production netns and dae0/dae0peer execution",
        "required_evidence": [
            "execute netns setup before BPF object load",
            "create and verify dae0/dae0peer production-equivalent link state",
            "record dae0/dae0peer attach points and runtime parameters",
            "prove cleanup restores link/netns state"
        ],
        "current_rust_evidence": [
            "Stage185 records production dataplane contract without netns execution",
            "Stage188 records netns/dae0 as part of the execution queue",
            "no Stage189 input proves production netns setup has run"
        ],
        "netns_setup_executed": false,
        "dae0_attach_executed": false,
        "production_dataplane_admitted": false,
        "source": "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:22.2,22.8"
    })
}

fn bpf_owner_handoff_execution_gap() -> Value {
    json!({
        "stage": "stage189",
        "gap": "production BPF owner handoff execution",
        "required_evidence": [
            "record production BPF object owner before reload handoff",
            "prove EjectBpf removes ownership from the old control plane",
            "prove InjectBpf moves ownership to the new control plane before old close",
            "record cleanup when replacement control plane fails"
        ],
        "current_rust_evidence": [
            "Stage164 uses a temporary SockMap owner handoff smoke",
            "Stage165 uses non-production daemon reload owner handoff",
            "Stage186 records reload/runtime parity contract only",
            "Stage188 records owner handoff execution queue only"
        ],
        "bpf_owner_handoff_executed": false,
        "production_bpf_owner_transferred": false,
        "production_dataplane_admitted": false,
        "source": "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:22.12"
    })
}

fn dataplane_gap_rows(written: bool) -> Value {
    let status = if written {
        "execution-gap-written"
    } else {
        "requires-explicit-stage189-writer"
    };
    json!([
        {
            "area": "Stage188 resolution verification",
            "status": status,
            "evidence": "Stage189 verifies the explicit Stage188 resolution bundle, manifest, production dataplane queue, gate summary, and Stage189 input",
            "boundary": "resolution verification is not production dataplane execution",
            "closed_flag": "production_dataplane_admitted=false"
        },
        {
            "area": "production listener and listen_socket_map",
            "status": status,
            "evidence": "Stage189 records the missing production TCP/UDP listener bind and listen_socket_map key 0/1 write evidence",
            "boundary": "does not bind listener or mutate production map",
            "closed_flag": "listen_socket_map_written=false"
        },
        {
            "area": "production tc/eBPF attach",
            "status": status,
            "evidence": "Stage189 records the missing production eBPF object load, tc attach, ownership, and cleanup evidence",
            "boundary": "does not attach tc/eBPF",
            "closed_flag": "ebpf_attached=false"
        },
        {
            "area": "netns and dae0/dae0peer",
            "status": status,
            "evidence": "Stage189 records the missing netns setup and dae0/dae0peer execution evidence required before production dataplane admission",
            "boundary": "does not modify netns or dae links",
            "closed_flag": "netns_setup_executed=false"
        },
        {
            "area": "BPF owner handoff",
            "status": status,
            "evidence": "Stage189 records the missing production BPF owner handoff evidence across reload boundaries",
            "boundary": "does not transfer production BPF ownership",
            "closed_flag": "bpf_owner_handoff_executed=false"
        },
        {
            "area": "benchmark/default safety",
            "status": "closed-preserved",
            "evidence": "Stage189 keeps benchmark and default/product switches closed because production dataplane execution is still not admitted",
            "boundary": "no benchmark data recorded",
            "closed_flag": "benchmark_executable_now=false"
        }
    ])
}

fn gate_summary() -> Value {
    json!([
        {
            "gate": "corpus_gate",
            "status": "prepared_for_daemon_smoke",
            "opens_after": "Stage183 reviewed corpus binding remains carried through Stage184-189"
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
            "status": "execution_gap_recorded",
            "opens_after": "real production listener bind, listen_socket_map key 0/1 write, netns/dae0 setup, tc/eBPF attach, and BPF owner handoff evidence pass"
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
        "production listener bind and listen_socket_map key 0/1 mutation have not executed",
        "production netns/dae0 setup and tc/eBPF attach have not executed",
        "production BPF object ownership handoff has not executed",
        "live reload/runtime parity has not executed after dataplane evidence",
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
            .map_err(|err| format!("create stage189 parent {} failed: {err}", parent.display()))?;
    }
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|err| format!("encode stage189 file {} failed: {err}", path.display()))?;
    fs::write(&path, bytes)
        .map_err(|err| format!("write stage189 file {} failed: {err}", path.display()))
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
        "stage188 gate {gate} mismatch: expected {expected}, got {status:?}"
    ))
}

fn validate_stage189_root(path: &Path) -> Result<(), String> {
    if !path.is_absolute() {
        return Err("stage189 root must be absolute".to_string());
    }
    if !path.to_string_lossy().starts_with("/tmp/dae-stage189") {
        return Err("stage189 root must be under /tmp/dae-stage189*".to_string());
    }
    Ok(())
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

fn stage189_files() -> Vec<&'static str> {
    vec![
        "manifest.json",
        "prior/stage188-resolution-verification.json",
        "dataplane/listener-sockmap-execution-gap.json",
        "dataplane/tc-ebpf-attach-execution-gap.json",
        "dataplane/netns-dae0-execution-gap.json",
        "dataplane/bpf-owner-handoff-execution-gap.json",
        "shared/gate-summary.json",
        "next/stage190-live-reload-runtime-parity-input.json",
    ]
}

fn path_string(path: &Path) -> String {
    path.display().to_string()
}
