use std::fs;
use std::path::Path;

use serde_json::{Value, json};

use crate::runner::RunnerOutput;

enum Stage190Mode<'a> {
    ReadOnly,
    WriteEvidence {
        root: &'a str,
        stage189_root: &'a str,
    },
}

pub(crate) fn run_stage190_live_reload_runtime_parity_execution_evidence_gate(
    args: &[String],
) -> RunnerOutput {
    match parse_stage190_args(args) {
        Ok(Stage190Mode::ReadOnly) => RunnerOutput::ok(format!("{}\n", stage190_report(None))),
        Ok(Stage190Mode::WriteEvidence {
            root,
            stage189_root,
        }) => match write_stage190_evidence(root, stage189_root) {
            Ok(result) => RunnerOutput::ok(format!("{}\n", stage190_report(Some(result)))),
            Err(err) => RunnerOutput::stdout_error(err),
        },
        Err(err) => RunnerOutput::usage(err),
    }
}

fn parse_stage190_args(args: &[String]) -> Result<Stage190Mode<'_>, String> {
    let mut write = false;
    let mut root = None;
    let mut stage189_root = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--write-evidence" => write = true,
            "--root" => {
                let Some(value) = iter.next() else {
                    return Err("stage190 --root requires a value".to_string());
                };
                root = Some(value.as_str());
            }
            _ if arg.starts_with("--root=") => root = arg.split_once('=').map(|(_, value)| value),
            "--stage189-root" => {
                let Some(value) = iter.next() else {
                    return Err("stage190 --stage189-root requires a value".to_string());
                };
                stage189_root = Some(value.as_str());
            }
            _ if arg.starts_with("--stage189-root=") => {
                stage189_root = arg.split_once('=').map(|(_, value)| value);
            }
            _ => return Err(format!("unsupported stage190 argument: {arg}")),
        }
    }
    match (write, root, stage189_root) {
        (false, None, None) => Ok(Stage190Mode::ReadOnly),
        (false, Some(_), _) | (false, _, Some(_)) => {
            Err("stage190 --root/--stage189-root require --write-evidence".to_string())
        }
        (true, Some(root), Some(stage189_root)) => Ok(Stage190Mode::WriteEvidence {
            root,
            stage189_root,
        }),
        (true, None, _) => Err("stage190 --write-evidence requires --root".to_string()),
        (true, _, None) => Err("stage190 --write-evidence requires --stage189-root".to_string()),
    }
}

fn stage190_report(write_result: Option<Value>) -> Value {
    let written = write_result.is_some();
    let mut report = json!({
        "name": "stage190-live-reload-runtime-parity-execution-evidence-gate",
        "stage": "stage190",
        "prior_gate": "stage189-production-dataplane-execution-evidence-gate",
        "evidence_class": "explicit-temp-root-live-reload-runtime-parity-execution-evidence-gap",
        "read_only": !written,
        "write_evidence": written,
        "artifact_root_policy": "explicit /tmp/dae-stage190* root only",
        "stage189_root_policy": "explicit /tmp/dae-stage189* root containing Stage189 production dataplane execution gap bundle",
        "benchmark_executable_now": false,
        "matched_go_rust_default_daemon_benchmark_recorded": false,
        "true_rust_default_daemon_admitted": false,
        "default_switch_allowed": false,
        "product_chain_switch_allowed": false
    });
    for key in [
        "live_reload_runtime_parity_execution_evidence_gate_available",
        "stage189_dataplane_bundle_required",
        "stage189_bundle_verifier_available",
        "listener_reuse_gap_available",
        "bpf_owner_transfer_gap_available",
        "dns_cache_migration_guard_gap_available",
        "bounded_close_runtime_overview_gap_available",
        "go_default_path_preserved",
        "go_fallback_required",
        "benchmark_exclusion_checked",
    ] {
        report[key] = json!(true);
    }
    for key in [
        "stage189_dataplane_bundle_verified",
        "listener_reuse_gap_written",
        "bpf_owner_transfer_gap_written",
        "dns_cache_migration_guard_gap_written",
        "bounded_close_runtime_overview_gap_written",
        "stage191_bounded_benchmark_input_written",
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
        "dns_cache_migration_guard_verified",
        "bounded_close_verified",
        "runtime_overview_parity_verified",
        "reload_scoped_resources_flushed",
        "reload_runtime_parity_admitted",
        "benchmark_readiness_admitted",
        "bounded_benchmark_executed",
        "default_path_mutation_allowed",
    ] {
        report[key] = json!(false);
    }
    report["stage189_required_files"] = json!(stage189_files());
    report["stage190_expected_files"] = json!(stage190_files());
    report["reload_runtime_gap_rows"] = reload_runtime_gap_rows(written);
    report["gate_summary"] = gate_summary();
    report["gate_decision"] = json!(
        "Stage190 verifies the explicit Stage189 production dataplane execution gap bundle and records live reload/runtime parity execution gaps. It does not execute live reload, reuse production listeners, transfer production BPF ownership, migrate live DNS cache, verify bounded Close or RuntimeOverview parity, run benchmark, or switch default/product paths"
    );
    report["remaining_blockers"] = remaining_blockers();
    report["next_admission_queue"] = json!([
        {
            "stage": "stage191",
            "target": "bounded same-corpus default daemon benchmark admission input",
            "required_output": "benchmark remains blocked until production dataplane execution and live reload/runtime parity both have real execution evidence"
        },
        {
            "stage": "stage192",
            "target": "default/product switch recertification input",
            "required_output": "default/product switch remains blocked until matched Go/Rust default daemon benchmark is recorded and reviewed"
        }
    ]);
    report["validation_commands"] = json!([
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage190/live_reload_runtime_parity_execution_evidence_gate.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage190_live_reload_runtime_parity_execution_evidence_gate.json",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage190-live-reload-runtime-parity-execution-evidence-gate",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage183-corpus-command-admission-binding-dry-run --write-admission-dry-run --root /tmp/dae-stage183-stage190-input",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage184-same-corpus-daemon-execution-smoke --execute-smoke --root /tmp/dae-stage184-stage190-input --stage183-root /tmp/dae-stage183-stage190-input",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage185-production-dataplane-listener-tc-ebpf-evidence-gate --write-evidence-gate --root /tmp/dae-stage185-stage190-input --stage184-root /tmp/dae-stage184-stage190-input",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage186-reload-runtime-parity-evidence-gate --write-parity-gate --root /tmp/dae-stage186-stage190-input --stage185-root /tmp/dae-stage185-stage190-input",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage187-matched-benchmark-readiness-gate --write-readiness-gate --root /tmp/dae-stage187-stage190-input --stage186-root /tmp/dae-stage186-stage190-input",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage188-bounded-benchmark-hard-gate-resolution --write-resolution --root /tmp/dae-stage188-stage190-input --stage187-root /tmp/dae-stage187-stage190-input",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage189-production-dataplane-execution-evidence-gate --write-evidence --root /tmp/dae-stage189-stage190-input --stage188-root /tmp/dae-stage188-stage190-input",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage190-live-reload-runtime-parity-execution-evidence-gate --write-evidence --root /tmp/dae-stage190-live-reload-runtime-evidence --stage189-root /tmp/dae-stage189-stage190-input",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage190 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage190 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage189 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli -p dae-product -q",
        "cargo fmt --manifest-path rust/Cargo.toml --all -- --check",
        "git diff --check"
    ]);
    report["source"] = json!([
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage190",
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage189",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.4",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.5",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.7",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.8"
    ]);
    if let Some(result) = write_result {
        report["write_result"] = result;
    }
    report
}

fn write_stage190_evidence(root: &str, stage189_root: &str) -> Result<Value, String> {
    let root_path = Path::new(root);
    let stage189_path = Path::new(stage189_root);
    validate_stage190_root(root_path)?;
    validate_stage189_root(stage189_path)?;
    if root_path.exists() {
        return Err(format!(
            "stage190 root already exists, remove it first: {}",
            root_path.display()
        ));
    }
    if !stage189_path.is_dir() {
        return Err(format!(
            "stage189 root does not exist or is not a directory: {}",
            stage189_path.display()
        ));
    }

    let stage189_verification = verify_stage189_bundle(stage189_path)?;
    fs::create_dir_all(root_path).map_err(|err| format!("create stage190 root failed: {err}"))?;

    write_json(
        root_path,
        "prior/stage189-dataplane-verification.json",
        &stage189_verification,
    )?;
    write_json(
        root_path,
        "reload/listener-reuse-execution-gap.json",
        &listener_reuse_execution_gap(),
    )?;
    write_json(
        root_path,
        "reload/bpf-owner-transfer-execution-gap.json",
        &bpf_owner_transfer_execution_gap(),
    )?;
    write_json(
        root_path,
        "reload/dns-cache-migration-guard-gap.json",
        &dns_cache_migration_guard_gap(),
    )?;
    write_json(
        root_path,
        "runtime/bounded-close-runtime-overview-gap.json",
        &bounded_close_runtime_overview_gap(),
    )?;
    write_json(
        root_path,
        "shared/gate-summary.json",
        &json!({ "gates": gate_summary() }),
    )?;
    write_json(
        root_path,
        "next/stage191-bounded-benchmark-execution-input.json",
        &json!({
            "stage": "stage190",
            "next_stage": "stage191",
            "stage189_dataplane_bundle_verified": true,
            "live_reload_runtime_execution_gap_recorded": true,
            "requires_real_production_dataplane_execution": true,
            "requires_real_listener_reuse_execution": true,
            "requires_real_bpf_owner_transfer_execution": true,
            "requires_real_dns_cache_migration_guard_execution": true,
            "requires_real_bounded_close_runtime_overview_execution": true,
            "production_dataplane_admitted": false,
            "reload_runtime_parity_admitted": false,
            "benchmark_executable_now": false,
            "bounded_benchmark_execution_allowed": false,
            "default_switch_allowed": false,
            "product_chain_switch_allowed": false
        }),
    )?;

    let manifest = json!({
        "stage": "stage190",
        "bundle": "live-reload-runtime-parity-execution-evidence-gap",
        "root": path_string(root_path),
        "stage189_root": path_string(stage189_path),
        "expected_file_count": stage190_files().len(),
        "files_written_count": stage190_files().len(),
        "missing_files": [],
        "stage189_verification": stage189_verification,
        "listener_reuse_gap_written": true,
        "bpf_owner_transfer_gap_written": true,
        "dns_cache_migration_guard_gap_written": true,
        "bounded_close_runtime_overview_gap_written": true,
        "stage191_bounded_benchmark_input_written": true,
        "hard_gates_resolved": false,
        "production_dataplane_admitted": false,
        "live_reload_executed": false,
        "production_listener_reused": false,
        "production_bpf_owner_transferred": false,
        "production_dns_cache_migrated": false,
        "dns_cache_migration_guard_verified": false,
        "bounded_close_verified": false,
        "runtime_overview_parity_verified": false,
        "reload_scoped_resources_flushed": false,
        "reload_runtime_parity_admitted": false,
        "benchmark_executable_now": false,
        "matched_go_rust_default_daemon_benchmark_recorded": false,
        "default_switch_allowed": false
    });
    write_json(root_path, "manifest.json", &manifest)?;

    let missing = stage190_files()
        .iter()
        .filter(|relative| !root_path.join(relative).is_file())
        .copied()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(format!(
            "stage190 evidence bundle missing files after write: {missing:?}"
        ));
    }

    Ok(json!({
        "root": path_string(root_path),
        "stage189_root": path_string(stage189_path),
        "expected_file_count": stage190_files().len(),
        "files_written_count": stage190_files().len(),
        "missing_files": [],
        "stage189_dataplane_bundle_verified": true,
        "listener_reuse_gap_written": true,
        "bpf_owner_transfer_gap_written": true,
        "dns_cache_migration_guard_gap_written": true,
        "bounded_close_runtime_overview_gap_written": true,
        "stage191_bounded_benchmark_input_written": true,
        "reload_runtime_parity_gate": "execution_gap_recorded",
        "hard_gates_resolved": false,
        "production_dataplane_admitted": false,
        "reload_runtime_parity_admitted": false,
        "benchmark_executable_now": false,
        "matched_go_rust_default_daemon_benchmark_recorded": false,
        "default_switch_allowed": false
    }))
}

fn verify_stage189_bundle(stage189_root: &Path) -> Result<Value, String> {
    let missing = stage189_files()
        .iter()
        .filter(|relative| !stage189_root.join(relative).is_file())
        .copied()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(format!(
            "stage189 dataplane evidence bundle missing required files: {missing:?}"
        ));
    }

    let manifest = read_json(stage189_root, "manifest.json")?;
    expect_str(
        &manifest,
        "stage",
        "stage189",
        "stage189 manifest stage mismatch",
    )?;
    for key in [
        "listener_sockmap_gap_written",
        "tc_ebpf_attach_gap_written",
        "netns_dae0_gap_written",
        "bpf_owner_handoff_gap_written",
        "stage190_reload_runtime_input_written",
    ] {
        expect_bool(
            &manifest,
            key,
            true,
            "stage189 manifest missing required written flag",
        )?;
    }
    for key in [
        "hard_gates_resolved",
        "production_listener_bound",
        "listen_socket_map_written",
        "production_tc_attach_smoke_passed",
        "ebpf_attached",
        "netns_setup_executed",
        "dae0_attach_executed",
        "bpf_owner_handoff_executed",
        "production_dataplane_admitted",
        "reload_runtime_parity_admitted",
        "benchmark_executable_now",
        "matched_go_rust_default_daemon_benchmark_recorded",
        "default_switch_allowed",
    ] {
        expect_bool(
            &manifest,
            key,
            false,
            "stage189 manifest unexpectedly opened a hard gate",
        )?;
    }

    let gate_summary = read_json(stage189_root, "shared/gate-summary.json")?;
    for (gate, status) in [
        ("corpus_gate", "prepared_for_daemon_smoke"),
        ("rust_production_command_gate", "closed"),
        ("daemon_execution_gate", "identity_smoke_passed"),
        ("production_dataplane_gate", "execution_gap_recorded"),
        ("matched_benchmark_gate", "closed"),
        ("default_product_switch_gate", "closed"),
    ] {
        expect_gate_status(&gate_summary, gate, status)?;
    }

    for file in [
        "dataplane/listener-sockmap-execution-gap.json",
        "dataplane/tc-ebpf-attach-execution-gap.json",
        "dataplane/netns-dae0-execution-gap.json",
        "dataplane/bpf-owner-handoff-execution-gap.json",
    ] {
        let gap = read_json(stage189_root, file)?;
        expect_bool(
            &gap,
            "production_dataplane_admitted",
            false,
            "stage189 dataplane gap unexpectedly admitted production dataplane",
        )?;
    }

    let next = read_json(
        stage189_root,
        "next/stage190-live-reload-runtime-parity-input.json",
    )?;
    for key in [
        "stage188_resolution_bundle_verified",
        "production_dataplane_execution_gap_recorded",
        "requires_real_production_listener_sockmap_execution",
        "requires_real_tc_ebpf_attach_execution",
        "requires_real_netns_dae0_execution",
        "requires_real_bpf_owner_handoff_execution",
    ] {
        expect_bool(
            &next,
            key,
            true,
            "stage189 next-stage input missing required flag",
        )?;
    }
    for key in [
        "production_dataplane_admitted",
        "reload_runtime_parity_execution_allowed",
        "benchmark_executable_now",
        "bounded_benchmark_execution_allowed",
        "default_switch_allowed",
    ] {
        expect_bool(
            &next,
            key,
            false,
            "stage189 next-stage input unexpectedly opened a hard gate",
        )?;
    }

    Ok(json!({
        "stage189_root": path_string(stage189_root),
        "required_files_verified": true,
        "required_file_count": stage189_files().len(),
        "stage189_dataplane_bundle_verified": true,
        "stage190_reload_runtime_input_verified": true,
        "production_dataplane_gate": "execution_gap_recorded",
        "production_dataplane_admitted": false,
        "reload_runtime_parity_admitted": false,
        "benchmark_executable_now": false,
        "default_switch_allowed": false
    }))
}

fn listener_reuse_execution_gap() -> Value {
    json!({
        "stage": "stage190",
        "gap": "live reload listener reuse execution",
        "required_evidence": [
            "old control plane ServeResult returns reusable listener after Close",
            "new control plane starts Serve with the old listener instead of re-listening",
            "ready callback fires only after the reused listener reaches ready",
            "reload failure path preserves or cleans up listener ownership"
        ],
        "current_rust_evidence": [
            "Stage186 records listener reuse contract only",
            "Stage189 records production dataplane execution gaps and does not admit production listener/sockmap",
            "no Stage190 input proves live reload listener reuse has run"
        ],
        "live_reload_executed": false,
        "production_listener_reused": false,
        "reload_runtime_parity_admitted": false,
        "source": "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.4,15.5"
    })
}

fn bpf_owner_transfer_execution_gap() -> Value {
    json!({
        "stage": "stage190",
        "gap": "live reload BPF owner transfer execution",
        "required_evidence": [
            "old control plane EjectBpf runs before replacement build",
            "new control plane InjectBpf receives the ejected object before old close completes",
            "failure rollback either returns ownership to the old path or closes the object",
            "RuntimeOverview reports the expected owner after reload"
        ],
        "current_rust_evidence": [
            "Stage164/165 use temporary or non-production owner handoff smoke",
            "Stage186 records BPF owner transfer contract only",
            "Stage189 records production BPF owner handoff gap only"
        ],
        "production_bpf_owner_transferred": false,
        "bpf_owner_handoff_executed": false,
        "reload_runtime_parity_admitted": false,
        "source": "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.4,15.8"
    })
}

fn dns_cache_migration_guard_gap() -> Value {
    json!({
        "stage": "stage190",
        "gap": "DNS cache migration guard execution",
        "required_evidence": [
            "snapshot DNS cache only when old and new DNS config are exactly equal",
            "do not migrate DNS cache when DNS bind or upstream config differs",
            "record old DNS listener stop/restart ordering when binds collide",
            "prove reload failure path does not leak a migrated cache into changed DNS config"
        ],
        "current_rust_evidence": [
            "Stage186 records DNS migration guard contract only",
            "Stage190 input does not prove live DNS cache migration guard execution"
        ],
        "production_dns_cache_migrated": false,
        "dns_cache_migration_guard_verified": false,
        "reload_runtime_parity_admitted": false,
        "source": "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.4"
    })
}

fn bounded_close_runtime_overview_gap() -> Value {
    json!({
        "stage": "stage190",
        "gap": "bounded Close, reload scoped cleanup, and RuntimeOverview parity execution",
        "required_evidence": [
            "Close cancels Serve and observes the bounded 2s shutdown grace",
            "reload scoped resources flush only after replacement control plane is current",
            "RuntimeOverview reports listener, BPF owner, DNS cache, pool/cache, and reload state after the transition",
            "recent runtime samples remain compatible with WebUI observation semantics"
        ],
        "current_rust_evidence": [
            "Stage186 records bounded close and RuntimeOverview contract only",
            "Stage190 input does not prove live bounded Close or RuntimeOverview parity execution"
        ],
        "bounded_close_verified": false,
        "runtime_overview_parity_verified": false,
        "reload_scoped_resources_flushed": false,
        "reload_runtime_parity_admitted": false,
        "source": "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.5,15.7,15.8"
    })
}

fn reload_runtime_gap_rows(written: bool) -> Value {
    let status = if written {
        "execution-gap-written"
    } else {
        "requires-explicit-stage190-writer"
    };
    json!([
        {
            "area": "Stage189 dataplane gap verification",
            "status": status,
            "evidence": "Stage190 verifies the explicit Stage189 production dataplane execution gap bundle, manifest, gap files, gate summary, and Stage190 input",
            "boundary": "dataplane gap verification is not live reload/runtime parity execution",
            "closed_flag": "reload_runtime_parity_admitted=false"
        },
        {
            "area": "live reload listener reuse",
            "status": status,
            "evidence": "Stage190 records the missing old ServeResult listener reuse and ready ordering evidence",
            "boundary": "does not execute live reload or reuse production listener",
            "closed_flag": "production_listener_reused=false"
        },
        {
            "area": "BPF owner transfer",
            "status": status,
            "evidence": "Stage190 records the missing EjectBpf/InjectBpf owner transfer and rollback evidence",
            "boundary": "does not transfer production BPF ownership",
            "closed_flag": "production_bpf_owner_transferred=false"
        },
        {
            "area": "DNS cache migration guard",
            "status": status,
            "evidence": "Stage190 records the missing exact-DNS-config migration guard and DNS bind collision ordering evidence",
            "boundary": "does not migrate live DNS cache",
            "closed_flag": "dns_cache_migration_guard_verified=false"
        },
        {
            "area": "bounded Close and RuntimeOverview",
            "status": status,
            "evidence": "Stage190 records the missing bounded Close, reload scoped cleanup, and RuntimeOverview parity evidence",
            "boundary": "does not execute bounded Close or RuntimeOverview parity smoke",
            "closed_flag": "runtime_overview_parity_verified=false"
        },
        {
            "area": "benchmark/default safety",
            "status": "closed-preserved",
            "evidence": "Stage190 keeps benchmark and default/product switches closed because production dataplane and reload/runtime parity are still not admitted",
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
            "opens_after": "Stage183 reviewed corpus binding remains carried through Stage184-190"
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
        "production dataplane execution remains a gap from Stage189",
        "live reload listener reuse has not executed against production resources",
        "production BPF owner transfer has not executed across live reload",
        "DNS cache migration guard has not executed against equal and changed DNS configs",
        "bounded Close, reload scoped cleanup, and RuntimeOverview parity have not executed",
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
            .map_err(|err| format!("create stage190 parent {} failed: {err}", parent.display()))?;
    }
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|err| format!("encode stage190 file {} failed: {err}", path.display()))?;
    fs::write(&path, bytes)
        .map_err(|err| format!("write stage190 file {} failed: {err}", path.display()))
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
        "stage189 gate {gate} mismatch: expected {expected}, got {status:?}"
    ))
}

fn validate_stage190_root(path: &Path) -> Result<(), String> {
    if !path.is_absolute() {
        return Err("stage190 root must be absolute".to_string());
    }
    if !path.to_string_lossy().starts_with("/tmp/dae-stage190") {
        return Err("stage190 root must be under /tmp/dae-stage190*".to_string());
    }
    Ok(())
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

fn stage190_files() -> Vec<&'static str> {
    vec![
        "manifest.json",
        "prior/stage189-dataplane-verification.json",
        "reload/listener-reuse-execution-gap.json",
        "reload/bpf-owner-transfer-execution-gap.json",
        "reload/dns-cache-migration-guard-gap.json",
        "runtime/bounded-close-runtime-overview-gap.json",
        "shared/gate-summary.json",
        "next/stage191-bounded-benchmark-execution-input.json",
    ]
}

fn path_string(path: &Path) -> String {
    path.display().to_string()
}
