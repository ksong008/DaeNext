use std::path::PathBuf;

use serde_json::{Value, json};

use crate::runner::RunnerOutput;

pub(crate) fn run_stage157_control_plane_entrypoint_gate(args: &[String]) -> RunnerOutput {
    let opts = match Stage157Options::parse(args) {
        Ok(opts) => opts,
        Err(output) => return output,
    };
    if opts.execute_smoke {
        match dae_daemon::stage157_control_plane_entrypoint_admission_report(&opts.root) {
            Ok(smoke) => RunnerOutput::ok(format!("{}\n", stage157_report(Some(smoke)))),
            Err(err) => RunnerOutput::stdout_error(err),
        }
    } else {
        RunnerOutput::ok(format!("{}\n", stage157_report(None)))
    }
}

#[derive(Debug, Clone)]
struct Stage157Options {
    execute_smoke: bool,
    root: PathBuf,
}

impl Stage157Options {
    fn parse(args: &[String]) -> Result<Self, RunnerOutput> {
        let mut opts = Self {
            execute_smoke: false,
            root: dae_daemon::default_stage157_root(),
        };
        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--execute-smoke" => opts.execute_smoke = true,
                "--root" => {
                    let Some(value) = iter.next() else {
                        return Err(RunnerOutput::usage("missing stage157 --root value"));
                    };
                    opts.root = value.into();
                }
                _ if arg.starts_with("--root=") => {
                    opts.root = arg.split_once('=').unwrap().1.into();
                }
                _ => {
                    return Err(RunnerOutput::usage(format!(
                        "unsupported stage157 argument: {arg}"
                    )));
                }
            }
        }
        Ok(opts)
    }
}

fn stage157_report(smoke: Option<Value>) -> Value {
    let smoke_passed = smoke.is_some();
    let mut report = json!({
        "name": "stage157-control-plane-entrypoint-admission-gate",
        "stage": "stage157",
        "prior_gate": "stage156-rust-default-run-identity-admission-gate",
        "evidence_class": "rust-daemon-opt-in-control-plane-entrypoint-admission-gate",
        "execute_smoke": smoke_passed,
        "read_only": !smoke_passed,
        "blocked": false,
        "blockers": []
    });
    for key in [
        "control_plane_entrypoint_harness_available",
        "rust_default_run_entrypoint_exists",
        "go_default_path_preserved",
        "go_fallback_required",
    ] {
        report[key] = json!(true);
    }
    for key in [
        "control_plane_entrypoint_optin_admitted",
        "rust_default_control_plane_entrypoint_admitted",
        "stage156_run_identity_reused",
        "stage151_owner_preflight_reused",
        "control_plane_startup_sequence_recorded",
        "control_plane_reload_owner_sequence_recorded",
        "control_plane_rollback_sequence_recorded",
        "listener_reuse_contract_recorded",
        "bpf_owner_transfer_contract_recorded",
        "dns_cache_migration_guard_recorded",
        "reload_scoped_flush_after_current_swap_recorded",
        "isolated_control_plane_entrypoint_paths_validated",
    ] {
        report[key] = json!(smoke_passed);
    }
    for key in [
        "production_listener_bound",
        "ebpf_attached",
        "benchmark_executable_now",
        "matched_go_rust_default_daemon_benchmark_recorded",
        "true_rust_default_daemon_admitted",
        "default_switch_allowed",
        "default_path_mutation_allowed",
        "product_chain_switch_allowed",
    ] {
        report[key] = json!(false);
    }
    report["entrypoint_scope"] = json!([
        "Stage157 composes Stage156 run identity and Stage151 control-plane owner preflight",
        "listener reuse, BPF ownership transfer, DNS cache guard, rollback, and reload scoped flush are recorded",
        "production listener binding and eBPF attach remain closed",
        "matched benchmark and default/product switches remain closed"
    ]);
    report["remaining_blockers"] = json!([
        "production listener binding and eBPF attach remain closed",
        "matched Go/Rust default daemon benchmark has not executed",
        "true Rust default daemon admission remains false until production binding and matched benchmark pass",
        "default daemon and product-chain switches remain closed"
    ]);
    report["next_admission_queue"] = json!([
        {
            "stage": "stage158",
            "target": "matched Go/Rust default daemon benchmark execution",
            "required_output": "run the same config corpus on Go default daemon and true Rust default daemon before any default/product switch"
        }
    ]);
    report["validation_commands"] = json!([
        "cargo run --manifest-path rust/Cargo.toml -p dae-daemon --bin dae-daemon-optin -- stage157-control-plane-entrypoint-admission --root /tmp/dae-stage157-control-plane-entrypoint",
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage157/control_plane_entrypoint_admission_gate.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage157_control_plane_entrypoint_admission_gate.json",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage157-control-plane-entrypoint-admission-gate",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage157-control-plane-entrypoint-admission-gate --execute-smoke --root /tmp/dae-stage157-cli-control-plane-entrypoint",
        "cargo test --manifest-path rust/Cargo.toml -p dae-daemon stage157 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage157 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage157 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage156 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-daemon -p dae-cli -p dae-product -q",
        "cargo fmt --manifest-path rust/Cargo.toml --all -- --check",
        "git diff --check"
    ]);
    report["source"] = json!([
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage157",
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage151",
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage156",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.3",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.4",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.8",
        "rust/crates/dae-daemon/src/control_plane_entrypoint.rs"
    ]);
    if let Some(smoke) = smoke {
        report["smoke"] = smoke;
    }
    report
}
