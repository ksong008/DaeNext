use std::path::PathBuf;

use serde_json::{Value, json};

use crate::runner::RunnerOutput;

pub(crate) fn run_stage151_control_plane_owner_gate(args: &[String]) -> RunnerOutput {
    let opts = match Stage151Options::parse(args) {
        Ok(opts) => opts,
        Err(output) => return output,
    };
    if opts.execute_smoke {
        match dae_daemon::stage151_control_plane_owner_preflight_report(&opts.root) {
            Ok(smoke) => RunnerOutput::ok(format!("{}\n", stage151_report(Some(smoke)))),
            Err(err) => RunnerOutput::stdout_error(err),
        }
    } else {
        RunnerOutput::ok(format!("{}\n", stage151_report(None)))
    }
}

#[derive(Debug, Clone)]
struct Stage151Options {
    execute_smoke: bool,
    root: PathBuf,
}

impl Stage151Options {
    fn parse(args: &[String]) -> Result<Self, RunnerOutput> {
        let mut opts = Self {
            execute_smoke: false,
            root: dae_daemon::default_stage151_root(),
        };
        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--execute-smoke" => opts.execute_smoke = true,
                "--root" => {
                    let Some(value) = iter.next() else {
                        return Err(RunnerOutput::usage("missing stage151 --root value"));
                    };
                    opts.root = value.into();
                }
                _ if arg.starts_with("--root=") => {
                    opts.root = arg.split_once('=').unwrap().1.into();
                }
                _ => {
                    return Err(RunnerOutput::usage(format!(
                        "unsupported stage151 argument: {arg}"
                    )));
                }
            }
        }
        Ok(opts)
    }
}

fn stage151_report(smoke: Option<Value>) -> Value {
    let smoke_passed = smoke.is_some();
    let mut report = json!({
        "name": "stage151-rust-control-plane-owner-preflight-gate",
        "stage": "stage151",
        "evidence_class": "rust-daemon-opt-in-control-plane-owner-preflight-gate",
        "execute_smoke": smoke_passed,
        "read_only": !smoke_passed,
        "blocked": false,
        "blockers": []
    });
    for key in [
        "rust_daemon_identity_scaffolded",
        "rust_daemon_lifecycle_smoke_passed",
        "rust_control_plane_owner_preflight_recorded",
        "control_plane_startup_sequence_recorded",
        "control_plane_reload_owner_sequence_recorded",
        "control_plane_rollback_sequence_recorded",
        "listener_reuse_contract_recorded",
        "bpf_owner_transfer_contract_recorded",
        "dns_cache_migration_guard_recorded",
        "reload_scoped_flush_after_current_swap_recorded",
        "go_default_path_preserved",
        "go_fallback_required",
    ] {
        report[key] = json!(true);
    }
    report["rust_control_plane_owner_smoke_passed"] = json!(smoke_passed);
    report["isolated_control_plane_owner_paths_validated"] = json!(smoke_passed);
    for key in [
        "production_listener_bound",
        "ebpf_attached",
        "production_paths_mutated",
        "rust_default_run_entrypoint_exists",
        "rust_default_control_plane_entrypoint_admitted",
        "benchmark_executable_now",
        "matched_go_rust_default_daemon_benchmark_recorded",
        "true_rust_default_daemon_admitted",
        "default_switch_allowed",
        "default_path_mutation_allowed",
        "product_chain_switch_allowed",
    ] {
        report[key] = json!(false);
    }
    report["owner_scope"] = json!([
        "startup sequence: config, bootstrap, wait-network, subscription, control-plane build, listen ready, on-ready",
        "reload success sequence: old BPF eject, guarded DNS cache migration, next build/inject, current swap, old close, scoped flush, listener reuse",
        "reload rollback sequence: failed next build returns owner to old control plane and keeps current old",
        "no production listener binding",
        "no eBPF attach"
    ]);
    report["remaining_blockers"] = json!([
        "Stage151 records control-plane ownership only as an opt-in isolated preflight",
        "Rust default run entrypoint remains absent",
        "production tproxy/eBPF/control-plane traffic is not started",
        "matched Go/Rust default daemon benchmark remains blocked",
        "default daemon and product-chain switches remain closed"
    ]);
    report["next_admission_queue"] = json!([
        {
            "stage": "stage152",
            "target": "Rust daemon signal/control-plane integration smoke",
            "required_output": "prove isolated signal -> progress -> owner sequence before benchmark"
        },
        {
            "stage": "stage153",
            "target": "matched default daemon benchmark execution",
            "required_output": "run Go and Rust daemon identities on the same corpus after default run entrypoint and control-plane admission pass"
        }
    ]);
    report["validation_commands"] = json!([
        "cargo run --manifest-path rust/Cargo.toml -p dae-daemon --bin dae-daemon-optin -- stage151-control-plane-owner-preflight --root /tmp/dae-stage151-control-plane-owner-preflight",
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage151/rust_control_plane_owner_preflight_gate.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage151_rust_control_plane_owner_preflight_gate.json",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage151-rust-control-plane-owner-preflight-gate",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage151-rust-control-plane-owner-preflight-gate --execute-smoke --root /tmp/dae-stage151-cli-control-plane-owner",
        "cargo test --manifest-path rust/Cargo.toml -p dae-daemon stage151 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage151 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage151 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage150 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-daemon -p dae-cli -p dae-product -q",
        "cargo fmt --manifest-path rust/Cargo.toml --all -- --check",
        "git diff --check"
    ]);
    report["source"] = json!([
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage151",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.3",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.4",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.5",
        "rust/crates/dae-daemon/src/control_plane.rs",
        "rust/crates/dae-control/src/reload.rs"
    ]);
    if let Some(smoke) = smoke {
        report["smoke"] = smoke;
    }
    report
}
