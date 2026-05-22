use std::path::PathBuf;

use serde_json::{Value, json};

use crate::runner::RunnerOutput;

pub(crate) fn run_stage153_run_entrypoint_gate(args: &[String]) -> RunnerOutput {
    let opts = match Stage153Options::parse(args) {
        Ok(opts) => opts,
        Err(output) => return output,
    };
    if opts.execute_smoke {
        match dae_daemon::stage153_run_entrypoint_preflight_report(&opts.root) {
            Ok(smoke) => RunnerOutput::ok(format!("{}\n", stage153_report(Some(smoke)))),
            Err(err) => RunnerOutput::stdout_error(err),
        }
    } else {
        RunnerOutput::ok(format!("{}\n", stage153_report(None)))
    }
}

#[derive(Debug, Clone)]
struct Stage153Options {
    execute_smoke: bool,
    root: PathBuf,
}

impl Stage153Options {
    fn parse(args: &[String]) -> Result<Self, RunnerOutput> {
        let mut opts = Self {
            execute_smoke: false,
            root: dae_daemon::default_stage153_root(),
        };
        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--execute-smoke" => opts.execute_smoke = true,
                "--root" => {
                    let Some(value) = iter.next() else {
                        return Err(RunnerOutput::usage("missing stage153 --root value"));
                    };
                    opts.root = value.into();
                }
                _ if arg.starts_with("--root=") => {
                    opts.root = arg.split_once('=').unwrap().1.into();
                }
                _ => {
                    return Err(RunnerOutput::usage(format!(
                        "unsupported stage153 argument: {arg}"
                    )));
                }
            }
        }
        Ok(opts)
    }
}

fn stage153_report(smoke: Option<Value>) -> Value {
    let smoke_passed = smoke.is_some();
    let mut report = json!({
        "name": "stage153-rust-run-entrypoint-preflight-gate",
        "stage": "stage153",
        "evidence_class": "rust-daemon-opt-in-run-entrypoint-preflight-gate",
        "execute_smoke": smoke_passed,
        "read_only": !smoke_passed,
        "blocked": false,
        "blockers": []
    });
    for key in [
        "rust_daemon_identity_scaffolded",
        "rust_daemon_lifecycle_smoke_passed",
        "rust_control_plane_owner_preflight_recorded",
        "rust_signal_control_plane_smoke_passed",
        "run_entrypoint_preflight_harness_available",
        "go_default_path_preserved",
        "go_fallback_required",
    ] {
        report[key] = json!(true);
    }
    for key in [
        "non_default_run_entrypoint_wrapper_available",
        "run_entrypoint_wrapper_composed",
        "run_entrypoint_lifecycle_smoke_reused",
        "run_entrypoint_signal_control_plane_smoke_reused",
        "run_entrypoint_on_ready_contract_recorded",
        "run_entrypoint_flag_contract_recorded",
        "isolated_run_entrypoint_paths_validated",
        "go_default_run_command_preserved",
    ] {
        report[key] = json!(smoke_passed);
    }
    for key in [
        "production_run_command_replaced",
        "production_pid_progress_paths_mutated",
        "production_signal_handler_installed",
        "production_listener_bound",
        "ebpf_attached",
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
    report["wrapper_scope"] = json!([
        "non-default stage153 command composes lifecycle smoke",
        "non-default stage153 command composes signal/control-plane smoke",
        "run flags and OnReady contract are recorded",
        "Go default dae run command is preserved",
        "no production pid/progress paths, signal handlers, listener binding, or eBPF attach"
    ]);
    report["remaining_blockers"] = json!([
        "Stage153 is only a non-default wrapper preflight",
        "Rust default run entrypoint remains absent",
        "production tproxy/eBPF/control-plane traffic is not started",
        "matched Go/Rust default daemon benchmark remains blocked",
        "default daemon and product-chain switches remain closed"
    ]);
    report["next_admission_queue"] = json!([
        {
            "stage": "stage154",
            "target": "matched default daemon benchmark readiness refresh",
            "required_output": "decide whether non-default wrapper evidence is enough to construct matched benchmark corpus without default switch"
        },
        {
            "stage": "stage155",
            "target": "product-chain default switch final blocker review",
            "required_output": "enumerate remaining blockers before any default/product switch"
        }
    ]);
    report["validation_commands"] = json!([
        "cargo run --manifest-path rust/Cargo.toml -p dae-daemon --bin dae-daemon-optin -- stage153-run-entrypoint-preflight --root /tmp/dae-stage153-run-entrypoint-preflight",
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage153/rust_run_entrypoint_preflight_gate.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage153_rust_run_entrypoint_preflight_gate.json",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage153-rust-run-entrypoint-preflight-gate",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage153-rust-run-entrypoint-preflight-gate --execute-smoke --root /tmp/dae-stage153-cli-run-entrypoint",
        "cargo test --manifest-path rust/Cargo.toml -p dae-daemon stage153 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage153 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage153 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage152 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-daemon -p dae-cli -p dae-product -q",
        "cargo fmt --manifest-path rust/Cargo.toml --all -- --check",
        "git diff --check"
    ]);
    report["source"] = json!([
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage153",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.1",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.2",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.3",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.4",
        "rust/crates/dae-daemon/src/run_entrypoint.rs",
        "rust/crates/dae-daemon/src/signal.rs",
        "rust/crates/dae-daemon/src/lifecycle.rs"
    ]);
    if let Some(smoke) = smoke {
        report["smoke"] = smoke;
    }
    report
}
