use std::path::PathBuf;

use serde_json::{Value, json};

use crate::runner::RunnerOutput;

pub(crate) fn run_stage152_signal_control_plane_gate(args: &[String]) -> RunnerOutput {
    let opts = match Stage152Options::parse(args) {
        Ok(opts) => opts,
        Err(output) => return output,
    };
    if opts.execute_smoke {
        match dae_daemon::stage152_signal_control_plane_smoke_report(&opts.root) {
            Ok(smoke) => RunnerOutput::ok(format!("{}\n", stage152_report(Some(smoke)))),
            Err(err) => RunnerOutput::stdout_error(err),
        }
    } else {
        RunnerOutput::ok(format!("{}\n", stage152_report(None)))
    }
}

#[derive(Debug, Clone)]
struct Stage152Options {
    execute_smoke: bool,
    root: PathBuf,
}

impl Stage152Options {
    fn parse(args: &[String]) -> Result<Self, RunnerOutput> {
        let mut opts = Self {
            execute_smoke: false,
            root: dae_daemon::default_stage152_root(),
        };
        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--execute-smoke" => opts.execute_smoke = true,
                "--root" => {
                    let Some(value) = iter.next() else {
                        return Err(RunnerOutput::usage("missing stage152 --root value"));
                    };
                    opts.root = value.into();
                }
                _ if arg.starts_with("--root=") => {
                    opts.root = arg.split_once('=').unwrap().1.into();
                }
                _ => {
                    return Err(RunnerOutput::usage(format!(
                        "unsupported stage152 argument: {arg}"
                    )));
                }
            }
        }
        Ok(opts)
    }
}

fn stage152_report(smoke: Option<Value>) -> Value {
    let smoke_passed = smoke.is_some();
    let mut report = json!({
        "name": "stage152-rust-signal-control-plane-smoke-gate",
        "stage": "stage152",
        "evidence_class": "rust-daemon-opt-in-signal-control-plane-smoke-gate",
        "execute_smoke": smoke_passed,
        "read_only": !smoke_passed,
        "blocked": false,
        "blockers": []
    });
    for key in [
        "rust_daemon_identity_scaffolded",
        "rust_daemon_lifecycle_smoke_passed",
        "rust_control_plane_owner_preflight_recorded",
        "signal_control_plane_smoke_harness_available",
        "go_default_path_preserved",
        "go_fallback_required",
    ] {
        report[key] = json!(true);
    }
    for key in [
        "rust_signal_control_plane_smoke_passed",
        "reload_signal_progress_owner_sequence_validated",
        "suspend_signal_progress_sequence_validated",
        "abort_file_one_shot_consumed",
        "isolated_pid_removed_on_stop",
        "stage151_owner_preflight_reused",
        "isolated_signal_control_plane_paths_validated",
    ] {
        report[key] = json!(smoke_passed);
    }
    for key in [
        "production_signal_handler_installed",
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
    report["signal_scope"] = json!([
        "synthetic SIGUSR1 reload writes ReloadSend, daemon ReloadProcessing, owner preflight, ReloadDone",
        "synthetic SIGUSR2 suspend writes ReloadProcessing then ReloadDone",
        "abort marker is consumed once before reload owner sequence",
        "synthetic SIGTERM removes isolated pid file",
        "no production signal handler, listener, or eBPF attach"
    ]);
    report["remaining_blockers"] = json!([
        "Stage152 uses synthetic isolated signal flow, not production OS signal handlers",
        "Rust default run entrypoint remains absent",
        "production tproxy/eBPF/control-plane traffic is not started",
        "matched Go/Rust default daemon benchmark remains blocked",
        "default daemon and product-chain switches remain closed"
    ]);
    report["next_admission_queue"] = json!([
        {
            "stage": "stage153",
            "target": "Rust default run entrypoint admission preflight",
            "required_output": "prove non-default run entrypoint wrapper can compose lifecycle, signal, and owner smoke without mutating Go default path"
        },
        {
            "stage": "stage154",
            "target": "matched default daemon benchmark execution",
            "required_output": "run Go and Rust daemon identities on the same corpus only after run entrypoint and control-plane admission pass"
        }
    ]);
    report["validation_commands"] = json!([
        "cargo run --manifest-path rust/Cargo.toml -p dae-daemon --bin dae-daemon-optin -- stage152-signal-control-plane-smoke --root /tmp/dae-stage152-signal-control-plane-smoke",
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage152/rust_signal_control_plane_smoke_gate.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage152_rust_signal_control_plane_smoke_gate.json",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage152-rust-signal-control-plane-smoke-gate",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage152-rust-signal-control-plane-smoke-gate --execute-smoke --root /tmp/dae-stage152-cli-signal-control-plane",
        "cargo test --manifest-path rust/Cargo.toml -p dae-daemon stage152 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage152 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage152 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage151 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-daemon -p dae-cli -p dae-product -q",
        "cargo fmt --manifest-path rust/Cargo.toml --all -- --check",
        "git diff --check"
    ]);
    report["source"] = json!([
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage152",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.1",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.2",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.4",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.5",
        "rust/crates/dae-daemon/src/signal.rs",
        "rust/crates/dae-daemon/src/control_plane.rs"
    ]);
    if let Some(smoke) = smoke {
        report["smoke"] = smoke;
    }
    report
}
