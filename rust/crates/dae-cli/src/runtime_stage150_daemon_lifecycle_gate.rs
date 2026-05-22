use std::path::PathBuf;

use serde_json::{Value, json};

use crate::runner::RunnerOutput;

pub(crate) fn run_stage150_daemon_lifecycle_gate(args: &[String]) -> RunnerOutput {
    let opts = match Stage150Options::parse(args) {
        Ok(opts) => opts,
        Err(output) => return output,
    };
    if opts.execute_smoke {
        match dae_daemon::stage150_lifecycle_smoke_report(&opts.root) {
            Ok(smoke) => RunnerOutput::ok(format!("{}\n", stage150_report(Some(smoke)))),
            Err(err) => RunnerOutput::stdout_error(err),
        }
    } else {
        RunnerOutput::ok(format!("{}\n", stage150_report(None)))
    }
}

#[derive(Debug, Clone)]
struct Stage150Options {
    execute_smoke: bool,
    root: PathBuf,
}

impl Stage150Options {
    fn parse(args: &[String]) -> Result<Self, RunnerOutput> {
        let mut opts = Self {
            execute_smoke: false,
            root: dae_daemon::default_stage150_root(),
        };
        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--execute-smoke" => opts.execute_smoke = true,
                "--root" => {
                    let Some(value) = iter.next() else {
                        return Err(RunnerOutput::usage("missing stage150 --root value"));
                    };
                    opts.root = value.into();
                }
                _ if arg.starts_with("--root=") => {
                    opts.root = arg.split_once('=').unwrap().1.into();
                }
                _ => {
                    return Err(RunnerOutput::usage(format!(
                        "unsupported stage150 argument: {arg}"
                    )));
                }
            }
        }
        Ok(opts)
    }
}

fn stage150_report(smoke: Option<Value>) -> Value {
    let smoke_passed = smoke.is_some();
    let mut report = json!({
        "name": "stage150-rust-daemon-lifecycle-smoke-gate",
        "stage": "stage150",
        "evidence_class": "rust-daemon-opt-in-lifecycle-smoke-gate",
        "execute_smoke": smoke_passed,
        "read_only": !smoke_passed,
        "blocked": false,
        "blockers": []
    });
    for key in [
        "rust_daemon_identity_scaffolded",
        "rust_daemon_crate_manifest_exists",
        "rust_daemon_optin_binary_exists",
        "rust_daemon_lifecycle_smoke_harness_available",
        "go_default_path_preserved",
        "go_fallback_required",
    ] {
        report[key] = json!(true);
    }
    report["rust_daemon_lifecycle_smoke_passed"] = json!(smoke_passed);
    report["isolated_pid_progress_paths_validated"] = json!(smoke_passed);
    report["production_paths_mutated"] = json!(false);
    for key in [
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
    report["lifecycle_scope"] = json!([
        "isolated pid file",
        "isolated progress file",
        "sdnotify READY=1 record",
        "startup ReloadDone byte",
        "reload ReloadSend/ReloadProcessing/ReloadDone sequence",
        "suspend ReloadProcessing/ReloadDone sequence",
        "no production /var/run mutation"
    ]);
    report["remaining_blockers"] = json!([
        "Rust default run entrypoint and control-plane ownership are not admitted",
        "Stage150 lifecycle smoke does not start production tproxy/eBPF/control-plane traffic",
        "matched benchmark cannot execute until control-plane lifecycle and traffic smoke pass",
        "default daemon and product-chain switches remain closed"
    ]);
    report["next_admission_queue"] = json!([
        {
            "stage": "stage151",
            "target": "Rust control-plane owner preflight",
            "required_output": "prove Rust-owned control-plane lifecycle under opt-in test paths"
        },
        {
            "stage": "stage152",
            "target": "matched default daemon benchmark execution",
            "required_output": "run Go and Rust daemon identities on the same corpus after lifecycle/control-plane preflight passes"
        }
    ]);
    report["validation_commands"] = json!([
        "cargo run --manifest-path rust/Cargo.toml -p dae-daemon --bin dae-daemon-optin -- stage150-lifecycle-smoke --root /tmp/dae-stage150-daemon-lifecycle-smoke",
        "cargo test --manifest-path rust/Cargo.toml -p dae-daemon -- --nocapture",
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage150/rust_daemon_lifecycle_smoke_gate.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage150_rust_daemon_lifecycle_smoke_gate.json",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage150-rust-daemon-lifecycle-smoke-gate",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage150-rust-daemon-lifecycle-smoke-gate --execute-smoke --root /tmp/dae-stage150-cli-lifecycle-smoke",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage150 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage150 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage149 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-daemon -p dae-cli -p dae-product -q",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound -p dae-cli -p dae-product -q",
        "cargo fmt --manifest-path rust/Cargo.toml --all -- --check",
        "git diff --check"
    ]);
    report["source"] = json!([
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage150",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.1",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.8",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:30.2",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:30.3",
        "rust/crates/dae-daemon/src/lifecycle.rs",
        "rust/crates/dae-daemon/src/runner.rs"
    ]);
    if let Some(smoke) = smoke {
        report["smoke"] = smoke;
    }
    report
}
