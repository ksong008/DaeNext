use std::path::PathBuf;

use serde_json::{Value, json};

use crate::runner::RunnerOutput;

pub(crate) fn run_stage156_default_run_identity_gate(args: &[String]) -> RunnerOutput {
    let opts = match Stage156Options::parse(args) {
        Ok(opts) => opts,
        Err(output) => return output,
    };
    if opts.execute_smoke {
        let daemon_opts = opts.daemon_options();
        match dae_daemon::stage156_default_run_identity_admission_report(&daemon_opts) {
            Ok(smoke) => RunnerOutput::ok(format!("{}\n", stage156_report(Some(smoke)))),
            Err(err) => RunnerOutput::stdout_error(err),
        }
    } else {
        RunnerOutput::ok(format!("{}\n", stage156_report(None)))
    }
}

#[derive(Debug, Clone)]
struct Stage156Options {
    execute_smoke: bool,
    root: PathBuf,
    config: Option<PathBuf>,
    logfile: Option<PathBuf>,
    disable_timestamp: bool,
    disable_pidfile: bool,
    disable_sudo: bool,
}

impl Stage156Options {
    fn parse(args: &[String]) -> Result<Self, RunnerOutput> {
        let mut opts = Self {
            execute_smoke: false,
            root: dae_daemon::default_stage156_root(),
            config: None,
            logfile: None,
            disable_timestamp: true,
            disable_pidfile: false,
            disable_sudo: true,
        };
        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--execute-smoke" => opts.execute_smoke = true,
                "--root" => {
                    let Some(value) = iter.next() else {
                        return Err(RunnerOutput::usage("missing stage156 --root value"));
                    };
                    opts.root = value.into();
                }
                _ if arg.starts_with("--root=") => {
                    opts.root = arg.split_once('=').unwrap().1.into();
                }
                "-c" | "--config" => {
                    let Some(value) = iter.next() else {
                        return Err(RunnerOutput::usage("missing stage156 --config value"));
                    };
                    opts.config = Some(value.into());
                }
                _ if arg.starts_with("--config=") => {
                    opts.config = Some(arg.split_once('=').unwrap().1.into());
                }
                "--logfile" => {
                    let Some(value) = iter.next() else {
                        return Err(RunnerOutput::usage("missing stage156 --logfile value"));
                    };
                    opts.logfile = Some(value.into());
                }
                _ if arg.starts_with("--logfile=") => {
                    opts.logfile = Some(arg.split_once('=').unwrap().1.into());
                }
                "--disable-timestamp" => opts.disable_timestamp = true,
                "--disable-pidfile" => opts.disable_pidfile = true,
                "--disable-sudo" => opts.disable_sudo = true,
                _ => {
                    return Err(RunnerOutput::usage(format!(
                        "unsupported stage156 argument: {arg}"
                    )));
                }
            }
        }
        Ok(opts)
    }

    fn daemon_options(&self) -> dae_daemon::Stage156DefaultRunIdentityOptions {
        let mut opts = dae_daemon::Stage156DefaultRunIdentityOptions::under_root(&self.root);
        if let Some(config) = &self.config {
            opts.config = config.clone();
        }
        if let Some(logfile) = &self.logfile {
            opts.logfile = logfile.clone();
        }
        opts.disable_timestamp = self.disable_timestamp;
        opts.disable_pidfile = self.disable_pidfile;
        opts.disable_sudo = self.disable_sudo;
        opts
    }
}

fn stage156_report(smoke: Option<Value>) -> Value {
    let smoke_passed = smoke.is_some();
    let mut report = json!({
        "name": "stage156-rust-default-run-identity-admission-gate",
        "stage": "stage156",
        "prior_gate": "stage155-product-chain-default-switch-blocker-review-gate",
        "evidence_class": "rust-daemon-opt-in-default-run-identity-admission-gate",
        "execute_smoke": smoke_passed,
        "read_only": !smoke_passed,
        "blocked": false,
        "blockers": []
    });
    for key in [
        "rust_default_run_identity_harness_available",
        "go_default_path_preserved",
        "go_fallback_required",
    ] {
        report[key] = json!(true);
    }
    for key in [
        "rust_default_run_identity_optin_admitted",
        "rust_default_run_entrypoint_exists",
        "config_corpus_loaded",
        "run_shaped_flags_validated",
        "run_identity_config_corpus_validated",
        "run_identity_on_ready_contract_validated",
        "isolated_pid_progress_paths_validated",
        "stage153_wrapper_reused",
    ] {
        report[key] = json!(smoke_passed);
    }
    for key in [
        "production_run_command_replaced",
        "production_pid_progress_paths_mutated",
        "production_signal_handler_installed",
        "rust_default_control_plane_entrypoint_admitted",
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
    report["identity_scope"] = json!([
        "Rust default run identity shape is opt-in only",
        "run-shaped flags are validated only during execute-smoke",
        "config corpus is read from an isolated test path",
        "pid/progress/sdnotify/log files are written only under /tmp/dae-stage156*",
        "Go default dae run command is preserved"
    ]);
    report["remaining_blockers"] = json!([
        "Rust default control-plane entrypoint is not admitted",
        "production listener binding and eBPF attach remain closed",
        "matched Go/Rust default daemon benchmark has not executed",
        "true Rust default daemon admission remains false until production control-plane and matched benchmark pass",
        "default daemon and product-chain switches remain closed"
    ]);
    report["next_admission_queue"] = json!([
        {
            "stage": "stage157",
            "target": "production control-plane entrypoint admission",
            "required_output": "prove listener reuse, eBPF ownership transfer, DNS cache guard, and rollback semantics before production binding"
        },
        {
            "stage": "stage158",
            "target": "matched Go/Rust default daemon benchmark execution",
            "required_output": "run the same config corpus on Go default daemon and true Rust default daemon before any default/product switch"
        }
    ]);
    report["validation_commands"] = json!([
        "cargo run --manifest-path rust/Cargo.toml -p dae-daemon --bin dae-daemon-optin -- stage156-default-run-identity-admission --root /tmp/dae-stage156-default-run-identity",
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage156/rust_default_run_identity_admission_gate.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage156_rust_default_run_identity_admission_gate.json",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage156-rust-default-run-identity-admission-gate",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage156-rust-default-run-identity-admission-gate --execute-smoke --root /tmp/dae-stage156-cli-default-run-identity",
        "cargo test --manifest-path rust/Cargo.toml -p dae-daemon stage156 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage156 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage156 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage155 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-daemon -p dae-cli -p dae-product -q",
        "cargo fmt --manifest-path rust/Cargo.toml --all -- --check",
        "git diff --check"
    ]);
    report["source"] = json!([
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage156",
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage153",
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage155",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.1",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.8",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:28.3",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:28.4",
        "rust/crates/dae-daemon/src/default_run_identity.rs"
    ]);
    if let Some(smoke) = smoke {
        report["smoke"] = smoke;
    }
    report
}
