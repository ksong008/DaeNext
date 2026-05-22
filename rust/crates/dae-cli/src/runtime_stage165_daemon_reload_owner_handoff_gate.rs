use std::path::PathBuf;

use serde_json::{Value, json};

use crate::runner::RunnerOutput;

pub(crate) fn run_stage165_daemon_reload_owner_handoff_gate(args: &[String]) -> RunnerOutput {
    let opts = match Stage165Options::parse(args) {
        Ok(opts) => opts,
        Err(output) => return output,
    };
    if opts.execute_smoke {
        match dae_daemon::stage165_reload_owner_handoff_smoke_report(&opts.root) {
            Ok(smoke) => RunnerOutput::ok(format!("{}\n", stage165_report(Some(smoke)))),
            Err(err) => RunnerOutput::stdout_error(err),
        }
    } else {
        RunnerOutput::ok(format!("{}\n", stage165_report(None)))
    }
}

#[derive(Debug, Clone)]
struct Stage165Options {
    execute_smoke: bool,
    root: PathBuf,
}

impl Stage165Options {
    fn parse(args: &[String]) -> Result<Self, RunnerOutput> {
        let mut opts = Self {
            execute_smoke: false,
            root: dae_daemon::default_stage165_root(),
        };
        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--execute-smoke" => opts.execute_smoke = true,
                "--root" => {
                    let Some(value) = iter.next() else {
                        return Err(RunnerOutput::usage("missing stage165 --root value"));
                    };
                    opts.root = value.into();
                }
                _ if arg.starts_with("--root=") => {
                    opts.root = arg.split_once('=').unwrap().1.into();
                }
                _ => {
                    return Err(RunnerOutput::usage(format!(
                        "unsupported stage165 argument: {arg}"
                    )));
                }
            }
        }
        Ok(opts)
    }
}

fn stage165_report(smoke: Option<Value>) -> Value {
    let execute_smoke = smoke.is_some();
    let smoke_passed = smoke
        .as_ref()
        .and_then(|value| {
            value["non_production_daemon_reload_owner_transfer_smoke_passed"].as_bool()
        })
        .unwrap_or(false);
    let scoped_cleanup_passed = smoke
        .as_ref()
        .and_then(|value| value["reload_scoped_cleanup_smoke_passed"].as_bool())
        .unwrap_or(false);
    let rollback_recorded = smoke
        .as_ref()
        .and_then(|value| value["rollback_blocker_recorded"].as_bool())
        .unwrap_or(false);
    let listen_handoff_passed = smoke
        .as_ref()
        .and_then(|value| value["listen_socket_map_key_handoff_smoke_passed"].as_bool())
        .unwrap_or(false);

    let mut blockers = vec![
        "production tc/netns attach remains closed",
        "production listener binding remains closed",
        "matched Go/Rust default daemon benchmark remains blocked",
        "default daemon and product-chain switches remain closed",
    ];
    if execute_smoke && !smoke_passed {
        blockers.insert(
            0,
            "non-production daemon reload owner handoff smoke did not pass in the current environment",
        );
    }

    let mut report = json!({
        "name": "stage165-non-production-daemon-reload-owner-handoff-smoke-gate",
        "stage": "stage165",
        "prior_gate": "stage164-non-production-bpf-owner-listener-handoff-smoke-gate",
        "evidence_class": "opt-in-non-production-daemon-reload-owner-handoff-smoke-gate",
        "execute_smoke": execute_smoke,
        "read_only": !execute_smoke,
        "blocked": true,
        "blockers": blockers
    });
    report["reload_owner_handoff_harness_available"] = json!(true);
    report["non_production_daemon_reload_owner_transfer_smoke_passed"] = json!(smoke_passed);
    report["reload_current_swap_smoke_passed"] = json!(smoke_passed);
    report["old_owner_close_smoke_passed"] = json!(smoke_passed);
    report["listener_reuse_sequence_smoke_passed"] = json!(smoke_passed);
    report["reload_scoped_cleanup_smoke_passed"] = json!(scoped_cleanup_passed);
    report["rollback_blocker_recorded"] = json!(rollback_recorded);
    report["listen_socket_map_key_handoff_smoke_passed"] = json!(listen_handoff_passed);
    for key in [
        "production_listener_bound",
        "production_tc_attach_smoke_passed",
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
    report["reload_rows"] = json!([
        {
            "area": "daemon reload owner handoff",
            "status": if smoke_passed { "passed-opt-in-smoke" } else if execute_smoke { "not-passed" } else { "harness-available-not-executed" },
            "evidence": "old owner ejects a temporary BPF object, new owner injects it, writes listen_socket_map keys 0/1, swaps current, closes old owner, and records reload callback order",
            "boundary": "the harness uses temporary SockMap/listener handles, not production dae tc/netns attach",
            "closed_flag": "production_tc_attach_smoke_passed=false"
        },
        {
            "area": "current swap and old close",
            "status": if smoke_passed { "validated" } else if execute_smoke { "not-validated" } else { "not-executed" },
            "evidence": "current owner changes from old-owner to new-owner only after listen_socket_map handoff; old owner closes after swap",
            "boundary": "does not reuse a production listener from a live Go daemon",
            "closed_flag": "production_listener_bound=false"
        },
        {
            "area": "reload scoped cleanup and rollback blocker",
            "status": if rollback_recorded && scoped_cleanup_passed { "recorded-with-cleanup" } else if execute_smoke { "partial" } else { "not-executed" },
            "evidence": "temporary reload-scoped resource is created and removed; rollback blocker records current-remains-old order for failed next build",
            "boundary": "rollback is non-production until proven against production owner resources",
            "closed_flag": "ebpf_attached=false"
        },
        {
            "area": "default safety",
            "status": "closed-preserved",
            "evidence": "Go default path, outbound/quic-go dependency boundary, matched benchmark, default switch, and product-chain switch stay unchanged",
            "boundary": "Stage165 is not true Rust default daemon admission",
            "closed_flag": "default_switch_allowed=false"
        }
    ]);
    report["remaining_blockers"] = json!([
        "production tc/netns attach remains closed",
        "production listener binding remains closed",
        "production-equivalent listener/eBPF benchmark has not executed",
        "matched Go/Rust default daemon benchmark has not executed",
        "true Rust default daemon admission remains false until production-equivalent evidence and matched benchmark data exist",
        "default daemon and product-chain switches remain closed"
    ]);
    report["next_admission_queue"] = json!([
        {
            "stage": "stage166",
            "target": "production-equivalent listener/eBPF benchmark admission queue",
            "required_output": "reuse the Stage165 reload owner handoff shape against production-equivalent attach/listener evidence before matched default daemon benchmark"
        }
    ]);
    report["validation_commands"] = json!([
        "cargo run --manifest-path rust/Cargo.toml -p dae-daemon --bin dae-daemon-optin -- stage165-reload-owner-handoff-smoke --root /tmp/dae-stage165-reload-owner-handoff",
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage165/non_production_daemon_reload_owner_handoff_smoke_gate.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage165_non_production_daemon_reload_owner_handoff_smoke_gate.json",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage165-non-production-daemon-reload-owner-handoff-smoke-gate",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage165-non-production-daemon-reload-owner-handoff-smoke-gate --execute-smoke --root /tmp/dae-stage165-cli-reload-owner-handoff",
        "cargo test --manifest-path rust/Cargo.toml -p dae-daemon stage165 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage165 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage165 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage164 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-daemon -p dae-cli -p dae-product -q",
        "cargo fmt --manifest-path rust/Cargo.toml --all -- --check",
        "git diff --check"
    ]);
    report["source"] = json!([
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage165",
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage164",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.4",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.5",
        "rust/crates/dae-daemon/src/reload_owner_handoff.rs",
        "rust/crates/dae-ebpf-support/src/sockmap.rs"
    ]);
    if let Some(smoke) = smoke {
        report["smoke"] = smoke;
    }
    report
}
