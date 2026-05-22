use serde_json::{Value, json};

use crate::runner::RunnerOutput;

pub(crate) fn run_stage162_temporary_ebpf_program_gate(args: &[String]) -> RunnerOutput {
    let opts = match Stage162Options::parse(args) {
        Ok(opts) => opts,
        Err(output) => return output,
    };
    let smoke = if opts.execute_smoke {
        Some(run_stage162_smoke())
    } else {
        None
    };
    RunnerOutput::ok(format!("{}\n", stage162_report(smoke)))
}

#[derive(Debug, Clone, Copy)]
struct Stage162Options {
    execute_smoke: bool,
}

impl Stage162Options {
    fn parse(args: &[String]) -> Result<Self, RunnerOutput> {
        let mut opts = Self {
            execute_smoke: false,
        };
        for arg in args {
            match arg.as_str() {
                "--execute-smoke" => opts.execute_smoke = true,
                _ => {
                    return Err(RunnerOutput::usage(format!(
                        "unsupported stage162 argument: {arg}"
                    )));
                }
            }
        }
        Ok(opts)
    }
}

fn run_stage162_smoke() -> Result<Value, String> {
    let smoke = dae_ebpf_support::run_temporary_socket_filter_attach_smoke()
        .map_err(|err| format!("temporary eBPF socket-filter attach smoke failed: {err}"))?;
    Ok(json!({
        "prog_type": smoke.prog_type,
        "prog_name": smoke.prog_name,
        "instruction_count": smoke.instruction_count,
        "attach_target": smoke.attach_target,
        "socket_bound_addr": smoke.socket_bound_addr,
        "program_loaded": smoke.program_loaded,
        "socket_attach_passed": smoke.socket_attach_passed,
        "socket_detach_passed": smoke.socket_detach_passed
    }))
}

fn stage162_report(smoke: Option<Result<Value, String>>) -> Value {
    let execute_smoke = smoke.is_some();
    let (smoke_passed, smoke_value, smoke_error) = match smoke {
        Some(Ok(value)) => (true, Some(value), None),
        Some(Err(err)) => (false, None, Some(err)),
        None => (false, None, None),
    };
    let mut blockers = vec![
        "production tc/netns attach smoke is not executed in Stage162",
        "production listener binding and production eBPF attach remain closed",
        "matched Go/Rust default daemon benchmark remains blocked",
        "default daemon and product-chain switches remain closed",
    ];
    if smoke_error.is_some() {
        blockers.insert(
            0,
            "temporary eBPF socket-filter program load/attach smoke failed in the current environment",
        );
    }

    let mut report = json!({
        "name": "stage162-temporary-ebpf-program-attach-preflight-gate",
        "stage": "stage162",
        "prior_gate": "stage161-temporary-ebpf-map-preflight-gate",
        "evidence_class": "opt-in-temporary-ebpf-program-load-socket-attach-cleanup-preflight-gate",
        "execute_smoke": execute_smoke,
        "read_only": !execute_smoke,
        "blocked": true,
        "blockers": blockers
    });
    report["temporary_ebpf_program_attach_harness_available"] = json!(true);
    for key in [
        "temporary_ebpf_program_load_smoke_passed",
        "temporary_ebpf_socket_attach_smoke_passed",
        "temporary_ebpf_socket_detach_cleanup_smoke_passed",
    ] {
        report[key] = json!(smoke_passed);
    }
    for key in [
        "production_tc_attach_smoke_passed",
        "production_listener_bound",
        "isolated_namespace_listener_smoke_passed",
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
    report["preflight_rows"] = json!([
        {
            "area": "BPF program load",
            "status": if smoke_passed { "passed-opt-in-smoke" } else if execute_smoke { "blocked-by-environment-or-verifier" } else { "harness-available-not-executed" },
            "evidence": "load a two-instruction SocketFilter eBPF program with GPL license through BPF_PROG_LOAD",
            "boundary": "program type is socket-filter only, not tc clsact/tproxy program",
            "closed_flag": "production_tc_attach_smoke_passed=false"
        },
        {
            "area": "temporary socket attach",
            "status": if smoke_passed { "attached-to-temporary-socket" } else if execute_smoke { "not-passed" } else { "not-executed" },
            "evidence": "attach the loaded program to a temporary loopback UDP socket with SO_ATTACH_BPF",
            "boundary": "does not attach to production interfaces, qdisc, netns, or dae tproxy listener",
            "closed_flag": "ebpf_attached=false"
        },
        {
            "area": "detach cleanup",
            "status": if smoke_passed { "detached-and-closed" } else if execute_smoke { "not-passed" } else { "not-executed" },
            "evidence": "detach the socket filter with SO_DETACH_BPF and close temporary fds",
            "boundary": "socket detach does not prove production BPF owner transfer",
            "closed_flag": "benchmark_executable_now=false"
        },
        {
            "area": "default safety",
            "status": "closed-preserved",
            "evidence": "no production listener, no tc hook, no default daemon switch, no product-chain switch",
            "boundary": "Stage162 is temporary socket attach preflight only",
            "closed_flag": "default_switch_allowed=false"
        }
    ]);
    report["remaining_blockers"] = json!([
        "production tc/netns attach remains closed",
        "production listener binding remains closed",
        "matched Go/Rust default daemon benchmark has not executed",
        "true Rust default daemon admission remains false until matched benchmark data exists",
        "default daemon and product-chain switches remain closed"
    ]);
    report["next_admission_queue"] = json!([
        {
            "stage": "stage163",
            "target": "production-equivalent BPF owner transfer and listener map handoff queue",
            "required_output": "compose Stage160 listener, Stage161 map, and Stage162 program attach evidence into a non-production owner-transfer preflight without switching defaults"
        }
    ]);
    report["validation_commands"] = json!([
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage162/temporary_ebpf_program_attach_preflight_gate.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage162_temporary_ebpf_program_attach_preflight_gate.json",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage162-temporary-ebpf-program-attach-preflight-gate",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage162-temporary-ebpf-program-attach-preflight-gate --execute-smoke",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage162 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage162 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage161 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-ebpf-support -p dae-cli -p dae-product -q",
        "cargo fmt --manifest-path rust/Cargo.toml --all -- --check",
        "git diff --check"
    ]);
    report["source"] = json!([
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage162",
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage161",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:11.1",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:11.4",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.4",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.5",
        "rust/crates/dae-ebpf-support/src/temporary_program.rs"
    ]);
    if let Some(value) = smoke_value {
        report["smoke"] = value;
    }
    if let Some(err) = smoke_error {
        report["smoke_error"] = json!(err);
    }
    report
}
