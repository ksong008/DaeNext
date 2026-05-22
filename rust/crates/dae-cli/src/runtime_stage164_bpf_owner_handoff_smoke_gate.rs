use serde_json::{Value, json};

use crate::runner::RunnerOutput;

pub(crate) fn run_stage164_bpf_owner_handoff_smoke_gate(args: &[String]) -> RunnerOutput {
    let opts = match Stage164Options::parse(args) {
        Ok(opts) => opts,
        Err(output) => return output,
    };
    let smoke = if opts.execute_smoke {
        Some(run_stage164_smoke())
    } else {
        None
    };
    RunnerOutput::ok(format!("{}\n", stage164_report(smoke)))
}

#[derive(Debug, Clone, Copy)]
struct Stage164Options {
    execute_smoke: bool,
}

impl Stage164Options {
    fn parse(args: &[String]) -> Result<Self, RunnerOutput> {
        let mut opts = Self {
            execute_smoke: false,
        };
        for arg in args {
            match arg.as_str() {
                "--execute-smoke" => opts.execute_smoke = true,
                _ => {
                    return Err(RunnerOutput::usage(format!(
                        "unsupported stage164 argument: {arg}"
                    )));
                }
            }
        }
        Ok(opts)
    }
}

fn run_stage164_smoke() -> Result<Value, String> {
    let smoke = dae_ebpf_support::run_listen_socket_map_fd_smoke()
        .map_err(|err| format!("temporary listen_socket_map handoff smoke failed: {err}"))?;
    Ok(json!({
        "map_type": smoke.map_type,
        "key_size": smoke.key_size,
        "value_size": smoke.value_size,
        "max_entries": smoke.max_entries,
        "keys_updated": smoke.keys_updated,
        "tcp_listener_fd_recorded": smoke.tcp_listener_fd >= 0,
        "udp_socket_fd_recorded": smoke.udp_socket_fd >= 0,
        "owner_transfer_sequence": [
            "old-owner-eject-temporary-bpf-object",
            "new-owner-inject-temporary-bpf-object",
            "write-listen-socket-map-key-0-tcp-fd",
            "write-listen-socket-map-key-1-udp-fd",
            "ready-after-map-handoff",
            "old-owner-close",
            "temporary-fd-cleanup-on-drop"
        ]
    }))
}

fn stage164_report(smoke: Option<Result<Value, String>>) -> Value {
    let execute_smoke = smoke.is_some();
    let (smoke_passed, smoke_value, smoke_error) = match smoke {
        Some(Ok(value)) => (true, Some(value), None),
        Some(Err(err)) => (false, None, Some(err)),
        None => (false, None, None),
    };
    let mut blockers = vec![
        "production tc/netns attach remains closed",
        "production listener binding remains closed",
        "matched Go/Rust default daemon benchmark remains blocked",
        "default daemon and product-chain switches remain closed",
    ];
    if smoke_error.is_some() {
        blockers.insert(
            0,
            "non-production owner/listen_socket_map handoff smoke failed in the current environment",
        );
    }

    let mut report = json!({
        "name": "stage164-non-production-bpf-owner-listener-handoff-smoke-gate",
        "stage": "stage164",
        "prior_gate": "stage163-bpf-owner-transfer-listener-map-handoff-queue-gate",
        "evidence_class": "opt-in-non-production-bpf-owner-listen-socket-map-handoff-smoke-gate",
        "execute_smoke": execute_smoke,
        "read_only": !execute_smoke,
        "blocked": true,
        "blockers": blockers
    });
    report["non_production_owner_handoff_harness_available"] = json!(true);
    for key in [
        "non_production_owner_transfer_sequence_smoke_passed",
        "listen_socket_map_key_handoff_smoke_passed",
        "temporary_sockmap_cleanup_smoke_passed",
    ] {
        report[key] = json!(smoke_passed);
    }
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
    report["handoff_rows"] = json!([
        {
            "area": "listen_socket_map fd handoff",
            "status": if smoke_passed { "passed-opt-in-smoke" } else if execute_smoke { "not-passed" } else { "harness-available-not-executed" },
            "evidence": "temporary SockMap key 0 receives TCP listener fd and key 1 receives UDP socket fd",
            "boundary": "temporary SockMap is not the production dae listen_socket_map",
            "closed_flag": "production_listener_bound=false"
        },
        {
            "area": "owner transfer sequence",
            "status": if smoke_passed { "sequence-recorded-with-smoke" } else if execute_smoke { "not-passed" } else { "not-executed" },
            "evidence": "old-owner eject, new-owner inject, map handoff before ready, old close, and cleanup are recorded around temporary handles",
            "boundary": "sequence does not yet run through full daemon reload",
            "closed_flag": "ebpf_attached=false"
        },
        {
            "area": "default safety",
            "status": "closed-preserved",
            "evidence": "no production tproxy listener, no tc/netns attach, no default daemon switch, no product-chain switch",
            "boundary": "Stage164 is non-production handoff smoke only",
            "closed_flag": "default_switch_allowed=false"
        }
    ]);
    report["remaining_blockers"] = json!([
        "production tc/netns attach remains closed",
        "production listener binding remains closed",
        "full daemon reload owner-transfer smoke has not executed",
        "matched Go/Rust default daemon benchmark has not executed",
        "default daemon and product-chain switches remain closed"
    ]);
    report["next_admission_queue"] = json!([
        {
            "stage": "stage165",
            "target": "full non-production daemon reload owner-transfer smoke",
            "required_output": "run owner-transfer/listen_socket_map handoff through a reload-shaped daemon harness before production-equivalent benchmark"
        }
    ]);
    report["validation_commands"] = json!([
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage164/non_production_bpf_owner_listener_handoff_smoke_gate.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage164_non_production_bpf_owner_listener_handoff_smoke_gate.json",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage164-non-production-bpf-owner-listener-handoff-smoke-gate",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage164-non-production-bpf-owner-listener-handoff-smoke-gate --execute-smoke",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage164 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage164 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage163 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-ebpf-support -p dae-cli -p dae-product -q",
        "cargo fmt --manifest-path rust/Cargo.toml --all -- --check",
        "git diff --check"
    ]);
    report["source"] = json!([
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage164",
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage163",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.4",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.5",
        "rust/crates/dae-ebpf-support/src/sockmap.rs"
    ]);
    if let Some(value) = smoke_value {
        report["smoke"] = value;
    }
    if let Some(err) = smoke_error {
        report["smoke_error"] = json!(err);
    }
    report
}
