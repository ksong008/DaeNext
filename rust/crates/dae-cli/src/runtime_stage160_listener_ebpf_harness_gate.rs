use std::path::PathBuf;

use serde_json::{Value, json};

use crate::runner::RunnerOutput;

pub(crate) fn run_stage160_listener_ebpf_harness_gate(args: &[String]) -> RunnerOutput {
    let opts = match Stage160Options::parse(args) {
        Ok(opts) => opts,
        Err(output) => return output,
    };
    if opts.execute_smoke {
        match dae_daemon::stage160_listener_ebpf_preflight_harness_report(&opts.root) {
            Ok(smoke) => RunnerOutput::ok(format!("{}\n", stage160_report(Some(smoke)))),
            Err(err) => RunnerOutput::stdout_error(err),
        }
    } else {
        RunnerOutput::ok(format!("{}\n", stage160_report(None)))
    }
}

#[derive(Debug, Clone)]
struct Stage160Options {
    execute_smoke: bool,
    root: PathBuf,
}

impl Stage160Options {
    fn parse(args: &[String]) -> Result<Self, RunnerOutput> {
        let mut opts = Self {
            execute_smoke: false,
            root: dae_daemon::default_stage160_root(),
        };
        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--execute-smoke" => opts.execute_smoke = true,
                "--root" => {
                    let Some(value) = iter.next() else {
                        return Err(RunnerOutput::usage("missing stage160 --root value"));
                    };
                    opts.root = value.into();
                }
                _ if arg.starts_with("--root=") => {
                    opts.root = arg.split_once('=').unwrap().1.into();
                }
                _ => {
                    return Err(RunnerOutput::usage(format!(
                        "unsupported stage160 argument: {arg}"
                    )));
                }
            }
        }
        Ok(opts)
    }
}

fn stage160_report(smoke: Option<Value>) -> Value {
    let smoke_passed = smoke.is_some();
    let mut report = json!({
        "name": "stage160-isolated-listener-ebpf-preflight-harness-gate",
        "stage": "stage160",
        "prior_gate": "stage159-production-listener-ebpf-benchmark-preflight-policy-gate",
        "evidence_class": "opt-in-isolated-listener-temporary-ebpf-preflight-harness-gate",
        "execute_smoke": smoke_passed,
        "read_only": !smoke_passed,
        "blocked": true,
        "blockers": [
            "temporary eBPF map creation/attach smoke is not executed in Stage160",
            "matched Go/Rust default daemon benchmark remains blocked until eBPF attach preflight passes",
            "default daemon and product-chain switches remain closed"
        ]
    });
    for key in [
        "isolated_listener_preflight_harness_available",
        "capability_preflight_harness_available",
        "temporary_bpf_pin_scope_harness_available",
        "go_default_path_preserved",
        "go_fallback_required",
    ] {
        report[key] = json!(true);
    }
    for key in [
        "temporary_port_scope_validated",
        "tcp_udp_loopback_listener_smoke_passed",
        "capability_preflight_executed",
        "temporary_bpf_pin_scope_validated",
        "rollback_cleanup_smoke_passed",
        "listener_fd_map_key_contract_recorded",
    ] {
        report[key] = json!(smoke_passed);
    }
    for key in [
        "production_listener_bound",
        "isolated_namespace_listener_smoke_passed",
        "ebpf_attached",
        "temporary_ebpf_attach_smoke_passed",
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
            "area": "temporary listener binding",
            "status": if smoke_passed { "passed-opt-in-smoke" } else { "harness-available-not-executed" },
            "evidence": "bind loopback TCP and UDP sockets on the same ephemeral port under an explicit temporary root",
            "boundary": "does not bind production tproxy port and does not write listen_socket_map",
            "closed_flag": "production_listener_bound=false"
        },
        {
            "area": "listen socket map contract",
            "status": if smoke_passed { "contract-recorded" } else { "recorded-not-executed" },
            "evidence": "records daenew BPF listen_socket_map key 0 for TCP and key 1 for UDP",
            "boundary": "Stage160 does not mutate any BPF map",
            "closed_flag": "ebpf_attached=false"
        },
        {
            "area": "capability preflight",
            "status": if smoke_passed { "executed-read-only" } else { "harness-available-not-executed" },
            "evidence": "reads CapEff and bpffs mount state to classify future temporary attach eligibility",
            "boundary": "capability presence is not eBPF attach success",
            "closed_flag": "temporary_ebpf_attach_smoke_passed=false"
        },
        {
            "area": "temporary BPF pin scope",
            "status": if smoke_passed { "created-and-cleaned" } else { "harness-available-not-executed" },
            "evidence": "creates and removes a temporary pin marker under /tmp/dae-stage160* only",
            "boundary": "marker cleanup is not map creation or tc attach",
            "closed_flag": "benchmark_executable_now=false"
        },
        {
            "area": "default safety",
            "status": "closed-preserved",
            "evidence": "Go default path, outbound/quic-go dependency boundary, default switch, and product-chain switch stay unchanged",
            "boundary": "Stage160 evidence is opt-in harness evidence only",
            "closed_flag": "default_switch_allowed=false"
        }
    ]);
    report["remaining_blockers"] = json!([
        "temporary eBPF map creation and attach smoke remains closed",
        "production listener binding remains closed",
        "matched Go/Rust default daemon benchmark has not executed",
        "true Rust default daemon admission remains false until matched benchmark data exists",
        "default daemon and product-chain switches remain closed"
    ]);
    report["next_admission_queue"] = json!([
        {
            "stage": "stage161",
            "target": "temporary eBPF map creation and attach preflight",
            "required_output": "create and clean temporary BPF maps/pins only when capability and bpffs preflight allow it; otherwise record environment blocker"
        }
    ]);
    report["validation_commands"] = json!([
        "cargo run --manifest-path rust/Cargo.toml -p dae-daemon --bin dae-daemon-optin -- stage160-listener-ebpf-preflight-harness --root /tmp/dae-stage160-daemon-preflight",
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage160/isolated_listener_ebpf_preflight_harness_gate.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage160_isolated_listener_ebpf_preflight_harness_gate.json",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage160-isolated-listener-ebpf-preflight-harness-gate",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage160-isolated-listener-ebpf-preflight-harness-gate --execute-smoke --root /tmp/dae-stage160-cli-preflight",
        "cargo test --manifest-path rust/Cargo.toml -p dae-daemon stage160 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage160 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage160 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage159 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-daemon -p dae-cli -p dae-product -q",
        "cargo fmt --manifest-path rust/Cargo.toml --all -- --check",
        "git diff --check"
    ]);
    report["source"] = json!([
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage160",
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage159",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:11.1",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:11.2",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.4",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.5",
        "rust/crates/dae-daemon/src/listener_ebpf_preflight.rs"
    ]);
    if let Some(smoke) = smoke {
        report["smoke"] = smoke;
    }
    report
}
