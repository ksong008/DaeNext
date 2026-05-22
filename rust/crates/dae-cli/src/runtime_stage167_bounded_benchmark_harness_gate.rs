use std::path::PathBuf;

use serde_json::{Value, json};

use crate::runner::RunnerOutput;

pub(crate) fn run_stage167_bounded_benchmark_harness_gate(args: &[String]) -> RunnerOutput {
    let opts = match Stage167Options::parse(args) {
        Ok(opts) => opts,
        Err(output) => return output,
    };
    if opts.execute_benchmark {
        match dae_daemon::stage167_reload_owner_benchmark_report(&opts.root, opts.iterations) {
            Ok(benchmark) => RunnerOutput::ok(format!("{}\n", stage167_report(Some(benchmark)))),
            Err(err) => RunnerOutput::stdout_error(err),
        }
    } else {
        RunnerOutput::ok(format!("{}\n", stage167_report(None)))
    }
}

#[derive(Debug, Clone)]
struct Stage167Options {
    execute_benchmark: bool,
    root: PathBuf,
    iterations: u32,
}

impl Stage167Options {
    fn parse(args: &[String]) -> Result<Self, RunnerOutput> {
        let mut opts = Self {
            execute_benchmark: false,
            root: dae_daemon::default_stage167_root(),
            iterations: 3,
        };
        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--execute-benchmark" => opts.execute_benchmark = true,
                "--root" => {
                    let Some(value) = iter.next() else {
                        return Err(RunnerOutput::usage("missing stage167 --root value"));
                    };
                    opts.root = value.into();
                }
                _ if arg.starts_with("--root=") => {
                    opts.root = arg.split_once('=').unwrap().1.into();
                }
                "--iterations" => {
                    let Some(value) = iter.next() else {
                        return Err(RunnerOutput::usage("missing stage167 --iterations value"));
                    };
                    opts.iterations = parse_iterations(value)?;
                }
                _ if arg.starts_with("--iterations=") => {
                    opts.iterations = parse_iterations(arg.split_once('=').unwrap().1)?;
                }
                _ => {
                    return Err(RunnerOutput::usage(format!(
                        "unsupported stage167 argument: {arg}"
                    )));
                }
            }
        }
        Ok(opts)
    }
}

fn parse_iterations(value: &str) -> Result<u32, RunnerOutput> {
    value
        .parse()
        .map_err(|_| RunnerOutput::usage("invalid stage167 --iterations value"))
}

fn stage167_report(benchmark: Option<Value>) -> Value {
    let execute_benchmark = benchmark.is_some();
    let benchmark_recorded = benchmark
        .as_ref()
        .and_then(|value| value["production_equivalent_listener_ebpf_benchmark_recorded"].as_bool())
        .unwrap_or(false);
    let bounded_executable_now = benchmark
        .as_ref()
        .and_then(|value| value["bounded_benchmark_executable_now"].as_bool())
        .unwrap_or(false);
    let artifact_summary_recorded = benchmark
        .as_ref()
        .and_then(|value| value["benchmark_artifact_summary_recorded"].as_bool())
        .unwrap_or(false);
    let rollback_cleanup_recorded = benchmark
        .as_ref()
        .and_then(|value| value["rollback_cleanup_benchmark_recorded"].as_bool())
        .unwrap_or(false);

    let mut report = json!({
        "name": "stage167-bounded-production-equivalent-listener-ebpf-benchmark-harness-gate",
        "stage": "stage167",
        "prior_gate": "stage166-production-equivalent-listener-ebpf-benchmark-admission-queue-gate",
        "evidence_class": "opt-in-bounded-production-equivalent-listener-ebpf-benchmark-harness-gate",
        "execute_benchmark": execute_benchmark,
        "read_only": !execute_benchmark,
        "blocked": true,
        "blockers": [
            "bounded listener/eBPF benchmark is not a matched Go/Rust default daemon benchmark",
            "production tc/netns attach remains closed",
            "default daemon and product-chain switches remain closed"
        ],
        "bounded_production_equivalent_benchmark_harness_available": true
    });
    report["bounded_production_equivalent_benchmark_harness_executed"] = json!(execute_benchmark);
    report["bounded_benchmark_executable_now"] = json!(bounded_executable_now);
    report["production_equivalent_listener_ebpf_benchmark_recorded"] = json!(benchmark_recorded);
    report["reload_owner_handoff_benchmark_recorded"] = json!(benchmark_recorded);
    report["benchmark_artifact_summary_recorded"] = json!(artifact_summary_recorded);
    report["rollback_cleanup_benchmark_recorded"] = json!(rollback_cleanup_recorded);
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
    report["benchmark_rows"] = json!([
        {
            "area": "bounded listener/eBPF benchmark harness",
            "status": if benchmark_recorded { "executed-with-metrics" } else if execute_benchmark { "executed-with-blocker" } else { "available-not-executed" },
            "evidence": "runs Stage165 reload owner handoff repeatedly and records total/min/max/avg elapsed_ns plus pass/fail counts",
            "boundary": "bounded benchmark uses temporary Stage165 roots and is not a matched Go/Rust default daemon benchmark",
            "closed_flag": "matched_go_rust_default_daemon_benchmark_recorded=false"
        },
        {
            "area": "cleanup",
            "status": if rollback_cleanup_recorded { "recorded" } else if execute_benchmark { "partial" } else { "not-executed" },
            "evidence": "removes per-iteration Stage165 temporary roots after collecting metrics",
            "boundary": "cleanup proof does not imply production tc/netns detach",
            "closed_flag": "production_tc_attach_smoke_passed=false"
        },
        {
            "area": "default safety",
            "status": "closed-preserved",
            "evidence": "Go default path, outbound/quic-go dependency boundary, matched default benchmark, default switch, and product-chain switch stay unchanged",
            "boundary": "Stage167 produces bounded metrics only",
            "closed_flag": "default_switch_allowed=false"
        }
    ]);
    report["remaining_blockers"] = json!([
        "matched Go/Rust default daemon benchmark has not executed",
        "production tc/netns attach remains closed",
        "true Rust default daemon admission remains false until matched benchmark data exists",
        "default daemon and product-chain switches remain closed"
    ]);
    report["next_admission_queue"] = json!([
        {
            "stage": "stage168",
            "target": "matched Go/Rust default daemon benchmark execution gate",
            "required_output": "compare Go default daemon and Rust opt-in daemon on the same corpus only after production-equivalent benchmark artifacts are accepted"
        }
    ]);
    report["validation_commands"] = json!([
        "cargo run --manifest-path rust/Cargo.toml -p dae-daemon --bin dae-daemon-optin -- stage167-reload-owner-benchmark --root /tmp/dae-stage167-reload-owner-benchmark --iterations 3",
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage167/bounded_listener_ebpf_benchmark_harness_gate.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage167_bounded_listener_ebpf_benchmark_harness_gate.json",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage167-bounded-production-equivalent-listener-ebpf-benchmark-harness-gate",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage167-bounded-production-equivalent-listener-ebpf-benchmark-harness-gate --execute-benchmark --iterations 3 --root /tmp/dae-stage167-cli-benchmark",
        "cargo test --manifest-path rust/Cargo.toml -p dae-daemon stage167 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage167 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage167 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage166 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-daemon -p dae-cli -p dae-product -q",
        "cargo fmt --manifest-path rust/Cargo.toml --all -- --check",
        "git diff --check"
    ]);
    report["source"] = json!([
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage167",
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage166",
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage165",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:11.1",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.4",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.5",
        "rust/crates/dae-daemon/src/reload_owner_benchmark.rs"
    ]);
    if let Some(benchmark) = benchmark {
        report["benchmark"] = benchmark;
    }
    report
}
