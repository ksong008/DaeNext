use serde_json::{Value, json};

use crate::runner::RunnerOutput;

pub(crate) fn run_stage168_matched_benchmark_execution_gate(args: &[String]) -> RunnerOutput {
    if let Some(arg) = args.first() {
        return RunnerOutput::usage(format!("unsupported stage168 argument: {arg}"));
    }
    RunnerOutput::ok(format!("{}\n", stage168_report()))
}

fn stage168_report() -> Value {
    let mut report = json!({
        "name": "stage168-matched-default-daemon-benchmark-execution-gate",
        "stage": "stage168",
        "prior_gate": "stage167-bounded-production-equivalent-listener-ebpf-benchmark-harness-gate",
        "evidence_class": "read-only-matched-default-daemon-benchmark-execution-gate-after-bounded-metrics",
        "execute_benchmark": false,
        "read_only": true,
        "blocked": true,
        "blockers": [
            "Stage167 bounded metrics are available but are not a matched Go/Rust default daemon benchmark",
            "production tc/netns attach remains closed",
            "Go default daemon and Rust opt-in daemon have not been run on the same corpus in this gate",
            "default daemon and product-chain switches remain closed"
        ]
    });
    for key in [
        "matched_benchmark_execution_gate_refreshed",
        "stage167_bounded_metrics_carried",
        "matched_benchmark_corpus_reconfirmed",
        "go_default_daemon_required",
        "rust_optin_daemon_required",
        "same_host_execution_requirements_reconfirmed",
        "artifact_requirements_reconfirmed",
        "rollback_cleanup_requirements_reconfirmed",
        "go_default_path_preserved",
        "go_fallback_required",
    ] {
        report[key] = json!(true);
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
    report["precondition_matrix"] = json!([
        {
            "area": "bounded production-equivalent metrics",
            "status": "available",
            "evidence": "Stage167 records bounded reload-owner/listen_socket_map metrics with pass/fail and cleanup counts",
            "blocker": ""
        },
        {
            "area": "Go default daemon run",
            "status": "required-not-executed",
            "evidence": "Go dae run remains the preserved default benchmark baseline",
            "blocker": "this gate does not start the Go default daemon"
        },
        {
            "area": "Rust opt-in daemon run",
            "status": "required-not-executed",
            "evidence": "Rust daemon has opt-in identity/control-plane/reload-owner/benchmark harness evidence",
            "blocker": "this gate does not start a Rust default daemon replacement"
        },
        {
            "area": "production tc/netns attach",
            "status": "closed",
            "evidence": "Stage167 bounded metrics are temporary-root metrics",
            "blocker": "matched default daemon benchmark cannot prove production tproxy/eBPF parity while production attach remains closed"
        },
        {
            "area": "default/product admission",
            "status": "closed",
            "evidence": "default and product-chain switch flags remain false",
            "blocker": "true Rust default daemon admission requires matched benchmark data"
        }
    ]);
    report["matched_benchmark_corpus"] = json!([
        "startup time and OnReady pid/progress/sdnotify behavior",
        "reload success, invalid-config rollback, listener reuse, BPF owner transfer, and reload scoped cleanup",
        "TCP tproxy route/dial/relay latency and throughput",
        "UDP tproxy endpoint behavior, loss, and throughput",
        "DNS UDP/53 cache migration, cache hit, and latency behavior",
        "admitted outbound protocol matrix under default daemon identity",
        "RuntimeOverview, RSS, CPU, active TCP connections, UDP sessions, DNS observability, and BPF map stats"
    ]);
    report["artifact_requirements"] = json!([
        "raw command logs for Go and Rust runs",
        "exact config corpus and outbound protocol matrix",
        "host, kernel, bpffs, capability, and sysctl metadata",
        "Go daemon version/build metadata",
        "Rust daemon version/build metadata",
        "bounded benchmark artifact summary from Stage167",
        "RSS/CPU/runtime overview samples",
        "rollback result and cleanup evidence"
    ]);
    report["gate_decision"] = json!(
        "Stage168 refreshes the matched Go/Rust default daemon benchmark execution gate after Stage167 bounded metrics, but does not record matched benchmark data because Go default daemon and Rust opt-in daemon have not been run on the same corpus and production tc/netns attach remains closed"
    );
    report["remaining_blockers"] = json!([
        "Go default daemon and Rust opt-in daemon have not been run on the same benchmark corpus",
        "production tc/netns attach remains closed",
        "matched Go/Rust default daemon benchmark has not executed",
        "true Rust default daemon admission remains false until matched benchmark data exists",
        "default daemon and product-chain switches remain closed"
    ]);
    report["next_admission_queue"] = json!([
        {
            "stage": "stage169",
            "target": "matched benchmark corpus artifact builder",
            "required_output": "materialize the exact same corpus and command artifact layout for Go default daemon and Rust opt-in daemon without switching defaults"
        }
    ]);
    report["validation_commands"] = json!([
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage168/matched_default_daemon_benchmark_execution_gate.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage168_matched_default_daemon_benchmark_execution_gate.json",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage168-matched-default-daemon-benchmark-execution-gate",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage168 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage168 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage167 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli -p dae-product -q",
        "cargo fmt --manifest-path rust/Cargo.toml --all -- --check",
        "git diff --check"
    ]);
    report["source"] = json!([
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage168",
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage158",
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage166",
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage167",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.4",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.5",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.8"
    ]);
    report
}
