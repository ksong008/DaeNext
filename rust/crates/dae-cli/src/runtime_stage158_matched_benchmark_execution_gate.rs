use serde_json::{Value, json};

use crate::runner::RunnerOutput;

pub(crate) fn run_stage158_matched_benchmark_execution_gate(args: &[String]) -> RunnerOutput {
    if let Some(arg) = args.first() {
        return RunnerOutput::usage(format!("unsupported stage158 argument: {arg}"));
    }
    RunnerOutput::ok(format!("{}\n", stage158_report()))
}

fn stage158_report() -> Value {
    let mut report = json!({
        "name": "stage158-matched-default-daemon-benchmark-execution-gate",
        "stage": "stage158",
        "prior_gate": "stage157-control-plane-entrypoint-admission-gate",
        "evidence_class": "read-only-matched-default-daemon-benchmark-execution-gate",
        "execute_smoke": false,
        "read_only": true,
        "blocked": true,
        "blockers": [
            "production listener binding is still closed",
            "eBPF attach is still closed",
            "matched Go/Rust default daemon benchmark cannot execute without production-equivalent listener and eBPF ownership",
            "default daemon and product-chain switches remain closed"
        ]
    });
    for key in [
        "matched_benchmark_execution_gate_recorded",
        "stage156_run_identity_carried",
        "stage157_control_plane_entrypoint_carried",
        "benchmark_corpus_manifest_recorded",
        "same_host_execution_requirements_recorded",
        "benchmark_artifact_requirements_recorded",
        "benchmark_blocker_recorded",
        "go_default_path_preserved",
        "go_fallback_required",
    ] {
        report[key] = json!(true);
    }
    for key in [
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
    report["precondition_matrix"] = json!([
        {
            "area": "Go default daemon identity",
            "status": "available",
            "evidence": "Go dae run remains the preserved default benchmark baseline",
            "blocker": ""
        },
        {
            "area": "Rust default run identity",
            "status": "opt-in-admitted",
            "evidence": "Stage156 admits run-shaped Rust default identity under isolated paths",
            "blocker": ""
        },
        {
            "area": "Rust control-plane entrypoint",
            "status": "opt-in-admitted",
            "evidence": "Stage157 composes Stage156 run identity with Stage151 owner preflight",
            "blocker": ""
        },
        {
            "area": "production listener",
            "status": "closed",
            "evidence": "Stage157 explicitly keeps production_listener_bound=false",
            "blocker": "matched default daemon benchmark cannot execute production-equivalent datapath"
        },
        {
            "area": "eBPF ownership",
            "status": "closed",
            "evidence": "Stage157 records BPF owner transfer contract but keeps ebpf_attached=false",
            "blocker": "matched default daemon benchmark cannot prove tproxy/eBPF parity"
        }
    ]);
    report["benchmark_corpus"] = json!([
        "startup time and OnReady pid/progress/sdnotify behavior",
        "TCP proxy latency and throughput",
        "UDP proxy latency, loss, and throughput",
        "DNS UDP/53 latency, cache hit, and DNS cache migration behavior",
        "reload success, invalid-config rollback, listener reuse, and reload scoped resource cleanup",
        "admitted outbound protocol matrix under default daemon identity",
        "RuntimeOverview, RSS, CPU, active connections, UDP sessions, and DNS observability"
    ]);
    report["artifact_requirements"] = json!([
        "raw command logs",
        "exact config corpus",
        "host, kernel, and capability metadata",
        "Go daemon version/build metadata",
        "Rust daemon version/build metadata",
        "RSS/CPU/runtime overview samples",
        "rollback result and cleanup evidence"
    ]);
    report["gate_decision"] = json!(
        "Stage158 records matched benchmark execution requirements but keeps benchmark execution blocked because production listener binding and eBPF attach remain closed; no benchmark numbers are recorded or implied"
    );
    report["remaining_blockers"] = json!([
        "production listener binding remains closed",
        "eBPF attach remains closed",
        "matched Go/Rust default daemon benchmark has not executed",
        "true Rust default daemon admission remains false until matched benchmark data exists",
        "default daemon and product-chain switches remain closed"
    ]);
    report["next_admission_queue"] = json!([
        {
            "stage": "stage159",
            "target": "production listener and eBPF benchmark preflight policy",
            "required_output": "define the minimal safe path for opening production-equivalent listener/eBPF benchmark evidence without switching defaults"
        }
    ]);
    report["validation_commands"] = json!([
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage158/matched_default_daemon_benchmark_execution_gate.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage158_matched_default_daemon_benchmark_execution_gate.json",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage158-matched-default-daemon-benchmark-execution-gate",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage158 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage158 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage157 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-daemon -p dae-cli -p dae-product -q",
        "cargo fmt --manifest-path rust/Cargo.toml --all -- --check",
        "git diff --check"
    ]);
    report["source"] = json!([
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage158",
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage154",
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage156",
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage157",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.3",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.4",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.5",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.8"
    ]);
    report
}
