use serde_json::{Value, json};

use crate::runner::RunnerOutput;

pub(crate) fn run_stage166_production_equivalent_benchmark_queue_gate(
    args: &[String],
) -> RunnerOutput {
    if let Some(arg) = args.first() {
        return RunnerOutput::usage(format!("unsupported stage166 argument: {arg}"));
    }
    RunnerOutput::ok(format!("{}\n", stage166_report()))
}

fn stage166_report() -> Value {
    let mut report = json!({
        "name": "stage166-production-equivalent-listener-ebpf-benchmark-admission-queue-gate",
        "stage": "stage166",
        "prior_gate": "stage165-non-production-daemon-reload-owner-handoff-smoke-gate",
        "evidence_class": "read-only-production-equivalent-listener-ebpf-benchmark-admission-queue-gate",
        "execute_smoke": false,
        "read_only": true,
        "blocked": true,
        "blockers": [
            "production-equivalent benchmark queue is recorded but benchmark execution is not started",
            "production tc/netns attach remains closed",
            "matched Go/Rust default daemon benchmark remains blocked",
            "default daemon and product-chain switches remain closed"
        ]
    });
    for key in [
        "production_equivalent_benchmark_queue_recorded",
        "stage159_policy_carried",
        "stage160_listener_preflight_carried",
        "stage161_map_preflight_carried",
        "stage162_program_attach_preflight_carried",
        "stage164_listener_handoff_smoke_carried",
        "stage165_reload_owner_handoff_smoke_carried",
        "benchmark_corpus_reconfirmed",
        "benchmark_environment_requirements_recorded",
        "rollback_cleanup_requirements_recorded",
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
    report["admission_rows"] = json!([
        {
            "area": "policy baseline",
            "status": "carried",
            "evidence": "Stage159 records production-equivalent listener/eBPF benchmark policy, temporary scope, capability classification, and rollback cleanup requirements",
            "boundary": "policy evidence alone does not execute benchmark",
            "closed_flag": "benchmark_executable_now=false"
        },
        {
            "area": "listener and temporary BPF primitives",
            "status": "carried",
            "evidence": "Stage160 listener loopback, Stage161 temporary BPF map, and Stage162 temporary BPF program attach are available as bounded preflight evidence",
            "boundary": "temporary primitives are not production tc/netns attach",
            "closed_flag": "production_tc_attach_smoke_passed=false"
        },
        {
            "area": "listen_socket_map handoff",
            "status": "carried",
            "evidence": "Stage164 writes temporary SockMap key 0 TCP fd and key 1 UDP fd and records owner handoff order",
            "boundary": "temporary SockMap is not the production dae listen_socket_map",
            "closed_flag": "production_listener_bound=false"
        },
        {
            "area": "daemon reload owner sequence",
            "status": "carried",
            "evidence": "Stage165 wraps the temporary handoff in reload-shaped current swap, old close, scoped cleanup, listener reuse, and rollback blocker recording",
            "boundary": "non-production daemon reload smoke is not matched default daemon benchmark",
            "closed_flag": "matched_go_rust_default_daemon_benchmark_recorded=false"
        },
        {
            "area": "default safety",
            "status": "closed-preserved",
            "evidence": "Go default path, outbound/quic-go dependency boundary, default switch, and product-chain switch stay unchanged",
            "boundary": "Stage166 records the next benchmark queue only",
            "closed_flag": "default_switch_allowed=false"
        }
    ]);
    report["benchmark_corpus"] = json!([
        "startup OnReady pid/progress/sdnotify behavior",
        "reload success, invalid-config rollback, listener reuse, and reload scoped cleanup",
        "temporary-to-production-equivalent listen_socket_map key 0/1 handoff",
        "TCP tproxy route/dial/relay latency and throughput",
        "UDP tproxy endpoint behavior, loss, and throughput",
        "DNS UDP/53 cache migration, cache hit, and latency behavior",
        "RuntimeOverview, RSS, CPU, active TCP connections, UDP sessions, and BPF map stats"
    ]);
    report["benchmark_environment_requirements"] = json!([
        "same host, kernel, bpffs, and capability metadata for Go and Rust runs",
        "same config corpus and admitted outbound protocol matrix",
        "bounded temporary namespace or explicit production-equivalent sandbox",
        "raw command logs and JSON reports preserved as artifacts",
        "cleanup proof for listeners, BPF objects, pid/progress files, and benchmark logs"
    ]);
    report["remaining_blockers"] = json!([
        "bounded production-equivalent benchmark harness has not executed",
        "production tc/netns attach remains closed",
        "matched Go/Rust default daemon benchmark has not executed",
        "true Rust default daemon admission remains false until production-equivalent evidence and matched benchmark data exist",
        "default daemon and product-chain switches remain closed"
    ]);
    report["next_admission_queue"] = json!([
        {
            "stage": "stage167",
            "target": "bounded production-equivalent listener/eBPF benchmark harness",
            "required_output": "execute an opt-in benchmark harness using the Stage166 queue while preserving default/product switch closure"
        }
    ]);
    report["validation_commands"] = json!([
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage166/production_equivalent_listener_ebpf_benchmark_admission_queue_gate.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage166_production_equivalent_listener_ebpf_benchmark_admission_queue_gate.json",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage166-production-equivalent-listener-ebpf-benchmark-admission-queue-gate",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage166 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage166 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage165 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli -p dae-product -q",
        "cargo fmt --manifest-path rust/Cargo.toml --all -- --check",
        "git diff --check"
    ]);
    report["source"] = json!([
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage166",
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage159",
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage160",
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage161",
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage162",
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage164",
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage165",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:11.1",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:11.4",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.4",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.5"
    ]);
    report
}
