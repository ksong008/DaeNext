use serde_json::{Value, json};

use crate::runner::RunnerOutput;

pub(crate) fn run_stage154_benchmark_readiness_refresh_gate(args: &[String]) -> RunnerOutput {
    if let Some(arg) = args.first() {
        return RunnerOutput::usage(format!("unsupported stage154 argument: {arg}"));
    }
    RunnerOutput::ok(format!("{}\n", stage154_report()))
}

fn stage154_report() -> Value {
    let mut report = json!({
        "name": "stage154-matched-default-daemon-benchmark-readiness-refresh-gate",
        "stage": "stage154",
        "evidence_class": "read-only-matched-default-daemon-benchmark-readiness-refresh-gate",
        "execute_smoke": false,
        "read_only": true,
        "blocked": true,
        "blockers": [
            "Stage153 provides a non-default wrapper only, not a Rust default run entrypoint",
            "Rust default control-plane entrypoint is not admitted",
            "production listener binding and eBPF attach remain closed",
            "matched Go default daemon vs true Rust default daemon benchmark has not been executed"
        ]
    });
    for key in [
        "matched_default_daemon_benchmark_plan_recorded",
        "benchmark_corpus_manifest_recorded",
        "benchmark_blocker_queue_recorded",
        "stage153_non_default_wrapper_recorded",
        "run_entrypoint_lifecycle_smoke_reused",
        "run_entrypoint_signal_control_plane_smoke_reused",
        "run_entrypoint_on_ready_contract_recorded",
        "run_entrypoint_flag_contract_recorded",
        "go_default_path_preserved",
        "go_fallback_required",
    ] {
        report[key] = json!(true);
    }
    for key in [
        "benchmark_executable_now",
        "rust_default_run_entrypoint_exists",
        "rust_default_control_plane_entrypoint_admitted",
        "production_listener_bound",
        "ebpf_attached",
        "matched_go_rust_default_daemon_benchmark_recorded",
        "true_rust_default_daemon_admitted",
        "default_switch_allowed",
        "default_path_mutation_allowed",
        "product_chain_switch_allowed",
    ] {
        report[key] = json!(false);
    }
    report["readiness_delta_from_stage147"] = json!({
        "rust_daemon_identity_scaffolded": true,
        "optin_lifecycle_smoke_passed": true,
        "control_plane_owner_preflight_recorded": true,
        "signal_control_plane_smoke_passed": true,
        "non_default_run_entrypoint_wrapper_recorded": true,
        "default_daemon_identity_available": false,
        "benchmark_executable_now": false,
        "decision": "Stage153 improves benchmark preconditions but does not satisfy matched default-daemon execution identity"
    });
    report["benchmark_manifest"] = json!({
        "go_default_daemon": {
            "build_command": "PATH=/root/.local/go1.25.9/bin:$PATH GOWORK=off make dae",
            "run_identity": "dae run --config <benchmark-config>",
            "required": true
        },
        "rust_default_daemon": {
            "build_command": "cargo build --manifest-path rust/Cargo.toml -p dae-daemon --bin dae-daemon-optin",
            "run_identity": "dae-daemon-optin stage153-run-entrypoint-preflight --root <tmp>",
            "required_identity": "future Rust default daemon run --config <benchmark-config>",
            "available_now": false,
            "reason": "current Rust identity is an opt-in wrapper preflight, not a default daemon run command"
        },
        "traffic_corpus": [
            "TCP proxy latency and throughput",
            "UDP proxy latency, loss, and throughput",
            "DNS UDP/53 latency, cache hit, and cache migration behavior",
            "reload success, invalid-config rollback, and post-reload resource cleanup",
            "admitted outbound protocol matrix",
            "RuntimeOverview, RSS, CPU, startup time, and reload time"
        ],
        "artifact_requirements": [
            "raw command logs",
            "config corpus",
            "host and kernel metadata",
            "Go daemon version/build metadata",
            "Rust daemon version/build metadata",
            "rollback result"
        ]
    });
    report["remaining_blockers"] = json!([
        "Rust default run entrypoint is still absent; Stage153 is opt-in wrapper evidence only",
        "Rust default control-plane entrypoint is not admitted",
        "production listener binding and eBPF attach remain closed",
        "matched benchmark cannot run until Go and Rust default daemon identities execute the same config corpus on the same host",
        "default daemon and product-chain switches remain closed"
    ]);
    report["next_admission_queue"] = json!([
        {
            "stage": "stage155",
            "target": "product-chain default switch final blocker review",
            "required_output": "carry benchmark blocker and enumerate product-chain blockers without enabling switch"
        },
        {
            "stage": "stage156",
            "target": "Rust default run identity admission",
            "required_output": "only after explicit approval, add a real Rust default run identity that can execute config corpus without replacing Go default path"
        }
    ]);
    report["validation_commands"] = json!([
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage154/matched_default_daemon_benchmark_readiness_refresh_gate.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage154_matched_default_daemon_benchmark_readiness_refresh_gate.json",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage154-matched-default-daemon-benchmark-readiness-refresh-gate",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage154 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage154 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage153 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound -p dae-cli -p dae-product -q",
        "cargo fmt --manifest-path rust/Cargo.toml --all -- --check",
        "git diff --check"
    ]);
    report["source"] = json!([
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage154",
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage147",
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage153",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.1",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.4",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.8",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:30.4"
    ]);
    report
}
