use serde_json::{Value, json};

use crate::runner::RunnerOutput;

pub(crate) fn run_stage147_matched_benchmark_readiness_gate(args: &[String]) -> RunnerOutput {
    if let Some(arg) = args.first() {
        return RunnerOutput::usage(format!("unsupported stage147 argument: {arg}"));
    }
    RunnerOutput::ok(format!("{}\n", stage147_report()))
}

fn stage147_report() -> Value {
    let mut report = json!({
        "name": "stage147-matched-default-daemon-benchmark-readiness-gate",
        "stage": "stage147",
        "evidence_class": "read-only-matched-default-daemon-benchmark-readiness-gate",
        "execute_smoke": false,
        "read_only": true,
        "blocked": true,
        "blockers": [
            "true Rust default daemon binary does not exist in the current Rust workspace",
            "Rust-owned default control-plane entrypoint is not admitted",
            "fallback-aware Rust candidate is read-only/opt-in evidence, not a default daemon",
            "matched Go default daemon vs true Rust default daemon benchmark has not been executed"
        ]
    });
    for key in [
        "matched_default_daemon_benchmark_plan_recorded",
        "benchmark_corpus_manifest_recorded",
        "benchmark_blocker_queue_recorded",
        "shared_transport_fallback_aware_recertified",
        "outbound_fallback_aware_recertified",
        "fallback_dependency_policy_recorded",
        "external_outbound_required",
        "external_quic_go_required",
        "go_default_path_preserved",
        "go_fallback_required",
    ] {
        report[key] = json!(true);
    }
    for key in [
        "benchmark_executable_now",
        "true_rust_daemon_binary_exists",
        "rust_default_control_plane_entrypoint_admitted",
        "matched_go_rust_default_daemon_benchmark_recorded",
        "shared_transport_true_dataplane_admitted",
        "outbound_true_dataplane_admitted",
        "true_rust_default_daemon_admitted",
        "default_switch_allowed",
        "default_path_mutation_allowed",
        "product_chain_switch_allowed",
    ] {
        report[key] = json!(false);
    }
    report["benchmark_manifest"] = json!({
        "go_default_daemon": {
            "build_command": "PATH=/root/.local/go1.25.9/bin:$PATH GOWORK=off make dae",
            "run_identity": "dae run --config <benchmark-config>",
            "required": true
        },
        "rust_default_daemon": {
            "build_command": "cargo build --manifest-path rust/Cargo.toml -p <future-rust-daemon-crate>",
            "run_identity": "<future-rust-daemon> run --config <benchmark-config>",
            "required": true,
            "available_now": false
        },
        "traffic_corpus": [
            "TCP proxy latency and throughput",
            "UDP proxy latency, loss, and throughput",
            "DNS UDP/53 latency, cache hit, and cache migration behavior",
            "reload success, invalid-config rollback, and post-reload resource cleanup",
            "admitted outbound protocol matrix with fallback-aware VLESS/VMess/Trojan-Go rows",
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
    report["current_benchmark_state"] = json!({
        "protocol_microbenchmarks_available": true,
        "fallback_aware_candidate_recorded": true,
        "matched_default_daemon_benchmark_available": false,
        "reason": "Stage147 records the fair benchmark contract, but the true Rust default daemon identity is absent"
    });
    report["remaining_blockers"] = json!([
        "true Rust default daemon binary and run entrypoint are not available",
        "Rust default daemon has not proven startup, pid, progress, systemd notify, reload, rollback, and control-plane ownership",
        "matched benchmark cannot run until Go and Rust daemon identities can execute the same config corpus on the same host",
        "default daemon and product-chain switches remain closed"
    ]);
    report["next_admission_queue"] = json!([
        {
            "stage": "stage148",
            "target": "Rust daemon identity preflight",
            "required_output": "define or detect a Rust-owned default daemon binary and run entrypoint without mutating Go default"
        },
        {
            "stage": "stage149",
            "target": "matched benchmark harness execution",
            "required_output": "run Go default daemon and Rust daemon candidate on the same config corpus and record metrics"
        },
        {
            "stage": "stage150",
            "target": "product-chain benchmark carry-forward",
            "required_output": "carry benchmark evidence into dae-wing/daed only after Stage149 records real data"
        }
    ]);
    report["validation_commands"] = json!([
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage147/matched_default_daemon_benchmark_readiness_gate.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage147_matched_default_daemon_benchmark_readiness_gate.json",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage147-matched-default-daemon-benchmark-readiness-gate",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage147 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage147 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage146 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound -p dae-cli -p dae-product -q",
        "cargo fmt --manifest-path rust/Cargo.toml --all -- --check",
        "git diff --check"
    ]);
    report["source"] = json!([
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage147",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.1",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.7",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.8",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:30.1",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:30.2",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:30.3",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:30.4",
        "rust/crates/dae-product/src/true_daemon_admission.rs",
        "testdata/rebuild-golden/engine/runtime_stage146/shared_transport_outbound_fallback_aware_recertification_gate.json"
    ]);
    report
}
