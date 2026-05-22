use serde_json::{Value, json};

use crate::runner::RunnerOutput;

pub(crate) fn run_stage148_daemon_identity_preflight_gate(args: &[String]) -> RunnerOutput {
    if let Some(arg) = args.first() {
        return RunnerOutput::usage(format!("unsupported stage148 argument: {arg}"));
    }
    RunnerOutput::ok(format!("{}\n", stage148_report()))
}

fn stage148_report() -> Value {
    let mut report = json!({
        "name": "stage148-rust-daemon-identity-preflight-gate",
        "stage": "stage148",
        "evidence_class": "read-only-rust-default-daemon-identity-preflight-gate",
        "execute_smoke": false,
        "read_only": true,
        "blocked": true,
        "blockers": [
            "rust/crates/dae-daemon/Cargo.toml is not present",
            "Rust default run entrypoint is not present",
            "dae-cli-optin is helper evidence and cannot be treated as the default daemon",
            "matched default-daemon benchmark remains non-executable"
        ]
    });
    for key in [
        "rust_daemon_identity_preflight_recorded",
        "go_default_daemon_identity_preserved",
        "cli_optin_helper_identity_recorded",
        "matched_default_daemon_benchmark_plan_recorded",
        "benchmark_corpus_manifest_recorded",
        "external_outbound_required",
        "external_quic_go_required",
        "go_default_path_preserved",
        "go_fallback_required",
    ] {
        report[key] = json!(true);
    }
    for key in [
        "rust_daemon_crate_manifest_exists",
        "rust_default_run_entrypoint_exists",
        "rust_default_control_plane_entrypoint_admitted",
        "true_rust_daemon_binary_exists",
        "benchmark_executable_now",
        "matched_go_rust_default_daemon_benchmark_recorded",
        "true_rust_default_daemon_admitted",
        "default_switch_allowed",
        "default_path_mutation_allowed",
        "product_chain_switch_allowed",
    ] {
        report[key] = json!(false);
    }
    report["identity_matrix"] = json!({
        "go_default_daemon": {
            "identity": "dae run",
            "source": "cmd/run.go",
            "preserved": true,
            "default_path_mutation_allowed": false
        },
        "rust_helper": {
            "identity": "dae-cli-optin",
            "source": "rust/crates/dae-cli/src/bin/dae-cli-optin.rs",
            "recorded": true,
            "counts_as_default_daemon": false
        },
        "rust_default_daemon": {
            "crate_manifest": "rust/crates/dae-daemon/Cargo.toml",
            "manifest_exists": false,
            "run_entrypoint_exists": false,
            "binary_exists": false,
            "admitted": false
        }
    });
    report["required_identity_contract"] = json!([
        "Rust daemon binary exposes run identity without replacing Go default",
        "Rust run entrypoint preserves config, logfile, pid/progress, sdnotify, pprof, signal, reload, and suspend semantics",
        "Rust control-plane owner is explicit and rollback-safe",
        "Go fallback selector and service rollback stay available",
        "matched benchmark runs only after both daemon identities can execute the same config corpus"
    ]);
    report["remaining_blockers"] = json!([
        "Rust default daemon crate and binary are absent",
        "Rust default daemon run entrypoint and control-plane ownership are not admitted",
        "matched benchmark cannot execute without a Rust daemon identity",
        "default daemon and product-chain switches remain closed"
    ]);
    report["next_admission_queue"] = json!([
        {
            "stage": "stage149",
            "target": "real Rust daemon crate scaffolding or detection",
            "required_output": "add or detect Rust daemon binary identity without wiring it as default"
        },
        {
            "stage": "stage150",
            "target": "Rust daemon lifecycle smoke",
            "required_output": "prove pid/progress/sdnotify/reload/suspend semantics under opt-in test paths"
        },
        {
            "stage": "stage151",
            "target": "matched default daemon benchmark execution",
            "required_output": "execute Go and Rust daemon identities on the same corpus only after lifecycle preflight passes"
        }
    ]);
    report["validation_commands"] = json!([
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage148/rust_daemon_identity_preflight_gate.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage148_rust_daemon_identity_preflight_gate.json",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage148-rust-daemon-identity-preflight-gate",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage148 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage148 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage147 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound -p dae-cli -p dae-product -q",
        "cargo fmt --manifest-path rust/Cargo.toml --all -- --check",
        "git diff --check"
    ]);
    report["source"] = json!([
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage148",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.1",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.8",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:30.1",
        "rust/crates/dae-product/src/true_daemon_admission.rs",
        "testdata/rebuild-golden/engine/runtime_stage147/matched_default_daemon_benchmark_readiness_gate.json"
    ]);
    report
}
