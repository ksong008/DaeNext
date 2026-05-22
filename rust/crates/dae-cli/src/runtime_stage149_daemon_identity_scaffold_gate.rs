use serde_json::{Value, json};

use crate::runner::RunnerOutput;

pub(crate) fn run_stage149_daemon_identity_scaffold_gate(args: &[String]) -> RunnerOutput {
    if let Some(arg) = args.first() {
        return RunnerOutput::usage(format!("unsupported stage149 argument: {arg}"));
    }
    RunnerOutput::ok(format!("{}\n", stage149_report()))
}

fn stage149_report() -> Value {
    let mut report = json!({
        "name": "stage149-rust-daemon-identity-scaffold-gate",
        "stage": "stage149",
        "evidence_class": "read-only-rust-daemon-identity-scaffold-gate",
        "execute_smoke": false,
        "read_only": true,
        "blocked": false,
        "blockers": []
    });
    for key in [
        "rust_daemon_identity_scaffolded",
        "rust_daemon_crate_manifest_exists",
        "rust_daemon_optin_binary_exists",
        "rust_daemon_identity_command_available",
        "go_default_daemon_identity_preserved",
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
        "rust_default_run_entrypoint_exists",
        "rust_default_control_plane_entrypoint_admitted",
        "rust_daemon_lifecycle_smoke_passed",
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
            "preserved": true,
            "default_path_mutation_allowed": false
        },
        "rust_daemon_crate": {
            "crate": "dae-daemon",
            "manifest": "rust/crates/dae-daemon/Cargo.toml",
            "manifest_exists": true,
            "lib_split_by_feature": true
        },
        "rust_optin_binary": {
            "binary": "dae-daemon-optin",
            "command": "cargo run --manifest-path rust/Cargo.toml -p dae-daemon --bin dae-daemon-optin -- identity",
            "identity_command_available": true,
            "counts_as_default_daemon": false
        }
    });
    report["crate_modules"] = json!(["identity", "preflight", "runner", "version"]);
    report["remaining_blockers"] = json!([
        "Rust daemon lifecycle smoke has not started a daemon under temporary pid/progress paths",
        "Rust default run entrypoint and control-plane ownership are not admitted",
        "matched benchmark cannot execute until lifecycle smoke passes",
        "default daemon and product-chain switches remain closed"
    ]);
    report["next_admission_queue"] = json!([
        {
            "stage": "stage150",
            "target": "Rust daemon lifecycle smoke under opt-in test paths",
            "required_output": "prove pid/progress/sdnotify/reload/suspend semantics without mutating Go default"
        },
        {
            "stage": "stage151",
            "target": "matched default daemon benchmark execution",
            "required_output": "run Go and Rust daemon identities on the same corpus after lifecycle smoke passes"
        },
        {
            "stage": "stage152",
            "target": "product-chain benchmark carry-forward",
            "required_output": "carry benchmark evidence into dae-wing/daed only after real matched data exists"
        }
    ]);
    report["validation_commands"] = json!([
        "cargo run --manifest-path rust/Cargo.toml -p dae-daemon --bin dae-daemon-optin -- identity",
        "cargo test --manifest-path rust/Cargo.toml -p dae-daemon -- --nocapture",
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage149/rust_daemon_identity_scaffold_gate.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage149_rust_daemon_identity_scaffold_gate.json",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage149-rust-daemon-identity-scaffold-gate",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage149 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage149 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage148 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-daemon -p dae-cli -p dae-product -q",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound -p dae-cli -p dae-product -q",
        "cargo fmt --manifest-path rust/Cargo.toml --all -- --check",
        "git diff --check"
    ]);
    report["source"] = json!([
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage149",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.1",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.8",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:30.1",
        "rust/crates/dae-daemon/Cargo.toml",
        "rust/crates/dae-daemon/src/lib.rs",
        "rust/crates/dae-daemon/src/bin/dae-daemon-optin.rs"
    ]);
    report
}
