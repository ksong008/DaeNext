#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stage148DaemonIdentityPreflightGateContract {
    pub name: &'static str,
    pub stage: &'static str,
    pub prior_gate: &'static str,
    pub stage_complete: bool,
    pub rust_daemon_identity_preflight_recorded: bool,
    pub go_default_daemon_identity_preserved: bool,
    pub cli_optin_helper_identity_recorded: bool,
    pub rust_daemon_crate_manifest_exists: bool,
    pub rust_default_run_entrypoint_exists: bool,
    pub rust_default_control_plane_entrypoint_admitted: bool,
    pub true_rust_daemon_binary_exists: bool,
    pub benchmark_executable_now: bool,
    pub matched_go_rust_default_daemon_benchmark_recorded: bool,
    pub true_rust_default_daemon_admitted: bool,
    pub default_switch_allowed: bool,
    pub product_chain_switch_allowed: bool,
    pub go_default_path_preserved: bool,
    pub go_fallback_required: bool,
    pub gate_decision: &'static str,
    pub rows: Vec<Stage148DaemonIdentityPreflightGateRow>,
    pub next_admission_queue: Vec<Stage148DaemonIdentityAdmissionQueueRow>,
    pub validation_commands: Vec<&'static str>,
    pub remaining_blockers: Vec<&'static str>,
    pub source: Vec<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stage148DaemonIdentityPreflightGateRow {
    pub area: &'static str,
    pub status: &'static str,
    pub evidence: &'static str,
    pub boundary: &'static str,
    pub next_action: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stage148DaemonIdentityAdmissionQueueRow {
    pub stage: &'static str,
    pub target: &'static str,
    pub required_output: &'static str,
}

pub fn stage148_daemon_identity_preflight_gate_contract()
-> Stage148DaemonIdentityPreflightGateContract {
    Stage148DaemonIdentityPreflightGateContract {
        name: "stage148-rust-daemon-identity-preflight-gate",
        stage: "stage148",
        prior_gate: "stage147-matched-default-daemon-benchmark-readiness-gate",
        stage_complete: true,
        rust_daemon_identity_preflight_recorded: true,
        go_default_daemon_identity_preserved: true,
        cli_optin_helper_identity_recorded: true,
        rust_daemon_crate_manifest_exists: false,
        rust_default_run_entrypoint_exists: false,
        rust_default_control_plane_entrypoint_admitted: false,
        true_rust_daemon_binary_exists: false,
        benchmark_executable_now: false,
        matched_go_rust_default_daemon_benchmark_recorded: false,
        true_rust_default_daemon_admitted: false,
        default_switch_allowed: false,
        product_chain_switch_allowed: false,
        go_default_path_preserved: true,
        go_fallback_required: true,
        gate_decision: "stage148 records Rust default daemon identity preflight only: Go dae run remains the preserved default, dae-cli-optin remains helper evidence, rust/crates/dae-daemon is absent, and benchmark/default/product admission stay closed",
        rows: vec![
            Stage148DaemonIdentityPreflightGateRow {
                area: "Go default daemon identity",
                status: "preserved",
                evidence: "Go dae run remains the default daemon identity and keeps pid/progress/sdnotify/reload semantics as the product-facing path",
                boundary: "preserving Go default is not Rust default admission",
                next_action: "keep Go fallback and default path untouched while Rust identity is introduced",
            },
            Stage148DaemonIdentityPreflightGateRow {
                area: "Rust helper identity",
                status: "recorded-helper-only",
                evidence: "dae-cli-optin carries staged runtime gates and protocol evidence",
                boundary: "helper evidence cannot be treated as a daemon binary or run entrypoint",
                next_action: "continue using helper only for opt-in gates",
            },
            Stage148DaemonIdentityPreflightGateRow {
                area: "Rust default daemon identity",
                status: "blocked-absent",
                evidence: "rust/crates/dae-daemon/Cargo.toml and a Rust run entrypoint are not present",
                boundary: "without daemon identity, matched default-daemon benchmark cannot execute",
                next_action: "add or detect a real Rust daemon crate without wiring it as default",
            },
            Stage148DaemonIdentityPreflightGateRow {
                area: "benchmark/default/product",
                status: "closed",
                evidence: "Stage147 benchmark plan exists but remains non-executable",
                boundary: "default_switch_allowed and product_chain_switch_allowed remain false",
                next_action: "run lifecycle smoke first, then matched benchmark",
            },
        ],
        next_admission_queue: vec![
            Stage148DaemonIdentityAdmissionQueueRow {
                stage: "stage149",
                target: "real Rust daemon crate scaffolding or detection",
                required_output: "add or detect Rust daemon binary identity without wiring it as default",
            },
            Stage148DaemonIdentityAdmissionQueueRow {
                stage: "stage150",
                target: "Rust daemon lifecycle smoke",
                required_output: "prove pid/progress/sdnotify/reload/suspend semantics under opt-in test paths",
            },
            Stage148DaemonIdentityAdmissionQueueRow {
                stage: "stage151",
                target: "matched default daemon benchmark execution",
                required_output: "execute Go and Rust daemon identities on the same corpus only after lifecycle preflight passes",
            },
        ],
        validation_commands: vec![
            "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage148/rust_daemon_identity_preflight_gate.json",
            "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage148_rust_daemon_identity_preflight_gate.json",
            "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage148-rust-daemon-identity-preflight-gate",
            "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage148 -- --nocapture",
            "cargo test --manifest-path rust/Cargo.toml -p dae-product stage148 -- --nocapture",
            "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage147 -- --nocapture",
            "cargo test --manifest-path rust/Cargo.toml -p dae-outbound -p dae-cli -p dae-product -q",
            "cargo fmt --manifest-path rust/Cargo.toml --all -- --check",
            "git diff --check",
        ],
        remaining_blockers: vec![
            "Rust default daemon crate and binary are absent",
            "Rust default daemon run entrypoint and control-plane ownership are not admitted",
            "matched benchmark cannot execute without a Rust daemon identity",
            "default daemon and product-chain switches remain closed",
        ],
        source: vec![
            "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage148",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.1",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.8",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:30.1",
            "rust/crates/dae-product/src/true_daemon_admission.rs",
            "testdata/rebuild-golden/engine/runtime_stage147/matched_default_daemon_benchmark_readiness_gate.json",
        ],
    }
}
