#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stage149DaemonIdentityScaffoldGateContract {
    pub name: &'static str,
    pub stage: &'static str,
    pub prior_gate: &'static str,
    pub stage_complete: bool,
    pub rust_daemon_identity_scaffolded: bool,
    pub rust_daemon_crate_manifest_exists: bool,
    pub rust_daemon_optin_binary_exists: bool,
    pub rust_daemon_identity_command_available: bool,
    pub rust_default_run_entrypoint_exists: bool,
    pub rust_default_control_plane_entrypoint_admitted: bool,
    pub rust_daemon_lifecycle_smoke_passed: bool,
    pub benchmark_executable_now: bool,
    pub matched_go_rust_default_daemon_benchmark_recorded: bool,
    pub true_rust_default_daemon_admitted: bool,
    pub default_switch_allowed: bool,
    pub product_chain_switch_allowed: bool,
    pub go_default_path_preserved: bool,
    pub go_fallback_required: bool,
    pub gate_decision: &'static str,
    pub rows: Vec<Stage149DaemonIdentityScaffoldGateRow>,
    pub next_admission_queue: Vec<Stage149DaemonIdentityAdmissionQueueRow>,
    pub validation_commands: Vec<&'static str>,
    pub remaining_blockers: Vec<&'static str>,
    pub source: Vec<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stage149DaemonIdentityScaffoldGateRow {
    pub area: &'static str,
    pub status: &'static str,
    pub evidence: &'static str,
    pub boundary: &'static str,
    pub next_action: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stage149DaemonIdentityAdmissionQueueRow {
    pub stage: &'static str,
    pub target: &'static str,
    pub required_output: &'static str,
}

pub fn stage149_daemon_identity_scaffold_gate_contract()
-> Stage149DaemonIdentityScaffoldGateContract {
    Stage149DaemonIdentityScaffoldGateContract {
        name: "stage149-rust-daemon-identity-scaffold-gate",
        stage: "stage149",
        prior_gate: "stage148-rust-daemon-identity-preflight-gate",
        stage_complete: true,
        rust_daemon_identity_scaffolded: true,
        rust_daemon_crate_manifest_exists: true,
        rust_daemon_optin_binary_exists: true,
        rust_daemon_identity_command_available: true,
        rust_default_run_entrypoint_exists: false,
        rust_default_control_plane_entrypoint_admitted: false,
        rust_daemon_lifecycle_smoke_passed: false,
        benchmark_executable_now: false,
        matched_go_rust_default_daemon_benchmark_recorded: false,
        true_rust_default_daemon_admitted: false,
        default_switch_allowed: false,
        product_chain_switch_allowed: false,
        go_default_path_preserved: true,
        go_fallback_required: true,
        gate_decision: "stage149 scaffolds a real but non-default Rust daemon identity: rust/crates/dae-daemon and dae-daemon-optin now exist and expose identity/preflight commands, while Go dae run remains the default and lifecycle, matched benchmark, default switch, and product switch stay closed",
        rows: vec![
            Stage149DaemonIdentityScaffoldGateRow {
                area: "Rust daemon crate",
                status: "present-opt-in-only",
                evidence: "rust/crates/dae-daemon/Cargo.toml is a workspace member and lib.rs is split into identity, preflight, runner, and version modules",
                boundary: "crate presence does not start or admit a production daemon",
                next_action: "add lifecycle smoke under temporary pid/progress paths",
            },
            Stage149DaemonIdentityScaffoldGateRow {
                area: "Rust daemon binary",
                status: "present-opt-in-only",
                evidence: "dae-daemon-optin exposes identity and stage149-identity-preflight commands",
                boundary: "the opt-in binary is not dae run and is not installed as the default service",
                next_action: "prove controlled startup semantics before any benchmark",
            },
            Stage149DaemonIdentityScaffoldGateRow {
                area: "Go default identity",
                status: "preserved",
                evidence: "Go dae run remains the product-facing default daemon path",
                boundary: "default_path_mutation_allowed remains false",
                next_action: "keep Go fallback available through lifecycle and benchmark stages",
            },
            Stage149DaemonIdentityScaffoldGateRow {
                area: "benchmark/default/product",
                status: "closed",
                evidence: "daemon identity exists, but lifecycle smoke and matched benchmark are still missing",
                boundary: "identity scaffolding is not benchmark evidence or product admission",
                next_action: "run Stage150 lifecycle smoke before Stage151 matched benchmark",
            },
        ],
        next_admission_queue: vec![
            Stage149DaemonIdentityAdmissionQueueRow {
                stage: "stage150",
                target: "Rust daemon lifecycle smoke under opt-in test paths",
                required_output: "prove pid/progress/sdnotify/reload/suspend semantics without mutating Go default",
            },
            Stage149DaemonIdentityAdmissionQueueRow {
                stage: "stage151",
                target: "matched default daemon benchmark execution",
                required_output: "run Go and Rust daemon identities on the same corpus after lifecycle smoke passes",
            },
            Stage149DaemonIdentityAdmissionQueueRow {
                stage: "stage152",
                target: "product-chain benchmark carry-forward",
                required_output: "carry benchmark evidence into dae-wing/daed only after real matched data exists",
            },
        ],
        validation_commands: vec![
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
            "git diff --check",
        ],
        remaining_blockers: vec![
            "Rust daemon lifecycle smoke has not started a daemon under temporary pid/progress paths",
            "Rust default run entrypoint and control-plane ownership are not admitted",
            "matched benchmark cannot execute until lifecycle smoke passes",
            "default daemon and product-chain switches remain closed",
        ],
        source: vec![
            "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage149",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.1",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.8",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:30.1",
            "rust/crates/dae-daemon/Cargo.toml",
            "rust/crates/dae-daemon/src/lib.rs",
            "rust/crates/dae-daemon/src/bin/dae-daemon-optin.rs",
        ],
    }
}
