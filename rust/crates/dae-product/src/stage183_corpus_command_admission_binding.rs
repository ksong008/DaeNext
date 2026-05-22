#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stage183CorpusCommandAdmissionBindingContract {
    pub name: &'static str,
    pub stage: &'static str,
    pub prior_gate: &'static str,
    pub stage_complete: bool,
    pub corpus_command_admission_binding_available: bool,
    pub stage178_reviewed_artifact_carried: bool,
    pub stage179_verifier_carried: bool,
    pub stage182_preflight_carried: bool,
    pub go_rust_command_templates_bound: bool,
    pub explicit_temp_root_required: bool,
    pub admission_bundle_written: bool,
    pub benchmark_executable_now: bool,
    pub matched_go_rust_default_daemon_benchmark_recorded: bool,
    pub default_switch_allowed: bool,
    pub reviewed_corpus_digest: &'static str,
    pub reviewed_outbound_matrix_digest: &'static str,
    pub bundle_files: Vec<&'static str>,
    pub closed_gates: Vec<Stage183ClosedGate>,
    pub command_templates: Vec<Stage183CommandTemplate>,
    pub validation_commands: Vec<&'static str>,
    pub source: Vec<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stage183ClosedGate {
    pub gate: &'static str,
    pub status: &'static str,
    pub opens_after: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stage183CommandTemplate {
    pub owner: &'static str,
    pub entrypoint: &'static str,
    pub executes_now: bool,
}

pub fn stage183_corpus_command_admission_binding_contract()
-> Stage183CorpusCommandAdmissionBindingContract {
    Stage183CorpusCommandAdmissionBindingContract {
        name: "stage183-corpus-command-admission-binding-dry-run",
        stage: "stage183",
        prior_gate: "stage182-production-rust-daemon-admission-preflight",
        stage_complete: true,
        corpus_command_admission_binding_available: true,
        stage178_reviewed_artifact_carried: true,
        stage179_verifier_carried: true,
        stage182_preflight_carried: true,
        go_rust_command_templates_bound: true,
        explicit_temp_root_required: true,
        admission_bundle_written: true,
        benchmark_executable_now: false,
        matched_go_rust_default_daemon_benchmark_recorded: false,
        default_switch_allowed: false,
        reviewed_corpus_digest: "11f6ff3348cf01a2c2482d9676ca9692f2730c427b37e647a96cbc6be4142e19",
        reviewed_outbound_matrix_digest: "2c2cfd8063500e7539be6cbc22c65207dae0d692eb68a0a5938dcb0cb82211ce",
        bundle_files: vec![
            "manifest.json",
            "corpus/reviewed-corpus-binding.json",
            "commands/go-default-command-template.json",
            "commands/rust-optin-command-template.json",
            "shared/gate-summary.json",
            "next/stage184-daemon-smoke-input.json",
        ],
        closed_gates: vec![
            Stage183ClosedGate {
                gate: "corpus_gate",
                status: "prepared_for_daemon_smoke",
                opens_after: "Stage184 consumes explicit Stage183 bundle and proves same-corpus daemon execution",
            },
            Stage183ClosedGate {
                gate: "rust_production_command_gate",
                status: "closed",
                opens_after: "production-shaped Rust dae run command identity is proven beyond Stage156 opt-in",
            },
            Stage183ClosedGate {
                gate: "daemon_execution_gate",
                status: "closed",
                opens_after: "Go default daemon and Rust opt-in daemon execute on the same reviewed corpus",
            },
            Stage183ClosedGate {
                gate: "production_dataplane_gate",
                status: "closed",
                opens_after: "listener bind, tc attach, listen_socket_map, and eBPF evidence pass",
            },
            Stage183ClosedGate {
                gate: "matched_benchmark_gate",
                status: "closed",
                opens_after: "benchmark readiness admission confirms Stage184-186 evidence",
            },
            Stage183ClosedGate {
                gate: "default_product_switch_gate",
                status: "closed",
                opens_after: "matched benchmark results and default/product recertification pass",
            },
        ],
        command_templates: vec![
            Stage183CommandTemplate {
                owner: "go-default-daemon",
                entrypoint: "dae run",
                executes_now: false,
            },
            Stage183CommandTemplate {
                owner: "rust-optin-daemon",
                entrypoint: "dae-daemon-optin stage156-default-run-identity-admission",
                executes_now: false,
            },
        ],
        validation_commands: vec![
            "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage183/corpus_command_admission_binding_dry_run.json",
            "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage183_corpus_command_admission_binding_dry_run.json",
            "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage183-corpus-command-admission-binding-dry-run",
            "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage183-corpus-command-admission-binding-dry-run --write-admission-dry-run --root /tmp/dae-stage183-corpus-command-admission-dry-run",
            "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage183 -- --nocapture",
            "cargo test --manifest-path rust/Cargo.toml -p dae-product stage183 -- --nocapture",
            "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage182 -- --nocapture",
            "cargo test --manifest-path rust/Cargo.toml -p dae-cli -p dae-product -q",
            "cargo fmt --manifest-path rust/Cargo.toml --all -- --check",
            "git diff --check",
        ],
        source: vec![
            "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage183",
            "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage182",
            "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage179",
            "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage178",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.3",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.4",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.5",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.8",
        ],
    }
}
