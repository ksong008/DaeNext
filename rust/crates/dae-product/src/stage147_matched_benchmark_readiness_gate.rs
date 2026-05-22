#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stage147MatchedBenchmarkReadinessGateContract {
    pub name: &'static str,
    pub stage: &'static str,
    pub prior_gate: &'static str,
    pub stage_complete: bool,
    pub matched_default_daemon_benchmark_plan_recorded: bool,
    pub benchmark_corpus_manifest_recorded: bool,
    pub benchmark_blocker_queue_recorded: bool,
    pub benchmark_executable_now: bool,
    pub true_rust_daemon_binary_exists: bool,
    pub rust_default_control_plane_entrypoint_admitted: bool,
    pub matched_go_rust_default_daemon_benchmark_recorded: bool,
    pub shared_transport_fallback_aware_recertified: bool,
    pub outbound_fallback_aware_recertified: bool,
    pub fallback_dependency_policy_recorded: bool,
    pub shared_transport_true_dataplane_admitted: bool,
    pub outbound_true_dataplane_admitted: bool,
    pub true_rust_default_daemon_admitted: bool,
    pub default_switch_allowed: bool,
    pub product_chain_switch_allowed: bool,
    pub go_default_path_preserved: bool,
    pub go_fallback_required: bool,
    pub gate_decision: &'static str,
    pub benchmark_manifest: Vec<Stage147BenchmarkManifestRow>,
    pub next_admission_queue: Vec<Stage147BenchmarkAdmissionQueueRow>,
    pub validation_commands: Vec<&'static str>,
    pub remaining_blockers: Vec<&'static str>,
    pub source: Vec<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stage147BenchmarkManifestRow {
    pub area: &'static str,
    pub status: &'static str,
    pub required_evidence: &'static str,
    pub blocker: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stage147BenchmarkAdmissionQueueRow {
    pub stage: &'static str,
    pub target: &'static str,
    pub required_output: &'static str,
}

pub fn stage147_matched_benchmark_readiness_gate_contract()
-> Stage147MatchedBenchmarkReadinessGateContract {
    Stage147MatchedBenchmarkReadinessGateContract {
        name: "stage147-matched-default-daemon-benchmark-readiness-gate",
        stage: "stage147",
        prior_gate: "stage146-shared-transport-outbound-fallback-aware-recertification-gate",
        stage_complete: true,
        matched_default_daemon_benchmark_plan_recorded: true,
        benchmark_corpus_manifest_recorded: true,
        benchmark_blocker_queue_recorded: true,
        benchmark_executable_now: false,
        true_rust_daemon_binary_exists: false,
        rust_default_control_plane_entrypoint_admitted: false,
        matched_go_rust_default_daemon_benchmark_recorded: false,
        shared_transport_fallback_aware_recertified: true,
        outbound_fallback_aware_recertified: true,
        fallback_dependency_policy_recorded: true,
        shared_transport_true_dataplane_admitted: false,
        outbound_true_dataplane_admitted: false,
        true_rust_default_daemon_admitted: false,
        default_switch_allowed: false,
        product_chain_switch_allowed: false,
        go_default_path_preserved: true,
        go_fallback_required: true,
        gate_decision: "stage147 records the matched default-daemon benchmark contract and blocker queue only: the fair benchmark requires a Go default daemon and a Rust-owned default daemon to run the same config corpus on the same host, but the Rust default daemon binary and entrypoint do not exist yet; default/product switches stay closed",
        benchmark_manifest: vec![
            Stage147BenchmarkManifestRow {
                area: "daemon identity",
                status: "blocked",
                required_evidence: "Go default daemon binary and Rust-owned default daemon binary both expose run identity, version metadata, pid/progress behavior, and rollback controls",
                blocker: "current Rust workspace exposes dae-cli-optin helper evidence, not a Rust-owned default daemon binary",
            },
            Stage147BenchmarkManifestRow {
                area: "traffic corpus",
                status: "recorded",
                required_evidence: "TCP, UDP, DNS UDP/53, reload rollback, admitted outbound protocols, RuntimeOverview, RSS, CPU, startup time, and reload time use the same config corpus",
                blocker: "corpus can be planned now, but cannot be executed as matched daemon benchmark until Rust daemon identity exists",
            },
            Stage147BenchmarkManifestRow {
                area: "measurement artifacts",
                status: "recorded",
                required_evidence: "raw logs, commands, config corpus, host/kernel metadata, Go/Rust build metadata, and rollback result are stored with benchmark output",
                blocker: "no benchmark data is recorded in Stage147",
            },
            Stage147BenchmarkManifestRow {
                area: "admission flags",
                status: "closed",
                required_evidence: "matched_go_rust_default_daemon_benchmark_recorded, true_rust_default_daemon_admitted, default_switch_allowed, and product_chain_switch_allowed stay false until real benchmark data exists",
                blocker: "read-only readiness cannot admit default/product switch",
            },
        ],
        next_admission_queue: vec![
            Stage147BenchmarkAdmissionQueueRow {
                stage: "stage148",
                target: "Rust daemon identity preflight",
                required_output: "define or detect a Rust-owned default daemon binary and run entrypoint without mutating Go default",
            },
            Stage147BenchmarkAdmissionQueueRow {
                stage: "stage149",
                target: "matched benchmark harness execution",
                required_output: "run Go default daemon and Rust daemon candidate on the same config corpus and record metrics",
            },
            Stage147BenchmarkAdmissionQueueRow {
                stage: "stage150",
                target: "product-chain benchmark carry-forward",
                required_output: "carry benchmark evidence into dae-wing/daed only after Stage149 records real data",
            },
        ],
        validation_commands: vec![
            "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage147/matched_default_daemon_benchmark_readiness_gate.json",
            "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage147_matched_default_daemon_benchmark_readiness_gate.json",
            "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage147-matched-default-daemon-benchmark-readiness-gate",
            "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage147 -- --nocapture",
            "cargo test --manifest-path rust/Cargo.toml -p dae-product stage147 -- --nocapture",
            "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage146 -- --nocapture",
            "cargo test --manifest-path rust/Cargo.toml -p dae-outbound -p dae-cli -p dae-product -q",
            "cargo fmt --manifest-path rust/Cargo.toml --all -- --check",
            "git diff --check",
        ],
        remaining_blockers: vec![
            "true Rust default daemon binary and run entrypoint are not available",
            "Rust default daemon has not proven startup, pid, progress, systemd notify, reload, rollback, and control-plane ownership",
            "matched benchmark cannot run until Go and Rust daemon identities can execute the same config corpus on the same host",
            "default daemon and product-chain switches remain closed",
        ],
        source: vec![
            "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage147",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.1",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.7",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.8",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:30.1",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:30.2",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:30.3",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:30.4",
            "rust/crates/dae-product/src/true_daemon_admission.rs",
            "testdata/rebuild-golden/engine/runtime_stage146/shared_transport_outbound_fallback_aware_recertification_gate.json",
        ],
    }
}
