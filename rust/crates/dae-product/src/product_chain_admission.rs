#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductChainAdmissionContract {
    pub name: &'static str,
    pub stage: &'static str,
    pub prior_gate: &'static str,
    pub queue_complete: bool,
    pub product_chain_switch_allowed: bool,
    pub default_switch_allowed: bool,
    pub go_default_path_preserved: bool,
    pub go_fallback_required: bool,
    pub daemon_live_evidence_complete: bool,
    pub true_rust_default_daemon_admitted: bool,
    pub admission_decision: &'static str,
    pub admission_rows: Vec<ProductChainAdmissionRow>,
    pub rollback_controls: Vec<&'static str>,
    pub validation_commands: Vec<&'static str>,
    pub source: Vec<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductChainAdmissionRow {
    pub area: &'static str,
    pub status: &'static str,
    pub required_evidence: &'static str,
    pub blocker: &'static str,
    pub next_action: &'static str,
}

pub fn product_chain_admission_contract() -> ProductChainAdmissionContract {
    ProductChainAdmissionContract {
        name: "stage23-product-chain-admission",
        stage: "stage23",
        prior_gate: "stage22-daemon-live-evidence-queue",
        queue_complete: true,
        product_chain_switch_allowed: false,
        default_switch_allowed: false,
        go_default_path_preserved: true,
        go_fallback_required: true,
        daemon_live_evidence_complete: true,
        true_rust_default_daemon_admitted: false,
        admission_decision: "establish product-chain admission queue only; do not switch install, release, dae-wing, or daed to a Rust default daemon until true Rust default daemon parity is proven",
        admission_rows: vec![
            ProductChainAdmissionRow {
                area: "daemon default identity",
                status: "blocked-before-true-rust-default",
                required_evidence: "matched Go default daemon vs true Rust default daemon live traffic, reload rollback, RSS/CPU/latency benchmark, and rollback smoke",
                blocker: "stage22 benchmark is no-daemon baseline vs opt-in active-proxy path, not a Go-vs-Rust default daemon benchmark",
                next_action: "define a separate true Rust default daemon admission gate before mutating dae run defaults",
            },
            ProductChainAdmissionRow {
                area: "install and systemd",
                status: "keep-go-backed-default",
                required_evidence: "install/dae.service keeps validate ExecStartPre, dae run ExecStart, reload $MAINPID, Type=notify, and package hooks",
                blocker: "installed service must not use Rust-only ExecStart until default daemon gate is reopened",
                next_action: "run isolated package install/reload/remove smoke without changing the host service",
            },
            ProductChainAdmissionRow {
                area: "release workflow and packages",
                status: "keep-go-backed-artifacts",
                required_evidence: "release workflow tag gate, package output layout, friendly filenames, and deb/rpm/pacman assets keep Go fallback semantics",
                blocker: "release artifacts must not imply Rust default daemon readiness",
                next_action: "run workflow/package dry smoke after true daemon gate defines artifact identity",
            },
            ProductChainAdmissionRow {
                area: "dae-wing and daed API chain",
                status: "deferred-cross-repo-validation",
                required_evidence: "RuntimeOverview fields, reload progress bytes, validate/export, route-aware HTTP transport, latency snapshots, and DNS observability are validated in dae-wing and daed repos",
                blocker: "dae local contracts exist, but downstream repos have not been validated against the stage22 live evidence boundary",
                next_action: "audit /root/project/dae-wing and /root/project/daed surfaces before any cross-repo default switch",
            },
            ProductChainAdmissionRow {
                area: "trace and sysdump diagnostics",
                status: "contract-ready-not-default-replacement",
                required_evidence: "trace build-tag CLI surface, ringbuf parser, bounded tracker, sysdump best-effort collector, tar path safety, and archive enum fixtures",
                blocker: "diagnostic contracts do not prove daemon default readiness",
                next_action: "run trace/sysdump smoke separately from daemon default switching",
            },
            ProductChainAdmissionRow {
                area: "rollback and fallback",
                status: "required-for-every-product-step",
                required_evidence: "Go daemon path, installed service rollback, release artifact rollback, and cross-repo config rollback stay documented and tested",
                blocker: "product chain must never mask daemon parity gaps",
                next_action: "carry go_fallback_required=true until all product-chain rows pass live validation",
            },
        ],
        rollback_controls: vec![
            "do not mutate installed systemd ExecStart to Rust-only mode",
            "do not mark release artifacts as Rust-default-daemon-ready",
            "do not update dae-wing or daed defaults from dae-local evidence alone",
            "keep Go daemon and Go outbound fallback available",
            "require isolated package smoke before install/release changes",
            "record every cross-repo validation result in the local plan before product rollout",
        ],
        validation_commands: vec![
            "cargo test --manifest-path rust/Cargo.toml -p dae-product product_chain_admission_contract_matches_golden_fixture -- --nocapture",
            "cargo fmt --manifest-path rust/Cargo.toml --all -- --check",
            "cargo test --manifest-path rust/Cargo.toml -p dae-product",
            "git diff --check",
        ],
        source: vec![
            "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage23",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:33.8",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:33.9",
            "rust/crates/dae-product/src/daemon_live_evidence.rs",
            "rust/crates/dae-product/src/systemd.rs",
            "rust/crates/dae-product/src/release.rs",
            "rust/crates/dae-product/src/integration.rs",
        ],
    }
}
