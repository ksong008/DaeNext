#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stage169MatchedBenchmarkArtifactBuilderContract {
    pub name: &'static str,
    pub stage: &'static str,
    pub prior_gate: &'static str,
    pub stage_complete: bool,
    pub matched_benchmark_artifact_layout_materialized: bool,
    pub command_plan_recorded: bool,
    pub same_corpus_layout_recorded: bool,
    pub go_rust_artifact_symmetry_recorded: bool,
    pub stage167_bounded_summary_required: bool,
    pub host_metadata_required: bool,
    pub bpf_dns_runtime_artifacts_required: bool,
    pub go_default_path_preserved: bool,
    pub go_fallback_required: bool,
    pub artifact_files_written_to_runtime_dir: bool,
    pub go_default_daemon_executed: bool,
    pub rust_optin_daemon_executed: bool,
    pub production_listener_bound: bool,
    pub production_tc_attach_smoke_passed: bool,
    pub ebpf_attached: bool,
    pub benchmark_executable_now: bool,
    pub matched_go_rust_default_daemon_benchmark_recorded: bool,
    pub true_rust_default_daemon_admitted: bool,
    pub default_switch_allowed: bool,
    pub default_path_mutation_allowed: bool,
    pub product_chain_switch_allowed: bool,
    pub artifact_root_template: &'static str,
    pub gate_decision: &'static str,
    pub rows: Vec<Stage169MatchedBenchmarkArtifactBuilderRow>,
    pub artifact_layout: Vec<Stage169ArtifactLayoutRow>,
    pub command_plan: Vec<Stage169CommandPlanRow>,
    pub symmetry_requirements: Vec<&'static str>,
    pub validation_commands: Vec<&'static str>,
    pub remaining_blockers: Vec<&'static str>,
    pub source: Vec<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stage169MatchedBenchmarkArtifactBuilderRow {
    pub area: &'static str,
    pub status: &'static str,
    pub evidence: &'static str,
    pub blocker: &'static str,
    pub next_action: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stage169ArtifactLayoutRow {
    pub path: &'static str,
    pub owner: &'static str,
    pub required: bool,
    pub content: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stage169CommandPlanRow {
    pub name: &'static str,
    pub executes_now: bool,
    pub purpose: &'static str,
}

pub fn stage169_matched_benchmark_artifact_builder_contract()
-> Stage169MatchedBenchmarkArtifactBuilderContract {
    Stage169MatchedBenchmarkArtifactBuilderContract {
        name: "stage169-matched-benchmark-corpus-artifact-builder",
        stage: "stage169",
        prior_gate: "stage168-matched-default-daemon-benchmark-execution-gate",
        stage_complete: true,
        matched_benchmark_artifact_layout_materialized: true,
        command_plan_recorded: true,
        same_corpus_layout_recorded: true,
        go_rust_artifact_symmetry_recorded: true,
        stage167_bounded_summary_required: true,
        host_metadata_required: true,
        bpf_dns_runtime_artifacts_required: true,
        go_default_path_preserved: true,
        go_fallback_required: true,
        artifact_files_written_to_runtime_dir: false,
        go_default_daemon_executed: false,
        rust_optin_daemon_executed: false,
        production_listener_bound: false,
        production_tc_attach_smoke_passed: false,
        ebpf_attached: false,
        benchmark_executable_now: false,
        matched_go_rust_default_daemon_benchmark_recorded: false,
        true_rust_default_daemon_admitted: false,
        default_switch_allowed: false,
        default_path_mutation_allowed: false,
        product_chain_switch_allowed: false,
        artifact_root_template: "artifacts/daex-stage169-matched-benchmark/<run-id>",
        gate_decision: "stage169 materializes the matched benchmark corpus artifact layout and command plan, but it does not write runtime artifact files, execute Go or Rust daemons, record matched benchmark data, admit true Rust default daemon, or switch default/product paths",
        rows: vec![
            Stage169MatchedBenchmarkArtifactBuilderRow {
                area: "same corpus layout",
                status: "recorded",
                evidence: "shared manifest, config corpus, outbound matrix, host metadata, BPF/DNS/runtime artifacts, and cleanup rows are listed",
                blocker: "runtime artifact files have not been written",
                next_action: "write this layout to an explicit temporary artifact directory in a later dry-run stage",
            },
            Stage169MatchedBenchmarkArtifactBuilderRow {
                area: "Go/Rust symmetry",
                status: "recorded",
                evidence: "Go default daemon and Rust opt-in daemon have parallel command logs, build metadata, and runtime samples",
                blocker: "neither daemon is executed in Stage169",
                next_action: "reject any later benchmark where Go and Rust artifact schemas or corpus digests differ",
            },
            Stage169MatchedBenchmarkArtifactBuilderRow {
                area: "BPF/DNS/runtime evidence",
                status: "required",
                evidence: "listen_socket_map key 0/1, pinned map compatibility, DNS cache migration guard, domain routing ownership, and RuntimeOverview samples are required artifacts",
                blocker: "production tc/netns attach remains closed",
                next_action: "keep benchmark_executable_now=false until production-equivalent attach and same-corpus runs exist",
            },
            Stage169MatchedBenchmarkArtifactBuilderRow {
                area: "default safety",
                status: "closed-preserved",
                evidence: "Go default path, fallback, default switch, default path mutation, product-chain switch, and outbound/quic-go boundary stay unchanged",
                blocker: "matched benchmark data is absent",
                next_action: "do not admit true Rust default daemon or mutate default/product paths",
            },
        ],
        artifact_layout: stage169_artifact_layout(),
        command_plan: stage169_command_plan(),
        symmetry_requirements: vec![
            "same config corpus digest for Go and Rust",
            "same host metadata snapshot for Go and Rust",
            "same outbound protocol matrix for Go and Rust",
            "same startup/reload/TCP/UDP/DNS/runtime sample schema",
            "same cleanup and rollback evidence schema",
            "separate raw logs and build metadata for Go and Rust",
            "Stage167 bounded summary carried as input evidence only",
        ],
        validation_commands: vec![
            "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage169/matched_benchmark_corpus_artifact_builder.json",
            "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage169_matched_benchmark_corpus_artifact_builder.json",
            "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage169-matched-benchmark-corpus-artifact-builder",
            "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage169 -- --nocapture",
            "cargo test --manifest-path rust/Cargo.toml -p dae-product stage169 -- --nocapture",
            "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage168 -- --nocapture",
            "cargo test --manifest-path rust/Cargo.toml -p dae-cli -p dae-product -q",
            "cargo fmt --manifest-path rust/Cargo.toml --all -- --check",
            "git diff --check",
        ],
        remaining_blockers: vec![
            "runtime artifact files have not been written",
            "Go default daemon and Rust opt-in daemon have not been run on the same benchmark corpus",
            "production tc/netns attach remains closed",
            "matched Go/Rust default daemon benchmark has not executed",
            "true Rust default daemon admission remains false until matched benchmark data exists",
            "default daemon and product-chain switches remain closed",
        ],
        source: vec![
            "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage169",
            "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage158",
            "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage167",
            "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage168",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:11.1",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:11.4",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.3",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.4",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.5",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.8",
        ],
    }
}

fn stage169_artifact_layout() -> Vec<Stage169ArtifactLayoutRow> {
    vec![
        Stage169ArtifactLayoutRow {
            path: "manifest.json",
            owner: "shared",
            required: true,
            content: "run id, git revisions, config corpus digest, host metadata digest, command plan digest, and admission flags",
        },
        Stage169ArtifactLayoutRow {
            path: "config/corpus.dae",
            owner: "shared",
            required: true,
            content: "exact dae config used by both Go default daemon and Rust opt-in daemon",
        },
        Stage169ArtifactLayoutRow {
            path: "config/outbound-matrix.json",
            owner: "shared",
            required: true,
            content: "admitted outbound protocol matrix and per-protocol fixture references",
        },
        Stage169ArtifactLayoutRow {
            path: "host/metadata.json",
            owner: "shared",
            required: true,
            content: "kernel, bpffs, capabilities, sysctl, network namespace, tc, and clock metadata",
        },
        Stage169ArtifactLayoutRow {
            path: "go/command.log",
            owner: "go-default-daemon",
            required: true,
            content: "raw Go default daemon command, stdout, stderr, exit status, and timestamps",
        },
        Stage169ArtifactLayoutRow {
            path: "rust/command.log",
            owner: "rust-optin-daemon",
            required: true,
            content: "raw Rust opt-in daemon command, stdout, stderr, exit status, and timestamps",
        },
        Stage169ArtifactLayoutRow {
            path: "go/build.json",
            owner: "go-default-daemon",
            required: true,
            content: "Go daemon version, git revision, build tags, and binary digest",
        },
        Stage169ArtifactLayoutRow {
            path: "rust/build.json",
            owner: "rust-optin-daemon",
            required: true,
            content: "Rust daemon version, git revision, feature set, and binary digest",
        },
        Stage169ArtifactLayoutRow {
            path: "go/runtime-samples.jsonl",
            owner: "go-default-daemon",
            required: true,
            content: "RuntimeOverview, RSS, CPU, active TCP connections, UDP sessions, DNS stats, and BPF map stats",
        },
        Stage169ArtifactLayoutRow {
            path: "rust/runtime-samples.jsonl",
            owner: "rust-optin-daemon",
            required: true,
            content: "RuntimeOverview, RSS, CPU, active TCP connections, UDP sessions, DNS stats, and BPF map stats",
        },
        Stage169ArtifactLayoutRow {
            path: "shared/stage167-bounded-summary.json",
            owner: "shared",
            required: true,
            content: "bounded reload-owner/listen_socket_map benchmark summary carried only as input evidence",
        },
        Stage169ArtifactLayoutRow {
            path: "shared/reload-rollback-cleanup.json",
            owner: "shared",
            required: true,
            content: "reload success, invalid config rollback, listener reuse, BPF owner transfer, and scoped cleanup evidence",
        },
        Stage169ArtifactLayoutRow {
            path: "shared/bpf-map-snapshot.json",
            owner: "shared",
            required: true,
            content: "listen_socket_map key 0/1, pinned map compatibility, routing tuple, domain routing, and ownership snapshot requirements",
        },
        Stage169ArtifactLayoutRow {
            path: "shared/dns-cache-snapshot.json",
            owner: "shared",
            required: true,
            content: "DNS cache migration guard, cache hit samples, UDP/53 behavior, and domain routing bitmap ownership evidence",
        },
    ]
}

fn stage169_command_plan() -> Vec<Stage169CommandPlanRow> {
    vec![
        Stage169CommandPlanRow {
            name: "shared setup",
            executes_now: false,
            purpose: "prepare the same config corpus, host metadata capture, clean artifact root, and preflight checks for both daemon candidates",
        },
        Stage169CommandPlanRow {
            name: "Go default baseline",
            executes_now: false,
            purpose: "run preserved Go dae default daemon with the shared corpus and collect startup, reload, TCP, UDP, DNS, runtime, and cleanup artifacts",
        },
        Stage169CommandPlanRow {
            name: "Rust opt-in candidate",
            executes_now: false,
            purpose: "run Rust opt-in daemon with the same corpus and collect the same artifact set without mutating default/product paths",
        },
        Stage169CommandPlanRow {
            name: "collection",
            executes_now: false,
            purpose: "normalize samples, verify artifact symmetry, record missing rows, and reject partial or mismatched corpus data",
        },
        Stage169CommandPlanRow {
            name: "cleanup",
            executes_now: false,
            purpose: "stop candidate processes, detach temporary resources, preserve logs, and verify rollback/cleanup artifacts",
        },
    ]
}
