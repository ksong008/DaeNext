use serde_json::{Value, json};

use crate::runner::RunnerOutput;

pub(crate) fn run_stage169_matched_benchmark_artifact_builder(args: &[String]) -> RunnerOutput {
    if let Some(arg) = args.first() {
        return RunnerOutput::usage(format!("unsupported stage169 argument: {arg}"));
    }
    RunnerOutput::ok(format!("{}\n", stage169_report()))
}

fn stage169_report() -> Value {
    let mut report = json!({
        "name": "stage169-matched-benchmark-corpus-artifact-builder",
        "stage": "stage169",
        "prior_gate": "stage168-matched-default-daemon-benchmark-execution-gate",
        "evidence_class": "read-only-matched-benchmark-corpus-artifact-layout-builder",
        "read_only": true,
        "execute_builder": false,
        "blocked": true,
        "blockers": [
            "this gate records artifact layout and command plan only",
            "Go default daemon and Rust opt-in daemon are not executed",
            "production tc/netns attach remains closed",
            "matched Go/Rust default daemon benchmark data is still absent"
        ]
    });
    for key in [
        "matched_benchmark_artifact_layout_materialized",
        "command_plan_recorded",
        "same_corpus_layout_recorded",
        "go_rust_artifact_symmetry_recorded",
        "stage167_bounded_summary_required",
        "host_metadata_required",
        "bpf_dns_runtime_artifacts_required",
        "go_default_path_preserved",
        "go_fallback_required",
    ] {
        report[key] = json!(true);
    }
    for key in [
        "artifact_files_written_to_runtime_dir",
        "go_default_daemon_executed",
        "rust_optin_daemon_executed",
        "production_listener_bound",
        "production_tc_attach_smoke_passed",
        "ebpf_attached",
        "benchmark_executable_now",
        "matched_go_rust_default_daemon_benchmark_recorded",
        "true_rust_default_daemon_admitted",
        "default_switch_allowed",
        "default_path_mutation_allowed",
        "product_chain_switch_allowed",
    ] {
        report[key] = json!(false);
    }
    report["artifact_root_template"] = json!("artifacts/daex-stage169-matched-benchmark/<run-id>");
    report["artifact_layout"] = json!([
        {
            "path": "manifest.json",
            "owner": "shared",
            "required": true,
            "content": "run id, git revisions, config corpus digest, host metadata digest, command plan digest, and admission flags"
        },
        {
            "path": "config/corpus.dae",
            "owner": "shared",
            "required": true,
            "content": "exact dae config used by both Go default daemon and Rust opt-in daemon"
        },
        {
            "path": "config/outbound-matrix.json",
            "owner": "shared",
            "required": true,
            "content": "admitted outbound protocol matrix and per-protocol fixture references"
        },
        {
            "path": "host/metadata.json",
            "owner": "shared",
            "required": true,
            "content": "kernel, bpffs, capabilities, sysctl, network namespace, tc, and clock metadata"
        },
        {
            "path": "go/command.log",
            "owner": "go-default-daemon",
            "required": true,
            "content": "raw Go default daemon command, stdout, stderr, exit status, and timestamps"
        },
        {
            "path": "rust/command.log",
            "owner": "rust-optin-daemon",
            "required": true,
            "content": "raw Rust opt-in daemon command, stdout, stderr, exit status, and timestamps"
        },
        {
            "path": "go/build.json",
            "owner": "go-default-daemon",
            "required": true,
            "content": "Go daemon version, git revision, build tags, and binary digest"
        },
        {
            "path": "rust/build.json",
            "owner": "rust-optin-daemon",
            "required": true,
            "content": "Rust daemon version, git revision, feature set, and binary digest"
        },
        {
            "path": "go/runtime-samples.jsonl",
            "owner": "go-default-daemon",
            "required": true,
            "content": "RuntimeOverview, RSS, CPU, active TCP connections, UDP sessions, DNS stats, and BPF map stats"
        },
        {
            "path": "rust/runtime-samples.jsonl",
            "owner": "rust-optin-daemon",
            "required": true,
            "content": "RuntimeOverview, RSS, CPU, active TCP connections, UDP sessions, DNS stats, and BPF map stats"
        },
        {
            "path": "shared/stage167-bounded-summary.json",
            "owner": "shared",
            "required": true,
            "content": "bounded reload-owner/listen_socket_map benchmark summary carried only as input evidence"
        },
        {
            "path": "shared/reload-rollback-cleanup.json",
            "owner": "shared",
            "required": true,
            "content": "reload success, invalid config rollback, listener reuse, BPF owner transfer, and scoped cleanup evidence"
        },
        {
            "path": "shared/bpf-map-snapshot.json",
            "owner": "shared",
            "required": true,
            "content": "listen_socket_map key 0/1, pinned map compatibility, routing tuple, domain routing, and ownership snapshot requirements"
        },
        {
            "path": "shared/dns-cache-snapshot.json",
            "owner": "shared",
            "required": true,
            "content": "DNS cache migration guard, cache hit samples, UDP/53 behavior, and domain routing bitmap ownership evidence"
        }
    ]);
    report["command_plan"] = json!([
        {
            "name": "shared setup",
            "executes_now": false,
            "purpose": "prepare the same config corpus, host metadata capture, clean artifact root, and preflight checks for both daemon candidates"
        },
        {
            "name": "Go default baseline",
            "executes_now": false,
            "purpose": "run preserved Go dae default daemon with the shared corpus and collect startup, reload, TCP, UDP, DNS, runtime, and cleanup artifacts"
        },
        {
            "name": "Rust opt-in candidate",
            "executes_now": false,
            "purpose": "run Rust opt-in daemon with the same corpus and collect the same artifact set without mutating default/product paths"
        },
        {
            "name": "collection",
            "executes_now": false,
            "purpose": "normalize samples, verify artifact symmetry, record missing rows, and reject partial or mismatched corpus data"
        },
        {
            "name": "cleanup",
            "executes_now": false,
            "purpose": "stop candidate processes, detach temporary resources, preserve logs, and verify rollback/cleanup artifacts"
        }
    ]);
    report["symmetry_requirements"] = json!([
        "same config corpus digest for Go and Rust",
        "same host metadata snapshot for Go and Rust",
        "same outbound protocol matrix for Go and Rust",
        "same startup/reload/TCP/UDP/DNS/runtime sample schema",
        "same cleanup and rollback evidence schema",
        "separate raw logs and build metadata for Go and Rust",
        "Stage167 bounded summary carried as input evidence only"
    ]);
    report["gate_decision"] = json!(
        "Stage169 materializes the matched benchmark corpus artifact layout and command plan, but it does not write runtime artifact files, execute Go or Rust daemons, record matched benchmark data, admit true Rust default daemon, or switch default/product paths"
    );
    report["remaining_blockers"] = json!([
        "runtime artifact files have not been written",
        "Go default daemon and Rust opt-in daemon have not been run on the same benchmark corpus",
        "production tc/netns attach remains closed",
        "matched Go/Rust default daemon benchmark has not executed",
        "true Rust default daemon admission remains false until matched benchmark data exists",
        "default daemon and product-chain switches remain closed"
    ]);
    report["next_admission_queue"] = json!([
        {
            "stage": "stage170",
            "target": "matched benchmark artifact writer dry-run",
            "required_output": "write the Stage169 artifact layout to an explicit temporary runtime directory without executing Go/Rust daemon benchmark or switching defaults"
        }
    ]);
    report["validation_commands"] = json!([
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage169/matched_benchmark_corpus_artifact_builder.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage169_matched_benchmark_corpus_artifact_builder.json",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage169-matched-benchmark-corpus-artifact-builder",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage169 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage169 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage168 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli -p dae-product -q",
        "cargo fmt --manifest-path rust/Cargo.toml --all -- --check",
        "git diff --check"
    ]);
    report["source"] = json!([
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage169",
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage158",
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage167",
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage168",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:11.1",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:11.4",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.3",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.4",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.5",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.8"
    ]);
    report
}
