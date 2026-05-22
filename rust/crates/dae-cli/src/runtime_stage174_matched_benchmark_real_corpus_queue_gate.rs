use serde_json::{Value, json};

use crate::runner::RunnerOutput;

pub(crate) fn run_stage174_matched_benchmark_real_corpus_queue_gate(
    args: &[String],
) -> RunnerOutput {
    if let Some(arg) = args.first() {
        return RunnerOutput::usage(format!("unsupported stage174 argument: {arg}"));
    }
    RunnerOutput::ok(format!("{}\n", stage174_report()))
}

fn stage174_report() -> Value {
    let mut report = json!({
        "name": "stage174-matched-benchmark-real-corpus-materialization-queue-gate",
        "stage": "stage174",
        "prior_gate": "stage173-matched-benchmark-command-capture-artifact-verifier",
        "evidence_class": "read-only-matched-benchmark-real-corpus-materialization-queue-gate",
        "read_only": true,
        "blocked": true,
        "blockers": [
            "Stage171 benchmark corpus is still a placeholder dry-run input",
            "Stage174 records a review queue and does not materialize a corpus artifact",
            "Rust production dae run command is not admitted",
            "default daemon and product-chain switches remain closed"
        ]
    });
    for key in [
        "real_corpus_materialization_queue_recorded",
        "stage171_placeholder_boundary_carried",
        "stage172_command_templates_carried",
        "stage173_artifact_verifier_carried",
        "same_corpus_review_requirements_recorded",
        "outbound_matrix_review_required",
        "digest_provenance_required",
        "sensitive_material_redaction_required",
        "go_default_path_preserved",
        "go_fallback_required",
    ] {
        report[key] = json!(true);
    }
    for key in [
        "rust_production_dae_run_command_exists",
        "real_benchmark_corpus_materialized",
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
    report["queue_rows"] = json!([
        {
            "area": "config corpus replacement",
            "status": "queued",
            "requirement": "replace the Stage171 config/corpus.dae placeholder with one reviewed config corpus shared by Go default and Rust opt-in commands",
            "boundary": "queue entry does not materialize or execute the corpus",
            "closed_flag": "real_benchmark_corpus_materialized=false"
        },
        {
            "area": "outbound protocol matrix",
            "status": "queued",
            "requirement": "bind the corpus to the admitted protocol matrix and fixture references that both daemon owners can consume",
            "boundary": "protocol matrix review is not outbound/default admission",
            "closed_flag": "default_switch_allowed=false"
        },
        {
            "area": "digest and provenance",
            "status": "queued",
            "requirement": "record digests, source revision, config review notes, host-independent input paths, and Stage172 command binding",
            "boundary": "digest metadata without a reviewed corpus remains pre-benchmark evidence",
            "closed_flag": "benchmark_executable_now=false"
        },
        {
            "area": "runtime evidence scope",
            "status": "queued",
            "requirement": "preserve startup order, reload listener reuse, BPF owner transfer, DNS cache migration, and RuntimeOverview sample requirements",
            "boundary": "requirements do not prove production listener or tc/netns attach",
            "closed_flag": "production_tc_attach_smoke_passed=false"
        },
        {
            "area": "sensitive material safety",
            "status": "queued",
            "requirement": "remove secrets, live subscription credentials, private endpoints, and host-specific mutable paths before corpus artifact review",
            "boundary": "redaction review must happen before materialization",
            "closed_flag": "matched_go_rust_default_daemon_benchmark_recorded=false"
        }
    ]);
    report["materialization_requirements"] = json!([
        "reviewed config/corpus.dae replacing the Stage171 placeholder",
        "reviewed config/outbound-matrix.json with admitted fixture references",
        "shared blake3 digest contract and source provenance for Go/Rust command templates",
        "startup, reload, BPF owner, DNS cache, RuntimeOverview, and cleanup evidence scope",
        "redaction proof for secrets, subscriptions, private endpoints, and host-specific mutable paths"
    ]);
    report["remaining_blockers"] = json!([
        "Rust production dae run command is not admitted",
        "real matched benchmark corpus is not materialized",
        "Go default daemon and Rust opt-in daemon have not been run on the same benchmark corpus",
        "production tc/netns attach remains closed",
        "matched Go/Rust default daemon benchmark has not executed",
        "default daemon and product-chain switches remain closed"
    ]);
    report["next_admission_queue"] = json!([
        {
            "stage": "stage175",
            "target": "matched benchmark real corpus candidate materializer dry-run",
            "required_output": "write an explicit temporary-root reviewed corpus candidate manifest and digest contract without starting daemon benchmark"
        }
    ]);
    report["validation_commands"] = json!([
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage174/matched_benchmark_real_corpus_materialization_queue_gate.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage174_matched_benchmark_real_corpus_materialization_queue_gate.json",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage174-matched-benchmark-real-corpus-materialization-queue-gate",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage174 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage174 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage173 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli -p dae-product -q",
        "cargo fmt --manifest-path rust/Cargo.toml --all -- --check",
        "git diff --check"
    ]);
    report["source"] = json!([
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage174",
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage173",
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage172",
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage171",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.3",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.4",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.5",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.8"
    ]);
    report
}
