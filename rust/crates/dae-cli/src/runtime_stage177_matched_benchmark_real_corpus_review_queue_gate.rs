use serde_json::{Value, json};

use crate::runner::RunnerOutput;

pub(crate) fn run_stage177_matched_benchmark_real_corpus_review_queue_gate(
    args: &[String],
) -> RunnerOutput {
    if let Some(arg) = args.first() {
        return RunnerOutput::usage(format!("unsupported stage177 argument: {arg}"));
    }
    RunnerOutput::ok(format!("{}\n", stage177_report()))
}

fn stage177_report() -> Value {
    let mut report = json!({
        "name": "stage177-matched-benchmark-real-corpus-review-admission-queue-gate",
        "stage": "stage177",
        "prior_gate": "stage176-matched-benchmark-real-corpus-candidate-artifact-verifier",
        "evidence_class": "read-only-real-corpus-review-admission-queue-gate",
        "read_only": true,
        "blocked": true,
        "blockers": [
            "Stage175 candidate remains review-pending and cannot be promoted directly",
            "reviewed input, provenance, redaction, and reviewer sign-off are not materialized",
            "Rust production dae run command is not admitted",
            "default daemon and product-chain switches remain closed"
        ]
    });
    for key in [
        "real_corpus_review_admission_queue_recorded",
        "stage175_candidate_boundary_carried",
        "stage176_candidate_verifier_carried",
        "reviewed_config_input_required",
        "reviewed_outbound_matrix_required",
        "digest_provenance_required",
        "redaction_evidence_required",
        "runtime_evidence_scope_required",
        "command_binding_required",
        "reviewer_signoff_required",
        "go_default_path_preserved",
        "go_fallback_required",
    ] {
        report[key] = json!(true);
    }
    for key in [
        "reviewed_real_corpus_ready",
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
    report["review_queue_rows"] = json!([
        {
            "area": "reviewed config input",
            "status": "required",
            "requirement": "replace the Stage175 candidate config with a reviewed, redacted, host-independent config corpus",
            "boundary": "review requirement does not materialize the corpus",
            "closed_flag": "real_benchmark_corpus_materialized=false"
        },
        {
            "area": "outbound matrix approval",
            "status": "required",
            "requirement": "approve protocol matrix coverage and fixture references against the admitted Rust protocol gates",
            "boundary": "matrix approval does not switch outbound/default paths",
            "closed_flag": "default_switch_allowed=false"
        },
        {
            "area": "digest and provenance",
            "status": "required",
            "requirement": "record source revision, review notes, blake3 digest contract, and Stage172/173 command binding",
            "boundary": "provenance alone is not benchmark execution",
            "closed_flag": "benchmark_executable_now=false"
        },
        {
            "area": "redaction evidence",
            "status": "required",
            "requirement": "prove secrets, subscription credentials, private endpoints, and host-specific mutable paths are removed",
            "boundary": "redaction review must be attached before materialization",
            "closed_flag": "matched_go_rust_default_daemon_benchmark_recorded=false"
        },
        {
            "area": "runtime parity scope",
            "status": "required",
            "requirement": "carry startup order, reload listener reuse, BPF owner transfer, DNS cache, RuntimeOverview, and cleanup evidence scope",
            "boundary": "scope review is not production listener/tc attach",
            "closed_flag": "production_tc_attach_smoke_passed=false"
        },
        {
            "area": "reviewer sign-off",
            "status": "required",
            "requirement": "record explicit sign-off that the reviewed corpus may replace the Stage175 review-pending candidate",
            "boundary": "sign-off is required before any materializer opens real_benchmark_corpus_materialized",
            "closed_flag": "reviewed_real_corpus_ready=false"
        }
    ]);
    report["review_admission_requirements"] = json!([
        "reviewed config corpus replaces Stage175 candidate config",
        "reviewed outbound matrix binds admitted protocol fixture coverage",
        "blake3 digest and provenance contract references source revision and command binding",
        "redaction evidence proves no secrets, subscriptions, private endpoints, or host-specific mutable paths",
        "runtime parity scope carries startup/reload/BPF/DNS/runtime overview requirements",
        "reviewer sign-off explicitly permits materializer dry-run to write reviewed corpus artifacts"
    ]);
    report["remaining_blockers"] = json!([
        "reviewed real corpus is not ready",
        "Rust production dae run command is not admitted",
        "real matched benchmark corpus is not materialized",
        "Go default daemon and Rust opt-in daemon have not been run on the same benchmark corpus",
        "production tc/netns attach remains closed",
        "matched Go/Rust default daemon benchmark has not executed",
        "default daemon and product-chain switches remain closed"
    ]);
    report["next_admission_queue"] = json!([{
        "stage": "stage178",
        "target": "matched benchmark reviewed corpus materializer dry-run",
        "required_output": "write an explicit temporary-root reviewed corpus artifact set only after review admission rows are carried"
    }]);
    report["validation_commands"] = json!([
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage177/matched_benchmark_real_corpus_review_admission_queue_gate.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage177_matched_benchmark_real_corpus_review_admission_queue_gate.json",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage177-matched-benchmark-real-corpus-review-admission-queue-gate",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage177 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage177 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage176 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli -p dae-product -q",
        "cargo fmt --manifest-path rust/Cargo.toml --all -- --check",
        "git diff --check"
    ]);
    report["source"] = json!([
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage177",
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage176",
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage175",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.3",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.4",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.5",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.8"
    ]);
    report
}
