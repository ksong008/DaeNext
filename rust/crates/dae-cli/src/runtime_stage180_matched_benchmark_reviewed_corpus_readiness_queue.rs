use serde_json::{Value, json};

use crate::runner::RunnerOutput;

pub(crate) fn run_stage180_matched_benchmark_reviewed_corpus_readiness_queue(
    args: &[String],
) -> RunnerOutput {
    if let Some(arg) = args.first() {
        return RunnerOutput::usage(format!("unsupported stage180 argument: {arg}"));
    }
    RunnerOutput::ok(format!("{}\n", stage180_report()))
}

fn stage180_report() -> Value {
    let mut report = json!({
        "name": "stage180-matched-benchmark-reviewed-corpus-readiness-admission-queue-gate",
        "stage": "stage180",
        "prior_gate": "stage179-matched-benchmark-reviewed-corpus-artifact-verifier",
        "evidence_class": "read-only-reviewed-corpus-readiness-admission-queue-gate",
        "read_only": true,
        "blocked": true,
        "blockers": [
            "Stage179 verifier evidence is necessary but insufficient for reviewed corpus readiness",
            "Rust production dae run command is not admitted",
            "Go default daemon and Rust opt-in daemon have not executed on the same reviewed corpus",
            "production listener/tc/eBPF evidence remains closed",
            "matched benchmark and default/product switches remain closed"
        ]
    });
    for key in [
        "reviewed_corpus_readiness_admission_queue_recorded",
        "stage178_reviewed_artifact_carried",
        "stage179_verifier_evidence_carried",
        "verified_file_set_required",
        "verified_digest_required",
        "redaction_runtime_command_evidence_required",
        "runtime_readiness_blockers_recorded",
        "benchmark_readiness_blockers_recorded",
        "default_switch_blockers_recorded",
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
    report["readiness_queue_rows"] = readiness_queue_rows();
    report["readiness_requirements"] = json!([
        "Stage179 verifier evidence must remain reproducible from an explicit Stage178 root",
        "Rust production dae run command must be admitted before readiness can open",
        "Go default daemon and Rust opt-in daemon must run against the same reviewed corpus",
        "production listener, tc attach, listen_socket_map, and eBPF evidence must be collected",
        "startup, reload listener reuse, BPF owner transfer, DNS cache, RuntimeOverview, and cleanup parity must be proven",
        "matched Go/Rust benchmark artifacts and metrics must be recorded",
        "default daemon and product-chain switch gates must be recertified after benchmark evidence"
    ]);
    report["gate_decision"] = json!(
        "Stage180 records the readiness admission queue after Stage179 verifier evidence; it keeps reviewed_real_corpus_ready, real corpus materialization, daemon execution, matched benchmark, true Rust default daemon, and default/product switches closed"
    );
    report["remaining_blockers"] = json!([
        "reviewed real corpus is not ready",
        "Rust production dae run command is not admitted",
        "real matched benchmark corpus is not materialized",
        "Go default daemon and Rust opt-in daemon have not been run on the same reviewed corpus",
        "production tc/netns attach remains closed",
        "matched Go/Rust default daemon benchmark has not executed",
        "default daemon and product-chain switches remain closed"
    ]);
    report["next_admission_queue"] = json!([{
        "stage": "stage181",
        "target": "matched benchmark reviewed corpus runtime readiness blocker gate",
        "required_output": "split Stage180 readiness blockers into runtime production command, daemon execution, listener/tc/eBPF, and matched benchmark blocker gates"
    }]);
    report["validation_commands"] = json!([
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage180/matched_benchmark_reviewed_corpus_readiness_admission_queue_gate.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage180_matched_benchmark_reviewed_corpus_readiness_admission_queue_gate.json",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage180-matched-benchmark-reviewed-corpus-readiness-admission-queue-gate",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage180 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage180 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage179 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli -p dae-product -q",
        "cargo fmt --manifest-path rust/Cargo.toml --all -- --check",
        "git diff --check"
    ]);
    report["source"] = json!([
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage180",
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage179",
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage178",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.3",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.4",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.5",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.8"
    ]);
    report
}

fn readiness_queue_rows() -> Value {
    json!([
        {
            "area": "Stage179 verifier evidence",
            "status": "carried-but-insufficient",
            "requirement": "keep explicit Stage178 root verification reproducible with file set, digest, redaction, runtime scope, command binding, and closed flags",
            "boundary": "artifact verification alone does not make reviewed corpus ready",
            "closed_flag": "reviewed_real_corpus_ready=false"
        },
        {
            "area": "Rust production run command",
            "status": "required",
            "requirement": "admit a production-shaped Rust dae run command before benchmark execution can use a Rust daemon candidate",
            "boundary": "Stage156 opt-in identity and Stage157 entrypoint evidence are not production daemon admission",
            "closed_flag": "rust_production_dae_run_command_exists=false"
        },
        {
            "area": "same-corpus daemon execution",
            "status": "required",
            "requirement": "run Go default daemon and Rust opt-in daemon on the same reviewed corpus with the Stage172/173 command binding",
            "boundary": "command templates and verifier artifacts are not daemon execution",
            "closed_flag": "go_default_daemon_executed=false,rust_optin_daemon_executed=false"
        },
        {
            "area": "production listener/tc/eBPF evidence",
            "status": "required",
            "requirement": "prove production listener bind, tc attach, listen_socket_map key 0/1 writes, and eBPF attach evidence",
            "boundary": "runtime evidence scope text is not production attach evidence",
            "closed_flag": "production_tc_attach_smoke_passed=false"
        },
        {
            "area": "reload and runtime parity",
            "status": "required",
            "requirement": "prove startup order, reload listener reuse, BPF owner transfer, DNS cache migration, RuntimeOverview, and reload cleanup parity",
            "boundary": "parity requirements remain blockers until executed against daemon lifecycle",
            "closed_flag": "benchmark_executable_now=false"
        },
        {
            "area": "matched benchmark record",
            "status": "required",
            "requirement": "record matched Go/Rust default daemon benchmark metrics and artifacts from the reviewed corpus",
            "boundary": "reviewed artifact digest is not benchmark data",
            "closed_flag": "matched_go_rust_default_daemon_benchmark_recorded=false"
        },
        {
            "area": "default/product switch recertification",
            "status": "required",
            "requirement": "recertify true Rust default daemon admission, default path mutation, and product-chain switch only after benchmark evidence",
            "boundary": "readiness queue does not switch daemon defaults",
            "closed_flag": "default_switch_allowed=false,product_chain_switch_allowed=false"
        }
    ])
}
