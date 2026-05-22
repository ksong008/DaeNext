use serde_json::{Value, json};

use crate::runner::RunnerOutput;

pub(crate) fn run_stage181_matched_benchmark_reviewed_corpus_runtime_blocker(
    args: &[String],
) -> RunnerOutput {
    if let Some(arg) = args.first() {
        return RunnerOutput::usage(format!("unsupported stage181 argument: {arg}"));
    }
    RunnerOutput::ok(format!("{}\n", stage181_report()))
}

fn stage181_report() -> Value {
    let mut report = json!({
        "name": "stage181-matched-benchmark-reviewed-corpus-runtime-readiness-blocker-gate",
        "stage": "stage181",
        "prior_gate": "stage180-matched-benchmark-reviewed-corpus-readiness-admission-queue-gate",
        "evidence_class": "read-only-reviewed-corpus-runtime-readiness-blocker-gate",
        "read_only": true,
        "blocked": true,
        "blockers": [
            "runtime production command blocker is still open",
            "same-corpus daemon execution blocker is still open",
            "production listener/tc/eBPF blocker is still open",
            "reload/runtime parity blocker is still open",
            "matched benchmark and default/product switch blockers remain closed"
        ]
    });
    for key in [
        "runtime_readiness_blocker_gate_recorded",
        "stage180_queue_carried",
        "production_command_blocker_recorded",
        "daemon_execution_blocker_recorded",
        "listener_tc_ebpf_blocker_recorded",
        "reload_runtime_parity_blocker_recorded",
        "matched_benchmark_blocker_recorded",
        "default_product_blocker_recorded",
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
    report["blocker_groups"] = blocker_groups();
    report["execution_order"] = json!([
        "admit production-shaped Rust dae run command",
        "execute Go default daemon and Rust opt-in daemon on the same reviewed corpus",
        "collect production listener, tc attach, listen_socket_map, and eBPF evidence",
        "prove startup, reload, DNS cache, RuntimeOverview, and cleanup parity",
        "record matched Go/Rust default daemon benchmark artifacts and metrics",
        "recertify true Rust default daemon, default path mutation, and product-chain switch gates"
    ]);
    report["gate_decision"] = json!(
        "Stage181 records a finer runtime readiness blocker gate after Stage180; it does not admit a production Rust daemon command, execute daemons, materialize a real corpus, record matched benchmark data, or switch default/product paths"
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
        "stage": "stage182",
        "target": "matched benchmark production Rust run command blocker gate",
        "required_output": "check what is still missing before a production-shaped Rust dae run command can be admitted for reviewed-corpus benchmark execution"
    }]);
    report["validation_commands"] = json!([
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage181/matched_benchmark_reviewed_corpus_runtime_readiness_blocker_gate.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage181_matched_benchmark_reviewed_corpus_runtime_readiness_blocker_gate.json",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage181-matched-benchmark-reviewed-corpus-runtime-readiness-blocker-gate",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage181 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage181 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage180 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli -p dae-product -q",
        "cargo fmt --manifest-path rust/Cargo.toml --all -- --check",
        "git diff --check"
    ]);
    report["source"] = json!([
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage181",
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage180",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.3",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.4",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.5",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.8"
    ]);
    report
}

fn blocker_groups() -> Value {
    json!([
        {
            "group": "production Rust run command",
            "status": "blocked",
            "evidence_required": "production-shaped Rust dae run command with config, pid/progress, signal, reload, and run identity boundaries",
            "next_step": "split command admission from benchmark execution",
            "closed_flag": "rust_production_dae_run_command_exists=false"
        },
        {
            "group": "same-corpus daemon execution",
            "status": "blocked",
            "evidence_required": "Go default daemon and Rust opt-in daemon execution logs bound to the same Stage178/179 reviewed corpus and Stage172/173 command template",
            "next_step": "prepare daemon execution gate after production command blocker is resolved",
            "closed_flag": "go_default_daemon_executed=false,rust_optin_daemon_executed=false"
        },
        {
            "group": "production listener/tc/eBPF",
            "status": "blocked",
            "evidence_required": "listener bind, tc attach, listen_socket_map key 0 TCP/key 1 UDP writes before ready, and eBPF attach evidence",
            "next_step": "keep production attach smoke separate from artifact verification",
            "closed_flag": "production_tc_attach_smoke_passed=false,ebpf_attached=false"
        },
        {
            "group": "reload/runtime parity",
            "status": "blocked",
            "evidence_required": "startup order, reload listener reuse, BPF owner transfer, DNS cache migration, RuntimeOverview, bounded close, and reload scoped cleanup",
            "next_step": "prove parity with daemon lifecycle evidence before benchmark readiness opens",
            "closed_flag": "benchmark_executable_now=false"
        },
        {
            "group": "matched benchmark record",
            "status": "blocked",
            "evidence_required": "same-host Go/Rust default daemon benchmark metrics and artifacts from the reviewed corpus",
            "next_step": "record matched benchmark only after runtime execution blockers close",
            "closed_flag": "matched_go_rust_default_daemon_benchmark_recorded=false"
        },
        {
            "group": "default/product recertification",
            "status": "blocked",
            "evidence_required": "true Rust default daemon admission, default path mutation, and product-chain switch recertification after benchmark data",
            "next_step": "keep default/product switch closed until benchmark and runtime evidence pass",
            "closed_flag": "default_switch_allowed=false,product_chain_switch_allowed=false"
        }
    ])
}
