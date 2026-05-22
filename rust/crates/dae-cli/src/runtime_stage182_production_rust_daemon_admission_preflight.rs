use serde_json::{Value, json};

use crate::runner::RunnerOutput;

pub(crate) fn run_stage182_production_rust_daemon_admission_preflight(
    args: &[String],
) -> RunnerOutput {
    if let Some(arg) = args.first() {
        return RunnerOutput::usage(format!("unsupported stage182 argument: {arg}"));
    }
    RunnerOutput::ok(format!("{}\n", stage182_report()))
}

fn stage182_report() -> Value {
    let mut report = json!({
        "name": "stage182-production-rust-daemon-admission-preflight",
        "stage": "stage182",
        "prior_gate": "stage181-matched-benchmark-reviewed-corpus-runtime-readiness-blocker-gate",
        "evidence_class": "read-only-production-rust-daemon-admission-preflight",
        "read_only": true,
        "blocked": true,
        "blockers": [
            "production Rust dae run command is not admitted",
            "reviewed corpus is still a dry-run artifact, not a real benchmark corpus",
            "pid/progress/signal/reload lifecycle has not been bound to a production Rust daemon",
            "listener/tc/eBPF evidence has not been collected",
            "matched benchmark and default/product switches remain closed"
        ]
    });
    for key in [
        "production_rust_daemon_admission_preflight_recorded",
        "stage181_runtime_blocker_carried",
        "command_identity_checked",
        "config_corpus_binding_checked",
        "progress_pid_signal_lifecycle_checked",
        "startup_reload_control_plane_requirements_checked",
        "default_path_isolation_checked",
        "benchmark_exclusion_checked",
        "stage156_optin_identity_carried",
        "stage157_control_plane_evidence_required",
        "stage178_reviewed_artifact_required",
        "stage179_verifier_required",
        "go_default_path_preserved",
        "go_fallback_required",
    ] {
        report[key] = json!(true);
    }
    for key in [
        "reviewed_real_corpus_ready",
        "rust_production_dae_run_command_exists",
        "rust_production_run_command_admitted",
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
    report["preflight_rows"] = preflight_rows();
    report["admission_requirements"] = json!([
        "production-shaped Rust dae run command identity must be separate from the Stage156 opt-in command",
        "reviewed corpus config and outbound matrix must be bound to the command without marking real benchmark corpus ready",
        "pid file, progress file, signal handler, reload trigger, and run identity paths must stay isolated until admission",
        "startup order, reload listener reuse, BPF owner transfer, DNS cache migration, and RuntimeOverview requirements must be carried before execution",
        "Go default path and product-chain default switch must remain unchanged",
        "matched benchmark execution must remain blocked until daemon lifecycle and listener/tc/eBPF evidence pass"
    ]);
    report["gate_decision"] = json!(
        "Stage182 records one merged production Rust daemon admission preflight. It carries command, corpus, lifecycle, runtime, default-isolation, and benchmark-exclusion requirements without admitting a production Rust dae run, executing daemons, binding listeners, attaching eBPF, recording benchmark data, or switching default/product paths"
    );
    report["remaining_blockers"] = json!([
        "Rust production dae run command is not admitted",
        "reviewed real corpus is not ready",
        "Go default daemon and Rust opt-in daemon have not been run on the same reviewed corpus",
        "production listener, tc attach, listen_socket_map, and eBPF evidence are missing",
        "reload/runtime parity has not been proven with daemon lifecycle evidence",
        "matched Go/Rust default daemon benchmark has not executed",
        "default daemon and product-chain switches remain closed"
    ]);
    report["next_admission_queue"] = json!([{
        "stage": "stage183",
        "target": "same-corpus daemon execution preflight",
        "required_output": "prepare Go default daemon and Rust opt-in daemon execution on the same reviewed corpus only after the production Rust daemon admission preflight remains closed and explicit"
    }]);
    report["validation_commands"] = json!([
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage182/production_rust_daemon_admission_preflight.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage182_production_rust_daemon_admission_preflight.json",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage182-production-rust-daemon-admission-preflight",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage182 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage182 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage181 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli -p dae-product -q",
        "cargo fmt --manifest-path rust/Cargo.toml --all -- --check",
        "git diff --check"
    ]);
    report["source"] = json!([
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage182",
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage181",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.3",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.4",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.5",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.8",
        "rust/crates/dae-daemon/src/default_run_identity.rs"
    ]);
    report
}

fn preflight_rows() -> Value {
    json!([
        {
            "area": "production command identity",
            "status": "checked-closed",
            "current_evidence": "Stage156 opt-in run-shaped identity exists, but production Rust dae run is not admitted",
            "required_before_admission": "separate Rust production dae run command identity with config, logfile, pid, progress, signal, reload, and run metadata boundaries",
            "boundary": "opt-in identity cannot replace Go default dae run",
            "closed_flag": "rust_production_dae_run_command_exists=false"
        },
        {
            "area": "reviewed config and corpus binding",
            "status": "checked-closed",
            "current_evidence": "Stage178 reviewed corpus dry-run artifact and Stage179 verifier evidence are required inputs",
            "required_before_admission": "bind reviewed config and outbound matrix to the command while keeping reviewed_real_corpus_ready false until daemon evidence exists",
            "boundary": "reviewed dry-run artifact is not a real benchmark corpus",
            "closed_flag": "reviewed_real_corpus_ready=false"
        },
        {
            "area": "pid progress signal reload lifecycle",
            "status": "checked-closed",
            "current_evidence": "Stage156 records isolated pid/progress/log paths; production signal handler and reload path are not installed",
            "required_before_admission": "prove pid/progress files, SIGUSR1 reload trigger, run identity, and bounded reload lifecycle are isolated and reversible",
            "boundary": "production pid/progress paths must not be mutated",
            "closed_flag": "rust_production_run_command_admitted=false"
        },
        {
            "area": "startup reload control-plane evidence",
            "status": "checked-closed",
            "current_evidence": "DAENEW memo requires startup order, listener ready, BPF owner transfer, DNS cache migration, RuntimeOverview, and bounded close",
            "required_before_admission": "prove startup order and reload semantics with daemon lifecycle evidence before benchmark execution",
            "boundary": "preflight does not bind listeners or attach eBPF",
            "closed_flag": "production_listener_bound=false"
        },
        {
            "area": "default path isolation",
            "status": "checked-closed",
            "current_evidence": "Go default path remains preserved and Rust path remains opt-in",
            "required_before_admission": "keep Go fallback and product-chain default path unchanged until true Rust default daemon admission is recertified",
            "boundary": "product-chain switch cannot happen before matched benchmark evidence",
            "closed_flag": "default_switch_allowed=false"
        },
        {
            "area": "benchmark exclusion",
            "status": "checked-closed",
            "current_evidence": "Stage181 keeps daemon execution, listener/tc/eBPF, and matched benchmark blockers closed",
            "required_before_admission": "run Go default daemon and Rust opt-in daemon on the same reviewed corpus only after production command preflight remains explicit",
            "boundary": "preflight is not benchmark execution",
            "closed_flag": "matched_go_rust_default_daemon_benchmark_recorded=false"
        }
    ])
}
