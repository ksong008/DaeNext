use serde_json::{Value, json};

use crate::runner::RunnerOutput;

pub(crate) fn run_stage159_listener_ebpf_policy_gate(args: &[String]) -> RunnerOutput {
    if let Some(arg) = args.first() {
        return RunnerOutput::usage(format!("unsupported stage159 argument: {arg}"));
    }
    RunnerOutput::ok(format!("{}\n", stage159_report()))
}

fn stage159_report() -> Value {
    let mut report = json!({
        "name": "stage159-production-listener-ebpf-benchmark-preflight-policy-gate",
        "stage": "stage159",
        "prior_gate": "stage158-matched-default-daemon-benchmark-execution-gate",
        "evidence_class": "read-only-production-listener-ebpf-benchmark-preflight-policy-gate",
        "execute_smoke": false,
        "read_only": true,
        "blocked": true,
        "blockers": [
            "production-equivalent listener/eBPF benchmark preflight policy is recorded but not executed",
            "no isolated namespace listener smoke has bound TCP/UDP listener yet",
            "no temporary eBPF pin/map attach smoke has executed yet",
            "matched benchmark remains blocked until safe preflight evidence exists"
        ]
    });
    for key in [
        "production_equivalent_benchmark_policy_recorded",
        "listener_binding_preflight_policy_recorded",
        "ebpf_attach_preflight_policy_recorded",
        "namespace_isolation_required",
        "temporary_bpf_pin_required",
        "capability_preflight_required",
        "rollback_cleanup_required",
        "go_default_path_preserved",
        "go_fallback_required",
    ] {
        report[key] = json!(true);
    }
    for key in [
        "production_listener_bound",
        "ebpf_attached",
        "isolated_namespace_listener_smoke_passed",
        "temporary_ebpf_attach_smoke_passed",
        "benchmark_executable_now",
        "matched_go_rust_default_daemon_benchmark_recorded",
        "true_rust_default_daemon_admitted",
        "default_switch_allowed",
        "default_path_mutation_allowed",
        "product_chain_switch_allowed",
    ] {
        report[key] = json!(false);
    }
    report["policy_rows"] = json!([
        {
            "area": "listener binding",
            "requirement": "bind TCP and UDP listeners only inside an isolated benchmark namespace or explicitly isolated temporary port scope",
            "current_status": "policy-recorded-not-executed",
            "closed_flag": "production_listener_bound=false"
        },
        {
            "area": "eBPF attach",
            "requirement": "use temporary BPF map/pin paths and never mutate production maps during benchmark preflight",
            "current_status": "policy-recorded-not-executed",
            "closed_flag": "ebpf_attached=false"
        },
        {
            "area": "capabilities",
            "requirement": "record CAP_NET_ADMIN/CAP_BPF or equivalent failure as environment blocker, not parity success",
            "current_status": "policy-recorded-not-executed",
            "closed_flag": "temporary_ebpf_attach_smoke_passed=false"
        },
        {
            "area": "rollback cleanup",
            "requirement": "remove temporary listeners, namespace handles, BPF maps/pins, pid/progress files, and benchmark logs after each run",
            "current_status": "policy-recorded-not-executed",
            "closed_flag": "benchmark_executable_now=false"
        },
        {
            "area": "default safety",
            "requirement": "preserve Go default dae run and keep product-chain switch closed while benchmark preflight is developed",
            "current_status": "policy-carried",
            "closed_flag": "default_switch_allowed=false"
        }
    ]);
    report["next_admission_queue"] = json!([
        {
            "stage": "stage160",
            "target": "isolated listener and temporary eBPF benchmark preflight harness",
            "required_output": "attempt isolated listener/BPF preflight without mutating production paths; record capability/environment blockers precisely"
        }
    ]);
    report["remaining_blockers"] = json!([
        "isolated namespace listener smoke has not executed",
        "temporary eBPF map/pin attach smoke has not executed",
        "matched Go/Rust default daemon benchmark has not executed",
        "true Rust default daemon admission remains false until matched benchmark data exists",
        "default daemon and product-chain switches remain closed"
    ]);
    report["validation_commands"] = json!([
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage159/production_listener_ebpf_benchmark_preflight_policy_gate.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage159_production_listener_ebpf_benchmark_preflight_policy_gate.json",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage159-production-listener-ebpf-benchmark-preflight-policy-gate",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage159 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage159 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage158 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-daemon -p dae-cli -p dae-product -q",
        "cargo fmt --manifest-path rust/Cargo.toml --all -- --check",
        "git diff --check"
    ]);
    report["source"] = json!([
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage159",
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage158",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.4",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.5",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.8"
    ]);
    report
}
