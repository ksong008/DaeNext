use serde_json::{Value, json};

use crate::runner::RunnerOutput;

pub(crate) fn run_stage155_product_chain_blocker_review_gate(args: &[String]) -> RunnerOutput {
    if let Some(arg) = args.first() {
        return RunnerOutput::usage(format!("unsupported stage155 argument: {arg}"));
    }
    RunnerOutput::ok(format!("{}\n", stage155_report()))
}

fn stage155_report() -> Value {
    let mut report = json!({
        "name": "stage155-product-chain-default-switch-blocker-review-gate",
        "stage": "stage155",
        "prior_gate": "stage154-matched-default-daemon-benchmark-readiness-refresh-gate",
        "evidence_class": "read-only-product-chain-default-switch-blocker-review-gate",
        "execute_smoke": false,
        "read_only": true,
        "blocked": true,
        "blockers": [
            "matched Go default daemon vs true Rust default daemon benchmark is still absent",
            "Rust default run identity is not admitted",
            "Rust default control-plane entrypoint is not admitted",
            "production listener binding and eBPF attach remain closed",
            "systemd, release, dae-wing, and daed default switches must stay blocked"
        ]
    });
    for key in [
        "product_chain_blocker_review_recorded",
        "benchmark_blocker_carried",
        "default_switch_blockers_recorded",
        "product_chain_switch_blockers_recorded",
        "external_dependency_policy_carried",
        "go_default_path_preserved",
        "go_fallback_required",
        "external_outbound_required",
        "external_quic_go_required",
    ] {
        report[key] = json!(true);
    }
    for key in [
        "benchmark_executable_now",
        "rust_default_run_entrypoint_exists",
        "rust_default_control_plane_entrypoint_admitted",
        "production_listener_bound",
        "ebpf_attached",
        "matched_go_rust_default_daemon_benchmark_recorded",
        "true_rust_default_daemon_admitted",
        "default_switch_allowed",
        "default_path_mutation_allowed",
        "product_chain_switch_allowed",
        "systemd_execstart_switch_allowed",
        "release_artifact_switch_allowed",
        "daewing_default_switch_allowed",
        "daed_default_switch_allowed",
    ] {
        report[key] = json!(false);
    }
    report["gate_decision"] = json!(
        "stage155 carries the Stage154 benchmark blocker into the product-chain/default-switch review: dae run, systemd, release artifacts, dae-wing, and daed must keep Go-backed defaults until a true Rust default daemon identity, production control-plane admission, and matched benchmark exist"
    );
    report["review_rows"] = json!([
        {
            "area": "matched benchmark",
            "status": "blocked-carried-from-stage154",
            "evidence": "Stage154 records corpus and artifact requirements but does not execute a Go-vs-Rust default daemon benchmark",
            "blocker": "benchmark_executable_now=false and matched_go_rust_default_daemon_benchmark_recorded=false",
            "next_action": "run matched benchmark only after Rust default run identity and control-plane admission exist"
        },
        {
            "area": "Rust default daemon identity",
            "status": "blocked-before-default",
            "evidence": "Stage153 provides an opt-in wrapper preflight only",
            "blocker": "rust_default_run_entrypoint_exists=false",
            "next_action": "introduce a real Rust default run identity without replacing Go default path"
        },
        {
            "area": "production control plane",
            "status": "blocked-before-production-ownership",
            "evidence": "Stage151 owner preflight is synthetic and Stage152/153 compose isolated smokes",
            "blocker": "production_listener_bound=false and ebpf_attached=false",
            "next_action": "admit production listener reuse and eBPF ownership separately before default switch"
        },
        {
            "area": "install, systemd, and release",
            "status": "keep-go-backed-default",
            "evidence": "default dae run remains the product-facing daemon path",
            "blocker": "systemd_execstart_switch_allowed=false and release_artifact_switch_allowed=false",
            "next_action": "keep package and service defaults on Go-backed dae run"
        },
        {
            "area": "dae-wing and daed product chain",
            "status": "cross-repo-switch-blocked",
            "evidence": "local dae gates do not prove dae-wing or daed runtime behavior",
            "blocker": "daewing_default_switch_allowed=false and daed_default_switch_allowed=false",
            "next_action": "validate downstream repos only after local default daemon admission"
        },
        {
            "area": "external outbound and quic-go dependencies",
            "status": "policy-carried",
            "evidence": "/root/project/outbound and /root/project/quic-go remain required external dependencies",
            "blocker": "dependency policy is preserved; this stage does not rewrite outbound or quic-go",
            "next_action": "keep external dependency boundary until explicit replacement stage"
        }
    ]);
    report["remaining_blockers"] = json!([
        "Rust default run entrypoint is still absent; Stage153 is opt-in wrapper evidence only",
        "Rust default control-plane entrypoint is not admitted",
        "production listener binding and eBPF attach remain closed",
        "matched benchmark cannot run until Go and Rust default daemon identities execute the same config corpus on the same host",
        "systemd, release, dae-wing, daed, default daemon, and product-chain switches remain closed"
    ]);
    report["next_admission_queue"] = json!([
        {
            "stage": "stage156",
            "target": "Rust default run identity admission",
            "required_output": "add a real Rust default run identity in opt-in form without replacing Go default dae run"
        },
        {
            "stage": "stage157",
            "target": "production control-plane entrypoint admission",
            "required_output": "prove listener reuse, eBPF ownership transfer, DNS cache guard, and rollback semantics before production binding"
        },
        {
            "stage": "stage158",
            "target": "matched Go/Rust default daemon benchmark execution",
            "required_output": "run the same config corpus on Go default daemon and true Rust default daemon before any default/product switch"
        }
    ]);
    report["validation_commands"] = json!([
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage155/product_chain_default_switch_blocker_review_gate.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage155_product_chain_default_switch_blocker_review_gate.json",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage155-product-chain-default-switch-blocker-review-gate",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage155 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage155 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage154 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound -p dae-cli -p dae-product -q",
        "cargo fmt --manifest-path rust/Cargo.toml --all -- --check",
        "git diff --check"
    ]);
    report["source"] = json!([
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage155",
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage154",
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage23",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.1",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.8",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:28.3",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:28.4"
    ]);
    report
}
