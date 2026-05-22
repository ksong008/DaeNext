use serde_json::{Value, json};

use crate::runner::RunnerOutput;

pub(crate) fn run_stage163_bpf_owner_handoff_queue_gate(args: &[String]) -> RunnerOutput {
    if let Some(arg) = args.first() {
        return RunnerOutput::usage(format!("unsupported stage163 argument: {arg}"));
    }
    RunnerOutput::ok(format!("{}\n", stage163_report()))
}

fn stage163_report() -> Value {
    let mut report = json!({
        "name": "stage163-bpf-owner-transfer-listener-map-handoff-queue-gate",
        "stage": "stage163",
        "prior_gate": "stage162-temporary-ebpf-program-attach-preflight-gate",
        "evidence_class": "read-only-bpf-owner-transfer-listener-map-handoff-queue-gate",
        "execute_smoke": false,
        "read_only": true,
        "blocked": true,
        "blockers": [
            "owner-transfer/listen-socket-map handoff queue is recorded but not executed",
            "production tc/netns attach remains closed",
            "matched Go/Rust default daemon benchmark remains blocked",
            "default daemon and product-chain switches remain closed"
        ]
    });
    for key in [
        "stage160_listener_preflight_carried",
        "stage161_map_preflight_carried",
        "stage162_program_attach_preflight_carried",
        "owner_transfer_handoff_queue_recorded",
        "listen_socket_map_handoff_queue_recorded",
        "rollback_cleanup_order_recorded",
        "go_default_path_preserved",
        "go_fallback_required",
    ] {
        report[key] = json!(true);
    }
    for key in [
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
    report["handoff_rows"] = json!([
        {
            "area": "listener handoff",
            "carried_evidence": "Stage160 loopback TCP/UDP same-port listener smoke and listen_socket_map key contract",
            "next_required_evidence": "write temporary TCP fd to listen_socket_map key 0 and UDP fd to key 1 before ready in a non-production owner-transfer harness",
            "boundary": "Stage163 does not write any BPF map",
            "closed_flag": "production_listener_bound=false"
        },
        {
            "area": "BPF object owner transfer",
            "carried_evidence": "Stage161 temporary map create/update/lookup/pin/reopen/unlink smoke",
            "next_required_evidence": "model old-owner eject, new-owner inject, rollback cleanup, and incompatible pinned map cleanup under temporary objects",
            "boundary": "Stage163 does not transfer a live production BPF object",
            "closed_flag": "ebpf_attached=false"
        },
        {
            "area": "program attach handoff",
            "carried_evidence": "Stage162 temporary socket-filter program load/attach/detach smoke",
            "next_required_evidence": "prove attach/eject cleanup order on non-production attach targets before any tc/netns candidate",
            "boundary": "Stage163 does not attach tc/netns/qdisc hooks",
            "closed_flag": "production_tc_attach_smoke_passed=false"
        },
        {
            "area": "reload rollback order",
            "carried_evidence": "DAENEW memo 15.4 requires old EjectBpf -> new build -> InjectBpf -> current swap -> old Close -> scoped cleanup",
            "next_required_evidence": "encode and smoke this order with temporary listener/map/program handles",
            "boundary": "queue record is not reload execution evidence",
            "closed_flag": "benchmark_executable_now=false"
        },
        {
            "area": "default safety",
            "carried_evidence": "Go default path and outbound/quic-go dependency boundary remain preserved",
            "next_required_evidence": "matched benchmark after production-equivalent listener/eBPF evidence exists",
            "boundary": "no default or product-chain switch",
            "closed_flag": "default_switch_allowed=false"
        }
    ]);
    report["remaining_blockers"] = json!([
        "non-production owner-transfer/listen-socket-map handoff smoke has not executed",
        "production tc/netns attach remains closed",
        "matched Go/Rust default daemon benchmark has not executed",
        "true Rust default daemon admission remains false until matched benchmark data exists",
        "default daemon and product-chain switches remain closed"
    ]);
    report["next_admission_queue"] = json!([
        {
            "stage": "stage164",
            "target": "non-production BPF owner-transfer and listen socket map handoff smoke",
            "required_output": "compose temporary listener, map, and program handles into owner-transfer/listen_socket_map handoff smoke while preserving cleanup order"
        }
    ]);
    report["validation_commands"] = json!([
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage163/bpf_owner_transfer_listener_map_handoff_queue_gate.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage163_bpf_owner_transfer_listener_map_handoff_queue_gate.json",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage163-bpf-owner-transfer-listener-map-handoff-queue-gate",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage163 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage163 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage162 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli -p dae-product -q",
        "cargo fmt --manifest-path rust/Cargo.toml --all -- --check",
        "git diff --check"
    ]);
    report["source"] = json!([
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage163",
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage160",
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage161",
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage162",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.4",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.5"
    ]);
    report
}
