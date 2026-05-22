use serde_json::{Value, json};

use crate::runner::RunnerOutput;

pub(crate) fn run_stage146_shared_transport_outbound_recertification_gate(
    args: &[String],
) -> RunnerOutput {
    if let Some(arg) = args.first() {
        return RunnerOutput::usage(format!("unsupported stage146 argument: {arg}"));
    }
    RunnerOutput::ok(format!("{}\n", stage146_report()))
}

fn stage146_report() -> Value {
    let mut report = json!({
        "name": "stage146-shared-transport-outbound-fallback-aware-recertification-gate",
        "stage": "stage146",
        "evidence_class": "read-only-shared-transport-outbound-fallback-aware-recertification-gate",
        "execute_smoke": false,
        "read_only": true,
        "blocked": false,
        "blockers": []
    });
    for key in [
        "shared_transport_fallback_aware_recertified",
        "outbound_fallback_aware_recertified",
        "fallback_dependency_policy_recorded",
        "vless_vmess_fallback_aware_recertified",
        "trojan_go_fallback_aware_recertified",
        "quic_h3_family_true_dataplane_admitted",
        "outbound_quic_go_dependency_preserved",
        "external_outbound_required",
        "external_quic_go_required",
        "go_default_path_preserved",
        "go_fallback_required",
        "protocol_outbound_partial_admitted",
    ] {
        report[key] = json!(true);
    }
    for key in [
        "vless_protocol_true_dataplane_admitted",
        "vmess_protocol_true_dataplane_admitted",
        "trojan_go_shared_transport_admitted",
        "vless_reality_full_handshake_admitted",
        "vless_vision_tls_reality_admitted",
        "vless_utls_fingerprint_wire_admitted",
        "vmess_utls_fingerprint_wire_admitted",
        "trojan_go_utls_fingerprint_wire_admitted",
        "trojan_go_reality_mutation_admitted",
        "trojan_go_cross_combination_recertified",
        "shared_transport_true_dataplane_admitted",
        "outbound_true_dataplane_admitted",
        "matched_go_rust_default_daemon_benchmark_recorded",
        "default_switch_allowed",
        "default_path_mutation_allowed",
        "product_chain_switch_allowed",
        "true_rust_default_daemon_admitted",
    ] {
        report[key] = json!(false);
    }
    report["recertification_matrix"] = json!({
        "completed_true_dataplane_rows": [
            "base proxy protocols",
            "Shadowsocks/SS2022/SIP003/SSR family",
            "standard Trojan",
            "AnyTLS",
            "Hysteria2/TUIC/Juicity QUIC/H3 family"
        ],
        "fallback_aware_rows": [
            "VLESS/VMess shared transport residuals",
            "Trojan-Go shared transport residuals",
            "shared_transport/outbound dependency policy"
        ],
        "go_fallback_rows": [
            "VLESS REALITY full handshake",
            "VLESS Vision intrinsic TLS/REALITY conn",
            "VLESS/VMess uTLS wire-level ClientHello",
            "Trojan-Go full shared transport cross-combinations",
            "Trojan-Go uTLS wire-level ClientHello",
            "Trojan-Go REALITY/full uTLS mutation"
        ],
        "default_switch_allowed": false,
        "product_switch_allowed": false
    });
    report["fallback_dependency_policy"] = json!({
        "preserve_external_outbound": "/root/project/outbound",
        "preserve_external_quic_go": "/root/project/quic-go",
        "go_default_path_preserved": true,
        "rust_default_path_mutation_allowed": false,
        "fallback_can_satisfy_recertification": true,
        "fallback_cannot_satisfy_true_rust_default": true
    });
    report["benchmark"] = json!({
        "benchmark_recorded": false,
        "network_benchmark_recorded": false,
        "reason": "Stage146 is a read-only fallback-aware recertification gate; matched Go/Rust default daemon benchmark is still blocked",
        "matched_go_rust_default_daemon_benchmark_recorded": false
    });
    report["remaining_blockers"] = json!([
        "VLESS and VMess true Rust protocol-wide admission remain closed by uTLS/REALITY/Vision fallback rows",
        "Trojan-Go true shared transport remains closed by uTLS wire, REALITY/full mutation, and cross-combination fallback rows",
        "shared_transport_true_dataplane and outbound_true_dataplane remain closed because this stage records fallback-aware policy only",
        "matched Go default daemon vs true Rust candidate benchmark remains missing",
        "default daemon and product-chain switches remain closed"
    ]);
    report["next_admission_queue"] = json!([
        {
            "stage": "stage147",
            "target": "default daemon benchmark readiness",
            "required_output": "record a matched Go default daemon vs fallback-aware Rust candidate benchmark without opening default_switch_allowed"
        },
        {
            "stage": "stage148",
            "target": "product-chain fallback-aware admission queue",
            "required_output": "carry external outbound/quic-go dependency policy into dae-wing and daed without default mutation"
        },
        {
            "stage": "future-true-rust-dataplane",
            "target": "replace fallback rows with true Rust implementations",
            "required_output": "only then reconsider shared_transport_true_dataplane_admitted and outbound_true_dataplane_admitted"
        }
    ]);
    report["validation_commands"] = json!([
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage146/shared_transport_outbound_fallback_aware_recertification_gate.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage146_shared_transport_outbound_fallback_aware_recertification_gate.json",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage146-shared-transport-outbound-fallback-aware-recertification-gate",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage146 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage146 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage145 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound -p dae-cli -p dae-product -q",
        "cargo fmt --manifest-path rust/Cargo.toml --all -- --check",
        "git diff --check"
    ]);
    report["source"] = json!([
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage146",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.7",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.8",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.11",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.18",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.20",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.21",
        "testdata/rebuild-golden/engine/runtime_stage132/quic_h3_family_recertification_admission.json",
        "testdata/rebuild-golden/engine/runtime_stage144/vless_vmess_fallback_aware_recertification_gate.json",
        "testdata/rebuild-golden/engine/runtime_stage145/trojan_go_fallback_aware_recertification_gate.json"
    ]);
    report
}
