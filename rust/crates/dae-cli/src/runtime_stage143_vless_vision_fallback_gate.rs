use serde_json::{Value, json};

use crate::runner::RunnerOutput;

pub(crate) fn run_stage143_vless_vision_fallback_gate(args: &[String]) -> RunnerOutput {
    if let Some(arg) = args.first() {
        return RunnerOutput::usage(format!("unsupported stage143 argument: {arg}"));
    }
    RunnerOutput::ok(format!("{}\n", stage143_report()))
}

fn stage143_report() -> Value {
    let mut report = json!({
        "name": "stage143-vless-vision-intrinsic-conn-fallback-gate",
        "stage": "stage143",
        "evidence_class": "read-only-vless-vision-intrinsic-tls-reality-fallback-gate",
        "execute_smoke": false,
        "read_only": true,
        "blocked": false,
        "blockers": []
    });
    for key in [
        "vless_vision_go_fallback_admitted",
        "vless_vision_intrinsic_conn_go_fallback_required",
        "vless_reality_go_fallback_admitted",
        "vless_reality_full_handshake_go_fallback_required",
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
        "vless_vision_tls_reality_admitted",
        "vless_vision_tcp_dataplane_admitted",
        "vless_vision_udp_packet_conn_admitted",
        "vless_reality_full_handshake_admitted",
        "vless_utls_fingerprint_wire_admitted",
        "vmess_utls_fingerprint_wire_admitted",
        "vless_protocol_true_dataplane_admitted",
        "vmess_protocol_true_dataplane_admitted",
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
    report["fallback_decision"] = json!({
        "decision": "keep VLESS Vision intrinsic TLS/REALITY conn on Go outbound fallback",
        "required_intrinsic_conn_types": [
            "*tls.Conn",
            "*utls.UConn",
            "*tls.RealityUConn"
        ],
        "rust_missing_prerequisites": [
            "intrinsic TLS conn hook",
            "intrinsic uTLS conn hook",
            "intrinsic REALITY conn hook",
            "Vision TCP/UDP packet conn over intrinsic TLS/REALITY"
        ],
        "go_error_boundary": "XTLS only supports TLS and REALITY directly for now",
        "default_path_mutation_allowed": false,
        "product_switch_allowed": false
    });
    report["benchmark"] = json!({
        "benchmark_recorded": false,
        "network_benchmark_recorded": false,
        "reason": "Stage143 is a read-only Vision fallback decision gate",
        "matched_go_rust_default_daemon_benchmark_recorded": false
    });
    report["remaining_blockers"] = json!([
        "VLESS Vision requires intrinsic TLS/uTLS/REALITY conn access",
        "Rust ordinary stream wrapper cannot satisfy Vision",
        "VLESS REALITY full handshake remains on Go outbound fallback",
        "VLESS/VMess uTLS wire-level fingerprint admission remains closed",
        "VMess uTLS full-combination recertification is incomplete",
        "Trojan-Go full shared transport remains blocked",
        "shared_transport_true_dataplane and outbound_true_dataplane remain closed until all protocol rows close",
        "matched Go default daemon vs true Rust candidate benchmark remains missing",
        "default daemon and product-chain switches remain closed"
    ]);
    report["validation_commands"] = json!([
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage143/vless_vision_intrinsic_conn_fallback_gate.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage143_vless_vision_intrinsic_conn_fallback_gate.json",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage143-vless-vision-intrinsic-conn-fallback-gate",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage143 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage143 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage142 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound -p dae-cli -p dae-product -q",
        "cargo fmt --manifest-path rust/Cargo.toml --all -- --check",
        "git diff --check"
    ]);
    report["source"] = json!([
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage143",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.6",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.7",
        "/root/project/outbound/protocol/vless/dialer.go",
        "/root/project/outbound/protocol/vless/vision",
        "testdata/rebuild-golden/engine/runtime_stage142/vless_reality_full_handshake_fallback_gate.json"
    ]);
    report
}
