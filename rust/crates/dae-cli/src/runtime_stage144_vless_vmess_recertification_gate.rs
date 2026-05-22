use serde_json::{Value, json};

use crate::runner::RunnerOutput;

pub(crate) fn run_stage144_vless_vmess_recertification_gate(args: &[String]) -> RunnerOutput {
    if let Some(arg) = args.first() {
        return RunnerOutput::usage(format!("unsupported stage144 argument: {arg}"));
    }
    RunnerOutput::ok(format!("{}\n", stage144_report()))
}

fn stage144_report() -> Value {
    let mut report = json!({
        "name": "stage144-vless-vmess-fallback-aware-recertification-gate",
        "stage": "stage144",
        "evidence_class": "read-only-vless-vmess-fallback-aware-recertification-gate",
        "execute_smoke": false,
        "read_only": true,
        "blocked": false,
        "blockers": []
    });
    for key in [
        "vless_vmess_fallback_aware_recertified",
        "vless_reality_go_fallback_admitted",
        "vless_reality_full_handshake_go_fallback_required",
        "vless_vision_go_fallback_admitted",
        "vless_vision_intrinsic_conn_go_fallback_required",
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
        "vless_reality_full_handshake_admitted",
        "vless_vision_tls_reality_admitted",
        "vless_utls_fingerprint_wire_admitted",
        "vmess_utls_fingerprint_wire_admitted",
        "trojan_go_shared_transport_admitted",
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
        "rust_completed_rows": [
            "VLESS/VMess gRPC HTTP/2 lifecycle",
            "VLESS/VMess WSS TLS lifecycle",
            "VLESS/VMess HTTPS HTTPUpgrade TLS lifecycle",
            "VLESS/VMess xHTTP HTTP/2 lifecycle",
            "VLESS/VMess xHTTP H3 lifecycle",
            "Go uTLS profile fixture/parser",
            "synthetic uTLS profile builder",
            "synthetic REALITY raw mutation harness"
        ],
        "go_fallback_rows": [
            "VLESS REALITY full handshake",
            "VLESS REALITY VerifyPeerCertificate",
            "VLESS REALITY spider fallback",
            "VLESS Vision intrinsic TLS/REALITY conn"
        ],
        "still_blocking_true_rust_protocol_wide": [
            "uTLS wire-level ClientHello emission is not a true handshake",
            "REALITY full handshake is Go fallback",
            "Vision intrinsic conn is Go fallback",
            "VMess uTLS full-combination recertification remains fallback-bound"
        ],
        "default_switch_allowed": false,
        "product_switch_allowed": false
    });
    report["benchmark"] = json!({
        "benchmark_recorded": false,
        "network_benchmark_recorded": false,
        "reason": "Stage144 recertifies fallback boundaries only; default daemon benchmark remains blocked",
        "matched_go_rust_default_daemon_benchmark_recorded": false
    });
    report["remaining_blockers"] = json!([
        "VLESS/VMess true Rust protocol-wide admission remains closed because residual uTLS/REALITY/Vision rows are fallback-bound",
        "Trojan-Go full shared transport remains blocked",
        "shared_transport_true_dataplane and outbound_true_dataplane remain closed until all protocol rows close",
        "matched Go default daemon vs true Rust candidate benchmark remains missing",
        "default daemon and product-chain switches remain closed"
    ]);
    report["validation_commands"] = json!([
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage144/vless_vmess_fallback_aware_recertification_gate.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage144_vless_vmess_fallback_aware_recertification_gate.json",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage144-vless-vmess-fallback-aware-recertification-gate",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage144 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage144 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage143 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound -p dae-cli -p dae-product -q",
        "cargo fmt --manifest-path rust/Cargo.toml --all -- --check",
        "git diff --check"
    ]);
    report["source"] = json!([
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage144",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.5",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.6",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.7",
        "testdata/rebuild-golden/engine/runtime_stage142/vless_reality_full_handshake_fallback_gate.json",
        "testdata/rebuild-golden/engine/runtime_stage143/vless_vision_intrinsic_conn_fallback_gate.json"
    ]);
    report
}
