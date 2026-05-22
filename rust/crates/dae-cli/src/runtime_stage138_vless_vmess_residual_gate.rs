use dae_outbound::shared_transport;
use serde_json::{Value, json};

use crate::runner::RunnerOutput;

pub(crate) fn run_stage138_vless_vmess_utls_reality_vision_blocker_gate(
    args: &[String],
) -> RunnerOutput {
    if let Some(arg) = args.first() {
        return RunnerOutput::usage(format!("unsupported stage138 argument: {arg}"));
    }
    RunnerOutput::ok(format!("{}\n", stage138_report()))
}

fn stage138_report() -> Value {
    let mut report = json!({
        "name": "stage138-vless-vmess-utls-reality-vision-blocker-gate",
        "stage": "stage138",
        "evidence_class": "read-only-vless-vmess-utls-reality-vision-residual-blocker-gate",
        "execute_smoke": false,
        "read_only": true,
        "blocked": true,
        "blockers": [
            "VLESS/VMess uTLS wire-level ClientHello parity is not implemented by rustls",
            "VLESS REALITY full uTLS handshake and VerifyPeerCertificate path remain incomplete",
            "VLESS XTLS Vision requires intrinsic TLS/REALITY conn hooks not provided by current Rust path",
            "VLESS/VMess protocol-wide true dataplane cannot open before those rows close"
        ]
    });
    for key in [
        "vless_grpc_http2_lifecycle_admitted",
        "vmess_grpc_http2_lifecycle_admitted",
        "vless_wss_tls_lifecycle_admitted",
        "vmess_wss_tls_lifecycle_admitted",
        "vless_https_httpupgrade_tls_lifecycle_admitted",
        "vmess_https_httpupgrade_tls_lifecycle_admitted",
        "vless_xhttp_http2_lifecycle_admitted",
        "vmess_xhttp_http2_lifecycle_admitted",
        "vless_xhttp_h3_lifecycle_admitted",
        "vmess_xhttp_h3_lifecycle_admitted",
        "vless_xhttp_h2_h3_lifecycle_admitted",
        "vmess_xhttp_h2_h3_lifecycle_admitted",
        "vless_protocol_partial_admitted",
        "vmess_protocol_partial_admitted",
        "protocol_outbound_partial_admitted",
        "outbound_quic_go_dependency_preserved",
        "external_outbound_required",
        "external_quic_go_required",
        "go_default_path_preserved",
        "go_fallback_required",
    ] {
        report[key] = json!(true);
    }
    for key in [
        "vless_utls_fingerprint_wire_admitted",
        "vmess_utls_fingerprint_wire_admitted",
        "vless_reality_full_handshake_admitted",
        "vless_vision_tls_reality_admitted",
        "vless_protocol_true_dataplane_admitted",
        "vmess_protocol_true_dataplane_admitted",
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
    report["completed_vless_vmess_rows"] = json!({
        "stage134_grpc_http2": {
            "vless_grpc_http2_lifecycle_admitted": true,
            "vmess_grpc_http2_lifecycle_admitted": true
        },
        "stage135_tls_transports": {
            "vless_wss_tls_lifecycle_admitted": true,
            "vmess_wss_tls_lifecycle_admitted": true,
            "vless_https_httpupgrade_tls_lifecycle_admitted": true,
            "vmess_https_httpupgrade_tls_lifecycle_admitted": true
        },
        "stage136_xhttp_http2": {
            "vless_xhttp_http2_lifecycle_admitted": true,
            "vmess_xhttp_http2_lifecycle_admitted": true
        },
        "stage137_xhttp_h3_tls": {
            "vless_xhttp_h3_lifecycle_admitted": true,
            "vmess_xhttp_h3_lifecycle_admitted": true,
            "vless_xhttp_h2_h3_lifecycle_admitted": true,
            "vmess_xhttp_h2_h3_lifecycle_admitted": true
        }
    });
    report["residual_blocker_matrix"] = json!({
        "utls": {
            "supported_name_count": shared_transport::supported_utls_fingerprint_count(),
            "selection_mapping_admitted": true,
            "wire_stack_deferred": shared_transport::U_TLS_WIRE_STACK_DEFERRED,
            "rustls_is_not_utls": true,
            "vless_utls_fingerprint_wire_admitted": false,
            "vmess_utls_fingerprint_wire_admitted": false,
            "required_next": "select or implement a Rust uTLS-compatible ClientHello wire stack matching outbound/transport/tls/utls.go"
        },
        "reality": {
            "session_id_aead_mutation_admitted": true,
            "full_utls_handshake_admitted": false,
            "verify_peer_certificate_admitted": false,
            "spider_fallback_admitted": false,
            "required_next": "wire session-id mutation into full uTLS handshake state and verify REALITY certificate/signature behavior"
        },
        "vision": {
            "flow_parser_contract_admitted": true,
            "intrinsic_tls_reality_conn_hook_admitted": false,
            "tcp_vision_dataplane_admitted": false,
            "udp_vision_packet_conn_admitted": false,
            "required_next": "provide a TLS/REALITY intrinsic conn hook equivalent before wrapping VLESS Vision"
        },
        "protocol_wide": {
            "vless_protocol_true_dataplane_admitted": false,
            "vmess_protocol_true_dataplane_admitted": false,
            "shared_transport_true_dataplane_admitted": false,
            "outbound_true_dataplane_admitted": false
        }
    });
    report["implementation_admission_queue"] = json!([
        {
            "order": 1,
            "target": "Rust uTLS-compatible ClientHello wire stack",
            "required_outputs": [
                "vless_utls_fingerprint_wire_admitted=true",
                "vmess_utls_fingerprint_wire_admitted=true",
                "wire-level ClientHello fixture comparison against Go uTLS for supported deterministic fingerprints"
            ]
        },
        {
            "order": 2,
            "target": "VLESS REALITY full handshake",
            "required_outputs": [
                "vless_reality_full_handshake_admitted=true",
                "session id mutation applied to actual ClientHello Raw bytes",
                "VerifyPeerCertificate and spider fallback behavior covered"
            ]
        },
        {
            "order": 3,
            "target": "VLESS XTLS Vision intrinsic conn hook",
            "required_outputs": [
                "vless_vision_tls_reality_admitted=true",
                "Vision TCP and UDP packet conn smoke over TLS/REALITY intrinsic connection"
            ]
        },
        {
            "order": 4,
            "target": "VLESS/VMess protocol-wide recertification",
            "required_outputs": [
                "vless_protocol_true_dataplane_admitted=true",
                "vmess_protocol_true_dataplane_admitted=true",
                "shared_transport_true_dataplane admission can be reconsidered after Trojan-Go closure"
            ]
        }
    ]);
    report["benchmark"] = json!({
        "benchmark_recorded": false,
        "reason": "Stage138 is a read-only residual blocker gate; recording a new network benchmark would imply a uTLS/REALITY/Vision implementation that is not present",
        "stage137_h3_benchmark_carried_forward": {
            "iterations_per_protocol": 2,
            "total_exchange_count": 4,
            "ns_per_vless_vmess_xhttp_h3_exchange": 94782572.75
        },
        "matched_go_rust_default_daemon_benchmark_recorded": false
    });
    report["remaining_blockers"] = json!([
        "VLESS/VMess uTLS wire-level ClientHello parity needs a real uTLS-compatible Rust wire stack or explicit Go fallback decision",
        "VLESS REALITY full uTLS handshake, VerifyPeerCertificate, and spider fallback are incomplete",
        "VLESS XTLS Vision intrinsic TLS/REALITY conn hook is incomplete",
        "VMess uTLS full-combination recertification is incomplete",
        "Trojan-Go full shared transport remains blocked",
        "shared_transport_true_dataplane and outbound_true_dataplane remain closed until all protocol rows close",
        "matched Go default daemon vs true Rust candidate benchmark remains missing",
        "default daemon and product-chain switches remain closed"
    ]);
    report["validation_commands"] = json!([
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage138/vless_vmess_utls_reality_vision_blocker_gate.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage138_vless_vmess_utls_reality_vision_blocker_gate.json",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage138-vless-vmess-utls-reality-vision-blocker-gate",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage138 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage138 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage137 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound -p dae-cli -p dae-product -q",
        "cargo fmt --manifest-path rust/Cargo.toml --all -- --check",
        "git diff --check"
    ]);
    report["source"] = json!([
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage138",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.6",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.7",
        "/root/project/outbound/transport/tls/utls.go",
        "rust/crates/dae-outbound/src/shared_transport/utls_fingerprint.rs",
        "rust/crates/dae-outbound/src/shared_transport/reality_aead.rs",
        "rust/crates/dae-product/src/stage137_vless_vmess_xhttp_h3_gate.rs"
    ]);
    report
}
