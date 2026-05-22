use super::smoke::{apply_stage136_outcome, run_stage136_smoke};
use super::*;

pub(super) fn stage136_report(opts: &Stage136Options) -> Value {
    let vless_key = match vless::password_to_key(&opts.vless_uuid) {
        Ok(key) => key,
        Err(err) => {
            return json!({
                "name": "stage136-vless-vmess-xhttp-http2-lifecycle-admission",
                "stage": "stage136",
                "blocked": true,
                "blockers": [format!("stage136 vless uuid is invalid: {err}")]
            });
        }
    };
    let vmess_cmd_key = match vmess::vmess_cmd_key_from_uuid(&opts.vmess_uuid) {
        Ok(key) => key,
        Err(err) => {
            return json!({
                "name": "stage136-vless-vmess-xhttp-http2-lifecycle-admission",
                "stage": "stage136",
                "blocked": true,
                "blockers": [format!("stage136 vmess uuid is invalid: {err}")]
            });
        }
    };
    let xhttp_options = match opts.xhttp_options_for_seq(opts.xhttp_seq) {
        Ok(options) => options,
        Err(err) => {
            return json!({
                "name": "stage136-vless-vmess-xhttp-http2-lifecycle-admission",
                "stage": "stage136",
                "blocked": true,
                "blockers": [format!("stage136 xhttp options invalid: {err}")]
            });
        }
    };
    let mut report = json!({
        "name": "stage136-vless-vmess-xhttp-http2-lifecycle-admission",
        "stage": "stage136",
        "evidence_class": "opt-in-protocol-vless-vmess-xhttp-http2-packet-up-lifecycle-true-dataplane-smoke",
        "execute_smoke": opts.execute_smoke,
        "read_only": !opts.execute_smoke,
        "blocked": false,
        "blockers": []
    });

    for key in [
        "socks5_protocol_true_dataplane_admitted",
        "http_connect_true_dataplane_admitted",
        "https_proxy_true_dataplane_admitted",
        "shadowsocks_protocol_true_dataplane_admitted",
        "trojan_protocol_true_dataplane_admitted",
        "anytls_true_dataplane_admitted",
        "hysteria2_true_quic_dataplane_admitted",
        "tuic_true_quic_dataplane_admitted",
        "juicity_true_quic_h3_dataplane_admitted",
        "quic_h3_family_true_dataplane_admitted",
        "trojan_go_shared_transport_partial_admitted",
        "vless_protocol_partial_admitted",
        "vmess_protocol_partial_admitted",
        "vless_grpc_http2_lifecycle_admitted",
        "vmess_grpc_http2_lifecycle_admitted",
        "vless_wss_tls_lifecycle_admitted",
        "vmess_wss_tls_lifecycle_admitted",
        "vless_https_httpupgrade_tls_lifecycle_admitted",
        "vmess_https_httpupgrade_tls_lifecycle_admitted",
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
        "vless_xhttp_http2_lifecycle_smoke_passed",
        "vmess_xhttp_http2_lifecycle_smoke_passed",
        "vless_vmess_xhttp_http2_lifecycle_smoke_passed",
        "vless_xhttp_http2_lifecycle_admitted",
        "vmess_xhttp_http2_lifecycle_admitted",
        "vless_xhttp_h2_h3_lifecycle_admitted",
        "vless_xhttp_h3_lifecycle_admitted",
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
    report["vless_vmess_xhttp_http2_contract"] = json!({
        "scope": "VLESS and VMess TCP payloads carried inside xHTTP packet-up DATA over HTTP/2 client preface, request SETTINGS/HEADERS/DATA, response SETTINGS ACK/HEADERS/DATA",
        "xhttp_host": xhttp_options.host,
        "xhttp_path": shared_transport::ir::normalize_xhttp_path_and_query(&xhttp_options.path).path,
        "xhttp_request_path": shared_transport::xhttp_request_path(&xhttp_options),
        "xhttp_mode": xhttp_options.mode,
        "xhttp_security": xhttp_options.security,
        "xhttp_alpn": xhttp_options.alpn,
        "xhttp_session_id": xhttp_options.session_id,
        "xhttp_seq": xhttp_options.seq,
        "http2_client_preface_required": true,
        "http2_settings_headers_data_required": true,
        "h2_packet_up_lifecycle": true,
        "h3_deferred": true,
        "tls_utls_reality_deferred": true,
        "download_settings_deferred": true,
        "stream_up_stream_one_deferred": true,
        "padding_placement_matrix_deferred": true,
        "default_go_path_preserved": true,
        "vless": {
            "protocol": "vless",
            "transport": "xhttp-http2-packet-up",
            "target": opts.vless_target,
            "uuid_key_hex": hex_encode(&vless_key),
            "payload_ascii": String::from_utf8_lossy(&opts.vless_payload).to_string(),
            "payload_len": opts.vless_payload.len(),
            "request_header_len": null,
            "response_header_len": null,
            "xhttp_request_body_len": null,
            "xhttp_response_body_len": null,
            "http2_lifecycle_validated": false,
            "payload_roundtrip_validated": false
        },
        "vmess": {
            "protocol": "vmess",
            "transport": "xhttp-http2-packet-up",
            "target": opts.vmess_target,
            "uuid": opts.vmess_uuid,
            "cmd_key_hex": hex_encode(&vmess_cmd_key),
            "security": "auto/aes-128-gcm",
            "security_byte": vmess::VMESS_AEAD_SECURITY_AES_128_GCM,
            "payload_ascii": String::from_utf8_lossy(&opts.vmess_payload).to_string(),
            "payload_len": opts.vmess_payload.len(),
            "request_header_len": null,
            "request_chunk_len": null,
            "response_header_len": null,
            "response_chunk_len": null,
            "xhttp_request_body_len": null,
            "xhttp_response_body_len": null,
            "http2_lifecycle_validated": false,
            "payload_roundtrip_validated": false,
            "reality_rejected_for_vmess": true
        }
    });
    report["benchmark"] = json!({
        "benchmark_recorded": false,
        "iterations_per_protocol": opts.benchmark_iters,
        "total_exchange_count": opts.benchmark_iters * 2,
        "elapsed_ns": null,
        "ns_per_vless_vmess_xhttp_http2_exchange": null,
        "scope": "local UnixStream loopback carrying VLESS TCP and VMess AEAD TCP payloads over xHTTP packet-up DATA over the shared HTTP/2 lifecycle helper; H3, TLS/uTLS/REALITY/Vision and matched Go default daemon baselines remain out of scope",
        "go_matched_default_daemon_baseline_recorded": false
    });
    report["protocol_matrix"] = json!({
        "vless_grpc_http2_lifecycle_admitted": true,
        "vmess_grpc_http2_lifecycle_admitted": true,
        "vless_wss_tls_lifecycle_admitted": true,
        "vmess_wss_tls_lifecycle_admitted": true,
        "vless_https_httpupgrade_tls_lifecycle_admitted": true,
        "vmess_https_httpupgrade_tls_lifecycle_admitted": true,
        "vless_xhttp_http2_lifecycle_admitted": false,
        "vmess_xhttp_http2_lifecycle_admitted": false,
        "vless_xhttp_h3_lifecycle_admitted": false,
        "vless_xhttp_h2_h3_lifecycle_admitted": false,
        "vless_protocol_true_dataplane_admitted": false,
        "vmess_protocol_true_dataplane_admitted": false,
        "trojan_go_shared_transport_admitted": false,
        "shared_transport_true_dataplane_admitted": false,
        "outbound_true_dataplane_admitted": false
    });
    report["remaining_blockers"] = json!([
        "VLESS xHTTP H3, uTLS fingerprint, REALITY full handshake, XTLS Vision, and protocol-wide recertification remain separate blockers",
        "VMess uTLS full-combination and protocol-wide recertification remain separate blockers",
        "Trojan-Go full shared transport remains blocked",
        "shared_transport_true_dataplane and outbound_true_dataplane remain closed until all protocol rows close",
        "matched Go default daemon vs true Rust candidate benchmark remains missing",
        "default daemon and product-chain switches remain closed"
    ]);
    report["validation_commands"] = json!([
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage136/vless_vmess_xhttp_http2_lifecycle_admission.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage136_vless_vmess_xhttp_http2_lifecycle_gate.json",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound stage136 -- --nocapture",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage136-vless-vmess-xhttp-http2-lifecycle-admission",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage136-vless-vmess-xhttp-http2-lifecycle-admission --execute-smoke --benchmark-iters 3",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage136 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage136 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage135 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound -p dae-cli -p dae-product -q",
        "cargo fmt --manifest-path rust/Cargo.toml --all -- --check",
        "git diff --check"
    ]);
    report["source"] = json!([
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage136",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.4",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.5",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.8",
        "rust/crates/dae-outbound/src/shared_transport/xhttp.rs",
        "rust/crates/dae-outbound/src/vless/dataplane/xhttp_http2.rs",
        "rust/crates/dae-outbound/src/vmess/dataplane/xhttp_http2.rs"
    ]);

    if !opts.execute_smoke {
        return report;
    }
    match run_stage136_smoke(opts) {
        Ok(outcome) => apply_stage136_outcome(&mut report, outcome),
        Err(err) => {
            report["blocked"] = json!(true);
            report["blockers"] = json!([err]);
        }
    }
    report
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}
