use super::smoke::{apply_stage134_outcome, run_stage134_smoke};
use super::*;

pub(super) fn stage134_report(opts: &Stage134Options) -> Value {
    let vless_key = match vless::password_to_key(&opts.vless_uuid) {
        Ok(key) => key,
        Err(err) => {
            return json!({
                "name": "stage134-vless-vmess-grpc-http2-lifecycle-admission",
                "stage": "stage134",
                "blocked": true,
                "blockers": [format!("stage134 vless uuid is invalid: {err}")]
            });
        }
    };
    let vmess_cmd_key = match vmess::vmess_cmd_key_from_uuid(&opts.vmess_uuid) {
        Ok(key) => key,
        Err(err) => {
            return json!({
                "name": "stage134-vless-vmess-grpc-http2-lifecycle-admission",
                "stage": "stage134",
                "blocked": true,
                "blockers": [format!("stage134 vmess uuid is invalid: {err}")]
            });
        }
    };
    let grpc_options = opts.grpc_options(&opts.grpc_address);
    let service_name = shared_transport::GrpcHttp2LifecycleOptions {
        authority: opts.grpc_address.clone(),
        service_name: opts.grpc_service_name.clone(),
    }
    .service_name_or_default();
    let mut report = json!({
        "name": "stage134-vless-vmess-grpc-http2-lifecycle-admission",
        "stage": "stage134",
        "evidence_class": "opt-in-protocol-vless-vmess-grpc-http2-lifecycle-true-dataplane-smoke",
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
        "vmess_protocol_partial_admitted",
        "vless_protocol_partial_admitted",
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
        "vless_grpc_http2_lifecycle_smoke_passed",
        "vmess_grpc_http2_lifecycle_smoke_passed",
        "vless_vmess_grpc_http2_lifecycle_smoke_passed",
        "vless_grpc_http2_lifecycle_admitted",
        "vmess_grpc_http2_lifecycle_admitted",
        "vless_tls_utls_reality_vision_admitted",
        "vmess_tls_utls_wss_admitted",
        "vless_xhttp_h2_h3_lifecycle_admitted",
        "vmess_xhttp_h2_lifecycle_admitted",
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
    report["vless_vmess_grpc_http2_contract"] = json!({
        "scope": "VLESS and VMess TCP payloads carried inside gRPC Hunk DATA over HTTP/2 client preface, request SETTINGS/HEADERS/DATA, response SETTINGS ACK/HEADERS/DATA",
        "grpc_address": opts.grpc_address,
        "grpc_service_name": service_name,
        "grpc_service_name_input": opts.grpc_service_name,
        "grpc_server_name": opts.grpc_server_name,
        "grpc_dialer_id": opts.grpc_dialer_id,
        "grpc_allow_insecure": opts.allow_insecure,
        "grpc_cache_key": grpc_options.cache_key(),
        "so_mark_carried": opts.so_mark,
        "mptcp_carried": opts.mptcp,
        "http2_client_preface_required": true,
        "http2_settings_headers_data_required": true,
        "full_tls_lifecycle": false,
        "tls_utls_reality_deferred": true,
        "xhttp_h2_h3_deferred": true,
        "vision_deferred": true,
        "default_go_path_preserved": true,
        "vless": {
            "protocol": "vless",
            "transport": "grpc-http2",
            "target": opts.vless_target,
            "uuid_key_hex": hex_encode(&vless_key),
            "payload_ascii": String::from_utf8_lossy(&opts.vless_payload).to_string(),
            "payload_len": opts.vless_payload.len(),
            "grpc_cache_key": grpc_options.cache_key(),
            "request_header_len": null,
            "response_header_len": null,
            "request_hunk_len": null,
            "response_hunk_len": null,
            "http2_lifecycle_validated": false,
            "payload_roundtrip_validated": false
        },
        "vmess": {
            "protocol": "vmess",
            "transport": "grpc-http2",
            "target": opts.vmess_target,
            "uuid": opts.vmess_uuid,
            "cmd_key_hex": hex_encode(&vmess_cmd_key),
            "security": "auto/aes-128-gcm",
            "security_byte": vmess::VMESS_AEAD_SECURITY_AES_128_GCM,
            "payload_ascii": String::from_utf8_lossy(&opts.vmess_payload).to_string(),
            "payload_len": opts.vmess_payload.len(),
            "grpc_cache_key": grpc_options.cache_key(),
            "request_header_len": null,
            "request_chunk_len": null,
            "response_header_len": null,
            "response_chunk_len": null,
            "request_hunk_len": null,
            "response_hunk_len": null,
            "http2_lifecycle_validated": false,
            "payload_roundtrip_validated": false
        }
    });
    report["benchmark"] = json!({
        "benchmark_recorded": false,
        "iterations_per_protocol": opts.benchmark_iters,
        "total_exchange_count": opts.benchmark_iters * 2,
        "elapsed_ns": null,
        "ns_per_vless_vmess_grpc_http2_exchange": null,
        "scope": "local UnixStream loopback carrying VLESS TCP and VMess AEAD TCP payloads over gRPC Hunk DATA over the shared HTTP/2 lifecycle helper; TLS/uTLS/REALITY and matched Go default daemon baselines remain out of scope",
        "go_matched_default_daemon_baseline_recorded": false
    });
    report["protocol_matrix"] = json!({
        "vmess_raw_mux_ws_httpupgrade_grpc_hunk_meek_http_partial_admitted": true,
        "vless_raw_mux_ws_httpupgrade_grpc_hunk_meek_http_xhttp_partial_admitted": true,
        "vless_grpc_http2_lifecycle_admitted": false,
        "vmess_grpc_http2_lifecycle_admitted": false,
        "vless_protocol_true_dataplane_admitted": false,
        "vmess_protocol_true_dataplane_admitted": false,
        "trojan_go_shared_transport_admitted": false,
        "shared_transport_true_dataplane_admitted": false,
        "outbound_true_dataplane_admitted": false
    });
    report["remaining_blockers"] = json!([
        "VLESS TLS/uTLS/REALITY/XTLS Vision and xHTTP H2/H3 lifecycle remain separate blockers",
        "VMess TLS/uTLS/WSS/xHTTP/H2 and protocol-wide recertification remain separate blockers",
        "Trojan-Go uTLS wire-level ClientHello, full REALITY/uTLS handshake, and cross-combination recertification remain blocked",
        "shared_transport_true_dataplane and outbound_true_dataplane remain closed until all protocol rows close",
        "matched Go default daemon vs true Rust candidate benchmark remains missing",
        "default daemon and product-chain switches remain closed"
    ]);
    report["validation_commands"] = json!([
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage134/vless_vmess_grpc_http2_lifecycle_admission.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage134_vless_vmess_grpc_http2_lifecycle_gate.json",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound stage134 -- --nocapture",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage134-vless-vmess-grpc-http2-lifecycle-admission",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage134-vless-vmess-grpc-http2-lifecycle-admission --execute-smoke --benchmark-iters 3",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage134 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage134 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage133 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound -p dae-cli -p dae-product -q",
        "cargo fmt --manifest-path rust/Cargo.toml --all -- --check",
        "git diff --check"
    ]);
    report["source"] = json!([
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage134",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.4",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.5",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.7",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.8",
        "rust/crates/dae-outbound/src/shared_transport/grpc_http2.rs",
        "rust/crates/dae-outbound/src/vless/dataplane/grpc_http2.rs",
        "rust/crates/dae-outbound/src/vmess/dataplane/grpc_http2.rs"
    ]);

    if !opts.execute_smoke {
        return report;
    }
    match run_stage134_smoke(opts) {
        Ok(outcome) => apply_stage134_outcome(&mut report, outcome),
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
