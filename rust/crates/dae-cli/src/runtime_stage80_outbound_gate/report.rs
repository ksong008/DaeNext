use super::smoke::{apply_stage80_outcome, run_stage80_smoke};
use super::utils::*;
use super::*;

pub(super) fn stage80_report(opts: &Stage80Options) -> Value {
    let key = match vless::password_to_key(&opts.uuid) {
        Ok(key) => key,
        Err(err) => {
            return json!({
                "name": "stage80-vless-xhttp-xmux-dataplane-admission",
                "stage": "stage80",
                "blocked": true,
                "blockers": [format!("stage80 uuid is invalid: {err}")]
            });
        }
    };
    if let Err(err) = dae_outbound::VMessMetadata::parse("tcp", &opts.target) {
        return json!({
            "name": "stage80-vless-xhttp-xmux-dataplane-admission",
            "stage": "stage80",
            "blocked": true,
            "blockers": [format!("stage80 target is invalid: {err}")]
        });
    }
    let xhttp_options = match opts.xhttp_options() {
        Ok(options) => options,
        Err(err) => {
            return json!({
                "name": "stage80-vless-xhttp-xmux-dataplane-admission",
                "stage": "stage80",
                "blocked": true,
                "blockers": [format!("stage80 xhttp options invalid: {err}")]
            });
        }
    };
    let payload_ascii = String::from_utf8_lossy(&opts.payload).to_string();
    let mut report = json!({
        "name": "stage80-vless-xhttp-xmux-dataplane-admission",
        "stage": "stage80",
        "evidence_class": "opt-in-protocol-vless-xhttp-xmux-shared-transport-true-dataplane-smoke",
        "execute_smoke": opts.execute_smoke,
        "read_only": !opts.execute_smoke,
        "blocked": false,
        "blockers": []
    });
    report["socks5_protocol_true_dataplane_admitted"] = json!(true);
    report["http_connect_true_dataplane_admitted"] = json!(true);
    report["shadowsocks_aead_protocol_true_dataplane_admitted"] = json!(true);
    report["trojanc_tcp_true_dataplane_admitted"] = json!(true);
    report["trojan_udp_over_tcp_admitted"] = json!(true);
    report["trojan_protocol_true_dataplane_admitted"] = json!(false);
    report["vless_tcp_raw_true_dataplane_admitted"] = json!(true);
    report["vless_udp_over_tcp_admitted"] = json!(true);
    report["vless_mux_admitted"] = json!(true);
    report["vless_websocket_admitted"] = json!(true);
    report["vless_httpupgrade_admitted"] = json!(true);
    report["vless_grpc_hunk_admitted"] = json!(true);
    report["vless_grpc_full_http2_admitted"] = json!(false);
    report["vless_meek_polling_admitted"] = json!(true);
    report["vless_meek_full_https_roundtripper_admitted"] = json!(false);
    report["vless_http_transport_put_admitted"] = json!(true);
    report["vless_http_h2_full_admitted"] = json!(false);
    report["vless_xhttp_xmux_smoke_passed"] = json!(false);
    report["vless_xhttp_admitted"] = json!(true);
    report["vless_xhttp_xmux_admitted"] = json!(false);
    report["vless_shared_transport_partial_admitted"] = json!(true);
    report["vless_protocol_partial_admitted"] = json!(true);
    report["vless_protocol_true_dataplane_admitted"] = json!(false);
    report["vless_tls_underlay_admitted"] = json!(false);
    report["vless_reality_underlay_admitted"] = json!(false);
    report["vless_vision_admitted"] = json!(false);
    report["vless_shared_transport_admitted"] = json!(false);
    report["vmess_aead_tcp_true_dataplane_admitted"] = json!(true);
    report["vmess_aead_udp_over_tcp_admitted"] = json!(true);
    report["vmess_udp_packet_addr_admitted"] = json!(true);
    report["vmess_mux_admitted"] = json!(true);
    report["vmess_websocket_admitted"] = json!(true);
    report["vmess_httpupgrade_admitted"] = json!(true);
    report["vmess_grpc_hunk_admitted"] = json!(true);
    report["vmess_grpc_full_http2_admitted"] = json!(false);
    report["vmess_meek_polling_admitted"] = json!(true);
    report["vmess_meek_full_https_roundtripper_admitted"] = json!(false);
    report["vmess_http_transport_put_admitted"] = json!(true);
    report["vmess_http_h2_full_admitted"] = json!(false);
    report["vmess_shared_transport_partial_admitted"] = json!(true);
    report["vmess_protocol_partial_admitted"] = json!(true);
    report["vmess_protocol_true_dataplane_admitted"] = json!(false);
    report["vmess_tls_underlay_admitted"] = json!(false);
    report["vmess_shared_transport_admitted"] = json!(false);
    report["ss2022_true_dataplane_admitted"] = json!(false);
    report["protocol_outbound_partial_admitted"] = json!(true);
    report["outbound_true_dataplane_admitted"] = json!(false);
    report["matched_go_rust_default_daemon_benchmark_recorded"] = json!(false);
    report["default_switch_allowed"] = json!(false);
    report["default_path_mutation_allowed"] = json!(false);
    report["product_chain_switch_allowed"] = json!(false);
    report["true_rust_default_daemon_admitted"] = json!(false);
    report["go_default_path_preserved"] = json!(true);
    report["go_fallback_required"] = json!(true);
    report["server_observation"] = json!(null);
    report["vless_xhttp_contract"] = json!({
        "protocol": "vless",
        "scope": "VLESS TCP request/response carried by xHTTP packet-up POST body with xmux options over a Rust TCP stream",
        "uuid": opts.uuid,
        "key_hex": hex_encode(&key),
        "network": "tcp",
        "underlay_network": "tcp",
        "transport": "xhttp-xmux-packet-up",
        "target": opts.target,
        "xhttp_host": xhttp_options.host,
        "xhttp_path": normalize_xhttp_path(&xhttp_options.path),
        "xhttp_request_path": shared_transport::xhttp_request_path(&xhttp_options),
        "xhttp_mode": xhttp_options.mode,
        "xhttp_security": xhttp_options.security,
        "xhttp_alpn": xhttp_options.alpn,
        "xhttp_session_id": xhttp_options.session_id,
        "xhttp_seq": xhttp_options.seq,
        "xhttp_packet_up_validated": false,
        "xhttp_xmux_enabled": true,
        "xmux_max_connections": opts.xmux_max_connections,
        "xmux_c_max_reuse_times": opts.xmux_c_max_reuse_times,
        "xmux_session_reuse_validated": false,
        "full_h2_h3_stack": false,
        "payload_ascii": payload_ascii,
        "payload_len": opts.payload.len(),
        "server": null,
        "request_header_validated": false,
        "response_header_validated": false,
        "empty_addons_validated": false,
        "tcp_command_validated": false,
        "target_metadata_validated": false,
        "payload_roundtrip_validated": false,
        "full_xhttp_lifecycle_deferred": "xHTTP H2/H3 request client lifecycle, TLS/uTLS, REALITY, downloadSettings, stream-up/stream-one, padding/placement matrix, and UDP require separate gates",
        "default_go_path_preserved": true
    });
    report["underlay_socket"] = json!({
        "requested_mark": opts.so_mark,
        "requested_mptcp": opts.mptcp,
        "listener": null,
        "last_dial_report": null,
        "so_mark_observed": false,
        "mptcp_status_recorded": false,
        "mptcp_protocol_observed": false
    });
    report["benchmark"] = json!({
        "benchmark_recorded": false,
        "iterations": opts.benchmark_iters,
        "elapsed_ns": null,
        "ns_per_vless_xhttp_xmux_exchange": null,
        "scope": "VLESS TCP request/response carried by xHTTP xmux POST body on a SO_MARKed Rust TCP socket",
        "go_matched_default_daemon_baseline_recorded": false,
        "go_baseline_gap": "all outbound protocols, daemon default lifecycle, and product-chain gates are not closed"
    });
    report["protocol_matrix"] = json!({
        "socks5_protocol_true_dataplane_admitted": true,
        "http_connect_true_dataplane_admitted": true,
        "https_proxy_tls_underlay_admitted": false,
        "shadowsocks_aead_protocol_true_dataplane_admitted": true,
        "ss2022_true_dataplane_admitted": false,
        "trojanc_tcp_true_dataplane_admitted": true,
        "trojan_udp_over_tcp_admitted": true,
        "trojan_protocol_true_dataplane_admitted": false,
        "vless_tcp_raw_true_dataplane_admitted": true,
        "vless_udp_over_tcp_admitted": true,
        "vless_mux_admitted": true,
        "vless_websocket_admitted": true,
        "vless_httpupgrade_admitted": true,
        "vless_grpc_hunk_admitted": true,
        "vless_meek_polling_admitted": true,
        "vless_http_transport_put_admitted": true,
        "vless_xhttp_admitted": true,
        "vless_xhttp_xmux_admitted": false,
        "vless_shared_transport_admitted": false,
        "vless_protocol_true_dataplane_admitted": false,
        "vless_tls_underlay_admitted": false,
        "vless_reality_underlay_admitted": false,
        "vless_vision_admitted": false,
        "vmess_aead_tcp_true_dataplane_admitted": true,
        "vmess_aead_udp_over_tcp_admitted": true,
        "vmess_udp_packet_addr_admitted": true,
        "vmess_mux_admitted": true,
        "vmess_websocket_admitted": true,
        "vmess_httpupgrade_admitted": true,
        "vmess_grpc_hunk_admitted": true,
        "vmess_meek_polling_admitted": true,
        "vmess_http_transport_put_admitted": true,
        "vmess_http_h2_full_admitted": false,
        "vmess_shared_transport_admitted": false,
        "vmess_protocol_true_dataplane_admitted": false,
        "quic_h3_session_protocols_admitted": false
    });
    report["remaining_blockers"] = json!([
        "SS2022 TCP/UDP true dataplane is still incomplete",
        "Trojan TLS and Trojan-Go shared transport rows are still incomplete",
        "VLESS xHTTP full H2/H3/TLS/uTLS/REALITY lifecycle, downloadSettings, stream-up/stream-one, padding/placement matrix, UDP, and full shared transport rows are still incomplete",
        "VMess full HTTP/2 h2 pool/TLS/uTLS, WSS, xHTTP, full gRPC HTTP/2/TLS, full Meek HTTPS, HTTPS HTTPUpgrade/TLS/uTLS, and full shared transport rows are still incomplete",
        "Hysteria2, TUIC, Juicity, AnyTLS, HTTPS proxy, and shared transport true dataplanes are still incomplete",
        "matched Go default daemon vs true Rust candidate benchmark is still missing",
        "clean dae-wing and daed product-chain recertification is still missing"
    ]);
    report["validation_commands"] = json!([
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage80/vless_xhttp_xmux_dataplane_admission.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage80_vless_xhttp_xmux_dataplane_gate.json",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound stage80 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage80 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage80 -- --nocapture",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage80-vless-xhttp-xmux-dataplane-admission --execute-smoke --ack-root-gate --benchmark-iters 10",
        "git diff --check"
    ]);
    report["source"] = json!([
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage80",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.4",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.5",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.3",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.8",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.18",
        "/root/project/outbound/dialer/v2ray/v2ray.go",
        "/root/project/outbound/transport/xhttp/xhttp.go",
        "/root/project/outbound/transport/xhttp/xhttp_test.go",
        "rust/crates/dae-outbound/src/vless/dataplane.rs",
        "rust/crates/dae-outbound/src/shared_transport/xhttp.rs",
        "rust/crates/dae-datapath/src/tcp_direct.rs"
    ]);

    if !opts.execute_smoke {
        return report;
    }
    if !opts.ack_root_gate {
        report["blocked"] = json!(true);
        report["blockers"] = json!([
            "stage80 root-gated smoke requires --ack-root-gate because it attempts SO_MARK/MPTCP underlay socket observation"
        ]);
        return report;
    }

    match run_stage80_smoke(opts) {
        Ok(outcome) => apply_stage80_outcome(&mut report, outcome),
        Err(err) => {
            report["blocked"] = json!(true);
            report["blockers"] = json!([err]);
        }
    }
    report
}
