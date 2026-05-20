use super::smoke::{apply_stage82_outcome, run_stage82_smoke};
use super::*;

pub(super) fn stage82_report(opts: &Stage82Options) -> Value {
    let tls_options = match opts.tls_options() {
        Ok(options) => options,
        Err(err) => {
            return json!({
                "name": "stage82-https-proxy-tls-dataplane-admission",
                "stage": "stage82",
                "blocked": true,
                "blockers": [format!("stage82 tls options invalid: {err}")]
            });
        }
    };
    let payload_ascii = String::from_utf8_lossy(&opts.payload).to_string();
    let response_ascii = String::from_utf8_lossy(&opts.response).to_string();
    let mut report = json!({
        "name": "stage82-https-proxy-tls-dataplane-admission",
        "stage": "stage82",
        "evidence_class": "opt-in-protocol-https-proxy-tls-true-dataplane-smoke",
        "execute_smoke": opts.execute_smoke,
        "read_only": !opts.execute_smoke,
        "blocked": false,
        "blockers": []
    });
    report["socks5_protocol_true_dataplane_admitted"] = json!(true);
    report["http_connect_true_dataplane_admitted"] = json!(true);
    report["https_proxy_tls_smoke_passed"] = json!(false);
    report["https_proxy_tls_underlay_admitted"] = json!(false);
    report["https_proxy_true_dataplane_admitted"] = json!(false);
    report["http_proxy_protocol_partial_admitted"] = json!(true);
    report["http_proxy_protocol_true_dataplane_admitted"] = json!(false);
    report["shared_tls_underlay_admitted"] = json!(true);
    report["shared_transport_true_dataplane_admitted"] = json!(false);
    report["shadowsocks_aead_protocol_true_dataplane_admitted"] = json!(true);
    report["ss2022_true_dataplane_admitted"] = json!(false);
    report["trojanc_tcp_true_dataplane_admitted"] = json!(true);
    report["trojan_udp_over_tcp_admitted"] = json!(true);
    report["trojan_tls_underlay_admitted"] = json!(false);
    report["trojan_go_shared_transport_admitted"] = json!(false);
    report["trojan_protocol_true_dataplane_admitted"] = json!(false);
    report["vless_tcp_raw_true_dataplane_admitted"] = json!(true);
    report["vless_udp_over_tcp_admitted"] = json!(true);
    report["vless_mux_admitted"] = json!(true);
    report["vless_websocket_admitted"] = json!(true);
    report["vless_httpupgrade_admitted"] = json!(true);
    report["vless_grpc_hunk_admitted"] = json!(true);
    report["vless_meek_polling_admitted"] = json!(true);
    report["vless_http_transport_put_admitted"] = json!(true);
    report["vless_xhttp_admitted"] = json!(true);
    report["vless_xhttp_xmux_admitted"] = json!(true);
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
    report["vmess_meek_polling_admitted"] = json!(true);
    report["vmess_http_transport_put_admitted"] = json!(true);
    report["vmess_protocol_true_dataplane_admitted"] = json!(false);
    report["vmess_tls_underlay_admitted"] = json!(false);
    report["vmess_shared_transport_admitted"] = json!(false);
    report["protocol_outbound_partial_admitted"] = json!(true);
    report["outbound_true_dataplane_admitted"] = json!(false);
    report["matched_go_rust_default_daemon_benchmark_recorded"] = json!(false);
    report["default_switch_allowed"] = json!(false);
    report["default_path_mutation_allowed"] = json!(false);
    report["product_chain_switch_allowed"] = json!(false);
    report["true_rust_default_daemon_admitted"] = json!(false);
    report["go_default_path_preserved"] = json!(true);
    report["go_fallback_required"] = json!(true);
    report["https_proxy_contract"] = json!({
        "protocol": "HTTPS proxy",
        "scope": "HTTP CONNECT proxy semantics over rustls TLS underlay",
        "proxy": null,
        "target": opts.target,
        "host_override": opts.host_override,
        "tls_server_name": tls_options.server_name,
        "alpn_protocol": tls_options.alpn_protocol,
        "selected_alpn": null,
        "certificate_der_len": null,
        "username_password_auth_required": true,
        "expected_status": 200,
        "payload_ascii": payload_ascii,
        "response_ascii": response_ascii,
        "tls_handshake_validated": false,
        "certificate_chain_validated": false,
        "server_name_validated": false,
        "alpn_validated": false,
        "connect_request_observed": false,
        "http_proxy_auth_observed": false,
        "payload_roundtrip_recorded": false,
        "udp_unsupported": true,
        "utls_deferred": true,
        "reality_deferred": true,
        "tls_fragment_deferred": true,
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
    report["server_observation"] = json!(null);
    report["benchmark"] = json!({
        "benchmark_recorded": false,
        "iterations": opts.benchmark_iters,
        "elapsed_ns": null,
        "ns_per_https_proxy_tls_connect": null,
        "scope": "HTTPS proxy TLS handshake plus CONNECT Basic auth plus payload roundtrip over Rust underlay socket",
        "go_matched_default_daemon_baseline_recorded": false,
        "go_baseline_gap": "all outbound protocols, daemon default lifecycle, and product-chain gates are not closed"
    });
    report["protocol_matrix"] = json!({
        "socks5_protocol_true_dataplane_admitted": true,
        "http_connect_true_dataplane_admitted": true,
        "https_proxy_tls_underlay_admitted": false,
        "https_proxy_true_dataplane_admitted": false,
        "shared_tls_underlay_admitted": true,
        "shared_transport_true_dataplane_admitted": false,
        "shadowsocks_aead_protocol_true_dataplane_admitted": true,
        "ss2022_true_dataplane_admitted": false,
        "trojanc_tcp_true_dataplane_admitted": true,
        "trojan_udp_over_tcp_admitted": true,
        "trojan_tls_underlay_admitted": false,
        "trojan_go_shared_transport_admitted": false,
        "trojan_protocol_true_dataplane_admitted": false,
        "vless_tls_underlay_admitted": false,
        "vless_reality_underlay_admitted": false,
        "vless_vision_admitted": false,
        "vless_shared_transport_admitted": false,
        "vless_protocol_true_dataplane_admitted": false,
        "vmess_tls_underlay_admitted": false,
        "vmess_shared_transport_admitted": false,
        "vmess_protocol_true_dataplane_admitted": false,
        "quic_h3_session_protocols_admitted": false
    });
    report["remaining_blockers"] = json!([
        "HTTPS proxy TLS admits only rustls HTTP CONNECT over TLS; uTLS fingerprint and TLS fragmentation are still deferred",
        "Trojan TLS and Trojan-Go shared transport chains still need protocol bytes over the correct TLS/WS/gRPC/httpupgrade layers",
        "VLESS and VMess TLS/WSS/gRPC/Meek/xHTTP full shared transport rows remain protocol-specific blockers",
        "SS2022 TCP/UDP true dataplane is still incomplete",
        "Hysteria2, TUIC, Juicity, AnyTLS, REALITY, Vision, and QUIC/H3 true dataplanes are still incomplete",
        "matched Go default daemon vs true Rust candidate benchmark is still missing",
        "clean dae-wing and daed product-chain recertification is still missing"
    ]);
    report["validation_commands"] = json!([
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage82/https_proxy_tls_dataplane_admission.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage82_https_proxy_tls_dataplane_gate.json",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound stage82 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage82 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage82 -- --nocapture",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage82-https-proxy-tls-dataplane-admission --execute-smoke --ack-root-gate --benchmark-iters 10",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound -p dae-cli -p dae-product",
        "cargo fmt --all --check",
        "git diff --check"
    ]);
    report["source"] = json!([
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage82",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.12",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.7",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.11",
        "/root/project/outbound/protocol/http",
        "/root/project/outbound/transport/tls",
        "rust/crates/dae-outbound/src/http_proxy/tls_dataplane.rs",
        "rust/crates/dae-outbound/src/shared_transport/tls.rs",
        "rust/crates/dae-datapath/src/tcp_direct.rs"
    ]);

    if !opts.execute_smoke {
        return report;
    }
    if !opts.ack_root_gate {
        report["blocked"] = json!(true);
        report["blockers"] = json!([
            "stage82 root-gated smoke requires --ack-root-gate because it attempts SO_MARK/MPTCP underlay socket observation"
        ]);
        return report;
    }

    match run_stage82_smoke(opts) {
        Ok(outcome) => apply_stage82_outcome(&mut report, outcome),
        Err(err) => {
            report["blocked"] = json!(true);
            report["blockers"] = json!([err]);
        }
    }
    report
}
