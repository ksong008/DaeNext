use super::smoke::{apply_stage81_outcome, run_stage81_smoke};
use super::*;

pub(super) fn stage81_report(opts: &Stage81Options) -> Value {
    let tls_options = match opts.tls_options() {
        Ok(options) => options,
        Err(err) => {
            return json!({
                "name": "stage81-shared-tls-underlay-dataplane-admission",
                "stage": "stage81",
                "blocked": true,
                "blockers": [format!("stage81 tls options invalid: {err}")]
            });
        }
    };
    let payload_ascii = String::from_utf8_lossy(&opts.payload).to_string();
    let mut report = json!({
        "name": "stage81-shared-tls-underlay-dataplane-admission",
        "stage": "stage81",
        "evidence_class": "opt-in-shared-tls-rustls-underlay-true-dataplane-smoke",
        "execute_smoke": opts.execute_smoke,
        "read_only": !opts.execute_smoke,
        "blocked": false,
        "blockers": []
    });
    report["socks5_protocol_true_dataplane_admitted"] = json!(true);
    report["http_connect_true_dataplane_admitted"] = json!(true);
    report["https_proxy_tls_underlay_admitted"] = json!(false);
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
    report["vless_grpc_full_http2_admitted"] = json!(false);
    report["vless_meek_polling_admitted"] = json!(true);
    report["vless_meek_full_https_roundtripper_admitted"] = json!(false);
    report["vless_http_transport_put_admitted"] = json!(true);
    report["vless_http_h2_full_admitted"] = json!(false);
    report["vless_xhttp_admitted"] = json!(true);
    report["vless_xhttp_xmux_admitted"] = json!(true);
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
    report["shared_tls_underlay_smoke_passed"] = json!(false);
    report["shared_tls_underlay_admitted"] = json!(false);
    report["shared_transport_true_dataplane_admitted"] = json!(false);
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
    report["shared_tls_contract"] = json!({
        "scope": "generic shared TLS underlay only",
        "implementation": "rustls",
        "local_certificate_authority": true,
        "self_signed_loopback_certificate": true,
        "server_name": tls_options.server_name,
        "alpn_protocol": tls_options.alpn_protocol,
        "selected_alpn": null,
        "allow_insecure": tls_options.allow_insecure,
        "payload_ascii": payload_ascii,
        "payload_len": opts.payload.len(),
        "certificate_der_len": null,
        "tls_handshake_validated": false,
        "certificate_chain_validated": false,
        "server_name_validated": false,
        "alpn_validated": false,
        "payload_roundtrip_validated": false,
        "full_utls_deferred": true,
        "reality_deferred": true,
        "tls_fragment_deferred": true,
        "passthrough_udp_deferred": true,
        "protocol_specific_completion": {
            "https_proxy": false,
            "trojan_tls": false,
            "trojan_go": false,
            "vless_tls": false,
            "vmess_tls": false,
            "wss": false,
            "grpc_tls": false,
            "meek_https": false,
            "xhttp_h2_h3_tls": false,
            "anytls": false
        },
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
        "ns_per_shared_tls_roundtrip": null,
        "scope": "rustls client/server TLS handshake and payload roundtrip on a SO_MARKed Rust TCP socket",
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
        "trojan_tls_underlay_admitted": false,
        "trojan_go_shared_transport_admitted": false,
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
        "vless_xhttp_xmux_admitted": true,
        "vless_tls_underlay_admitted": false,
        "vless_reality_underlay_admitted": false,
        "vless_vision_admitted": false,
        "vless_shared_transport_admitted": false,
        "vless_protocol_true_dataplane_admitted": false,
        "vmess_aead_tcp_true_dataplane_admitted": true,
        "vmess_aead_udp_over_tcp_admitted": true,
        "vmess_udp_packet_addr_admitted": true,
        "vmess_mux_admitted": true,
        "vmess_websocket_admitted": true,
        "vmess_httpupgrade_admitted": true,
        "vmess_grpc_hunk_admitted": true,
        "vmess_meek_polling_admitted": true,
        "vmess_http_transport_put_admitted": true,
        "vmess_tls_underlay_admitted": false,
        "vmess_shared_transport_admitted": false,
        "vmess_protocol_true_dataplane_admitted": false,
        "shared_tls_underlay_admitted": false,
        "shared_transport_true_dataplane_admitted": false,
        "quic_h3_session_protocols_admitted": false
    });
    report["remaining_blockers"] = json!([
        "Generic rustls TLS underlay is not uTLS fingerprinting, REALITY, TLS fragmentation, or Vision",
        "HTTPS proxy must still run HTTP proxy semantics over TLS with h2,http/1.1 ALPN before admission",
        "Trojan TLS and Trojan-Go shared transport chains still need protocol bytes over the correct TLS/WS/gRPC/httpupgrade layers",
        "VLESS and VMess TLS/WSS/gRPC/Meek/xHTTP full shared transport rows remain protocol-specific blockers",
        "SS2022 TCP/UDP true dataplane is still incomplete",
        "Hysteria2, TUIC, Juicity, AnyTLS, and QUIC/H3 true dataplanes are still incomplete",
        "matched Go default daemon vs true Rust candidate benchmark is still missing",
        "clean dae-wing and daed product-chain recertification is still missing"
    ]);
    report["validation_commands"] = json!([
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage81/shared_tls_underlay_dataplane_admission.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage81_shared_tls_underlay_dataplane_gate.json",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound stage81 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage81 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage81 -- --nocapture",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage81-shared-tls-underlay-dataplane-admission --execute-smoke --ack-root-gate --benchmark-iters 10",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound -p dae-cli -p dae-product",
        "cargo fmt --all --check",
        "git diff --check"
    ]);
    report["source"] = json!([
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage81",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.7",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.8",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.11",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.12",
        "/root/project/outbound/transport/tls",
        "rust/crates/dae-outbound/src/shared_transport/tls.rs",
        "rust/crates/dae-datapath/src/tcp_direct.rs"
    ]);

    if !opts.execute_smoke {
        return report;
    }
    if !opts.ack_root_gate {
        report["blocked"] = json!(true);
        report["blockers"] = json!([
            "stage81 root-gated smoke requires --ack-root-gate because it attempts SO_MARK/MPTCP underlay socket observation"
        ]);
        return report;
    }

    match run_stage81_smoke(opts) {
        Ok(outcome) => apply_stage81_outcome(&mut report, outcome),
        Err(err) => {
            report["blocked"] = json!(true);
            report["blockers"] = json!([err]);
        }
    }
    report
}
