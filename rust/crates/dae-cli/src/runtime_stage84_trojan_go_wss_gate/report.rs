use super::smoke::{apply_stage84_outcome, run_stage84_smoke};
use super::*;

pub(super) fn stage84_report(opts: &Stage84Options) -> Value {
    let tls_options = match opts.tls_options() {
        Ok(options) => options,
        Err(err) => {
            return json!({
                "name": "stage84-trojan-go-wss-dataplane-admission",
                "stage": "stage84",
                "blocked": true,
                "blockers": [format!("stage84 tls options invalid: {err}")]
            });
        }
    };
    let payload_ascii = String::from_utf8_lossy(&opts.payload).to_string();
    let password_sha224_hex = trojan::packet::password_sha224_hex(&opts.password);
    let mut report = json!({
        "name": "stage84-trojan-go-wss-dataplane-admission",
        "stage": "stage84",
        "evidence_class": "opt-in-protocol-trojan-go-wss-true-dataplane-smoke",
        "execute_smoke": opts.execute_smoke,
        "read_only": !opts.execute_smoke,
        "blocked": false,
        "blockers": []
    });
    report["socks5_protocol_true_dataplane_admitted"] = json!(true);
    report["http_connect_true_dataplane_admitted"] = json!(true);
    report["https_proxy_true_dataplane_admitted"] = json!(true);
    report["shared_tls_underlay_admitted"] = json!(true);
    report["shadowsocks_aead_protocol_true_dataplane_admitted"] = json!(true);
    report["ss2022_true_dataplane_admitted"] = json!(false);
    report["trojanc_tcp_true_dataplane_admitted"] = json!(true);
    report["trojan_udp_over_tcp_admitted"] = json!(true);
    report["trojan_tls_underlay_admitted"] = json!(true);
    report["trojan_standard_protocol_true_dataplane_admitted"] = json!(true);
    report["trojan_protocol_true_dataplane_admitted"] = json!(true);
    report["trojan_go_wss_smoke_passed"] = json!(false);
    report["trojan_go_wss_admitted"] = json!(false);
    report["trojan_go_shared_transport_partial_admitted"] = json!(false);
    report["trojan_go_shared_transport_admitted"] = json!(false);
    report["trojan_go_grpc_admitted"] = json!(false);
    report["trojan_go_httpupgrade_admitted"] = json!(false);
    report["trojan_go_inner_shadowsocks_admitted"] = json!(false);
    report["vless_tls_underlay_admitted"] = json!(false);
    report["vless_reality_underlay_admitted"] = json!(false);
    report["vless_vision_admitted"] = json!(false);
    report["vless_protocol_true_dataplane_admitted"] = json!(false);
    report["vmess_tls_underlay_admitted"] = json!(false);
    report["vmess_protocol_true_dataplane_admitted"] = json!(false);
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
    report["trojan_go_wss_contract"] = json!({
        "protocol": "trojan-go",
        "transport": "wss",
        "inner_protocol": "trojanc",
        "scope": "trojanc TCP request/response carried by WebSocket binary frames inside rustls TLS underlay",
        "target": opts.target,
        "tls_server_name": tls_options.server_name,
        "alpn_protocol": tls_options.alpn_protocol,
        "selected_alpn": null,
        "certificate_der_len": null,
        "ws_host": opts.ws_host,
        "ws_path": opts.ws_path,
        "payload_ascii": payload_ascii,
        "password_sha224_hex": password_sha224_hex,
        "server": null,
        "tls_handshake_validated": false,
        "certificate_chain_validated": false,
        "server_name_validated": false,
        "alpn_validated": false,
        "websocket_upgrade_validated": false,
        "websocket_binary_frame_validated": false,
        "password_sha224_validated": false,
        "tcp_command_validated": false,
        "target_metadata_validated": false,
        "payload_roundtrip_validated": false,
        "grpc_deferred": true,
        "httpupgrade_deferred": true,
        "inner_shadowsocks_deferred": true,
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
        "ns_per_trojan_go_wss_exchange": null,
        "scope": "rustls TLS handshake plus WebSocket Upgrade/binary frame plus trojanc TCP request header parse plus payload echo over SO_MARKed Rust TCP socket",
        "go_matched_default_daemon_baseline_recorded": false,
        "go_baseline_gap": "all outbound protocols, daemon default lifecycle, and product-chain gates are not closed"
    });
    report["protocol_matrix"] = json!({
        "socks5_protocol_true_dataplane_admitted": true,
        "http_connect_true_dataplane_admitted": true,
        "https_proxy_true_dataplane_admitted": true,
        "shared_tls_underlay_admitted": true,
        "shadowsocks_aead_protocol_true_dataplane_admitted": true,
        "ss2022_true_dataplane_admitted": false,
        "trojanc_tcp_true_dataplane_admitted": true,
        "trojan_udp_over_tcp_admitted": true,
        "trojan_tls_underlay_admitted": true,
        "trojan_standard_protocol_true_dataplane_admitted": true,
        "trojan_protocol_true_dataplane_admitted": true,
        "trojan_go_wss_admitted": false,
        "trojan_go_shared_transport_partial_admitted": false,
        "trojan_go_shared_transport_admitted": false,
        "trojan_go_grpc_admitted": false,
        "trojan_go_httpupgrade_admitted": false,
        "trojan_go_inner_shadowsocks_admitted": false,
        "vless_protocol_true_dataplane_admitted": false,
        "vmess_protocol_true_dataplane_admitted": false,
        "shared_transport_true_dataplane_admitted": false,
        "quic_h3_session_protocols_admitted": false
    });
    report["remaining_blockers"] = json!([
        "Trojan-Go gRPC, HTTPUpgrade, and inner Shadowsocks are still incomplete",
        "Trojan-Go WSS admits rustls only; uTLS fingerprint, REALITY, and TLS fragmentation are still deferred",
        "SS2022 TCP/UDP true dataplane is still incomplete",
        "VLESS and VMess TLS/WSS/gRPC/Meek/xHTTP full shared transport rows remain protocol-specific blockers",
        "Hysteria2, TUIC, Juicity, AnyTLS, REALITY, Vision, and QUIC/H3 true dataplanes are still incomplete",
        "matched Go default daemon vs true Rust candidate benchmark is still missing",
        "clean dae-wing and daed product-chain recertification is still missing"
    ]);
    report["validation_commands"] = json!([
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage84/trojan_go_wss_dataplane_admission.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage84_trojan_go_wss_dataplane_gate.json",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound stage84 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage84 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage84 -- --nocapture",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage84-trojan-go-wss-dataplane-admission --execute-smoke --ack-root-gate --benchmark-iters 10",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound -p dae-cli -p dae-product",
        "cargo fmt --all --check",
        "git diff --check"
    ]);
    report["source"] = json!([
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage84",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.11",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.7",
        "/root/project/outbound/protocol/trojanc",
        "/root/project/outbound/transport/tls",
        "/root/project/outbound/transport/ws",
        "rust/crates/dae-outbound/src/trojan/websocket_tls_dataplane.rs",
        "rust/crates/dae-outbound/src/shared_transport/tls.rs",
        "rust/crates/dae-outbound/src/shared_transport/dataplane.rs",
        "rust/crates/dae-datapath/src/tcp_direct.rs"
    ]);

    if !opts.execute_smoke {
        return report;
    }
    if !opts.ack_root_gate {
        report["blocked"] = json!(true);
        report["blockers"] = json!([
            "stage84 root-gated smoke requires --ack-root-gate because it attempts SO_MARK/MPTCP underlay socket observation"
        ]);
        return report;
    }

    match run_stage84_smoke(opts) {
        Ok(outcome) => apply_stage84_outcome(&mut report, outcome),
        Err(err) => {
            report["blocked"] = json!(true);
            report["blockers"] = json!([err]);
        }
    }
    report
}
