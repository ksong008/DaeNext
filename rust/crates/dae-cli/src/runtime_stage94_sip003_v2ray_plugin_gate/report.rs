use super::smoke::{apply_stage94_outcome, run_stage94_smoke};
use super::*;

pub(super) fn stage94_report(opts: &Stage94Options) -> Value {
    let spec = match shadowsocks::cipher_spec(&opts.cipher) {
        Ok(spec) => spec,
        Err(err) => {
            return json!({
                "name": "stage94-sip003-v2ray-plugin-dataplane-admission",
                "stage": "stage94",
                "blocked": true,
                "blockers": [format!("stage94 requires ordinary Shadowsocks AEAD cipher: {err}")]
            });
        }
    };
    if let Err(err) = shadowsocks::ShadowsocksMetadata::parse(&opts.target) {
        return json!({
            "name": "stage94-sip003-v2ray-plugin-dataplane-admission",
            "stage": "stage94",
            "blocked": true,
            "blockers": [format!("stage94 target is invalid: {err}")]
        });
    }
    let plugin_options = match shadowsocks::Sip003V2rayPluginOptions::new(
        &opts.tls_server_name,
        &opts.tls_alpn,
        &opts.ws_host,
        &opts.ws_path,
    ) {
        Ok(options) => options,
        Err(err) => {
            return json!({
                "name": "stage94-sip003-v2ray-plugin-dataplane-admission",
                "stage": "stage94",
                "blocked": true,
                "blockers": [format!("stage94 v2ray-plugin options invalid: {err}")]
            });
        }
    };

    let payload_ascii = String::from_utf8_lossy(&opts.payload).to_string();
    let mut report = json!({
        "name": "stage94-sip003-v2ray-plugin-dataplane-admission",
        "stage": "stage94",
        "evidence_class": "opt-in-protocol-sip003-v2ray-plugin-tls-ws-mux-shadowsocks-aead-true-dataplane-smoke",
        "execute_smoke": opts.execute_smoke,
        "read_only": !opts.execute_smoke,
        "blocked": false,
        "blockers": [],
        "socks5_protocol_true_dataplane_admitted": true,
        "http_connect_true_dataplane_admitted": true,
        "https_proxy_true_dataplane_admitted": true,
        "shared_tls_underlay_admitted": true,
        "shadowsocks_aead_protocol_true_dataplane_admitted": true,
        "ss2022_true_dataplane_admitted": true,
        "sip003_simple_obfs_http_admitted": true,
        "sip003_simple_obfs_tls_admitted": true,
        "sip003_v2ray_plugin_smoke_passed": false,
        "sip003_v2ray_plugin_admitted": false,
        "sip003_plugin_transport_admitted": false,
        "shadowsocksr_true_dataplane_admitted": false,
        "shadowsocks_protocol_partial_admitted": true,
        "shadowsocks_protocol_true_dataplane_admitted": false,
        "trojan_protocol_true_dataplane_admitted": true,
        "trojan_go_shared_transport_partial_admitted": true,
        "trojan_go_shared_transport_admitted": false,
        "shared_transport_true_dataplane_admitted": false,
        "protocol_outbound_partial_admitted": true,
        "outbound_true_dataplane_admitted": false,
        "matched_go_rust_default_daemon_benchmark_recorded": false,
        "default_switch_allowed": false,
        "default_path_mutation_allowed": false,
        "product_chain_switch_allowed": false,
        "true_rust_default_daemon_admitted": false,
        "go_default_path_preserved": true,
        "go_fallback_required": true
    });
    report["sip003_contract"] = json!({
        "protocol": "shadowsocks",
        "plugin": "v2ray-plugin",
        "obfs": "",
        "tls": "tls",
        "scope": "SIP003 v2ray-plugin TLS(rustls) -> WebSocket binary frame -> mux new/data frame -> ordinary Shadowsocks AEAD TCP client initial and server payload over SO_MARKed Rust TCP underlay",
        "server": null,
        "tls_server_name": plugin_options.tls.server_name,
        "tls_alpn": plugin_options.tls.alpn_protocol,
        "selected_alpn": null,
        "ws_host": plugin_options.ws_host,
        "ws_path": plugin_options.ws_path,
        "mux": {
            "id_hex": "0000",
            "host": plugin_options.mux.host,
            "port": plugin_options.mux.port,
            "network": plugin_options.mux.network,
            "new_frame_validated": false,
            "data_frame_validated": false
        },
        "passthrough_udp": {
            "tls": plugin_options.tls_passthrough_udp,
            "websocket": plugin_options.ws_passthrough_udp,
            "mux": plugin_options.mux_passthrough_udp,
            "actual_udp_dataplane_deferred": true
        },
        "target": opts.target,
        "payload_ascii": payload_ascii,
        "payload_len": opts.payload.len(),
        "tls_handshake_validated": false,
        "certificate_chain_validated": false,
        "server_name_validated": false,
        "alpn_validated": false,
        "websocket_handshake_validated": false,
        "websocket_binary_frame_validated": false,
        "inner_shadowsocks_aead": {
            "cipher": spec.cipher,
            "salt_len": spec.salt_len,
            "key_len": spec.key_len,
            "target": null,
            "client_salt_len": null,
            "server_salt_len": null,
            "payload_len": null,
            "payload_roundtrip_validated": false
        },
        "simple_obfs_http_admitted": true,
        "simple_obfs_tls_admitted": true,
        "ssr_deferred": true,
        "ordinary_aead_boundary_preserved": true,
        "ss2022_boundary_preserved": true,
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
        "exchange_count": null,
        "elapsed_ns": null,
        "ns_per_sip003_v2ray_plugin_exchange": null,
        "scope": "rustls TLS handshake, WebSocket upgrade and binary frame, mux new/data frame, ordinary Shadowsocks AEAD TCP salt/HKDF/chunk encrypt/decrypt, target metadata, payload echo, SO_MARK/MPTCP Rust TCP underlay",
        "go_matched_default_daemon_baseline_recorded": false,
        "go_baseline_gap": "Stage 94 validates opt-in Rust dataplane only; SSR, Shadowsocks family protocol-wide admission, default daemon lifecycle, and product-chain gates are not closed"
    });
    report["protocol_matrix"] = json!({
        "shadowsocks_aead_protocol_true_dataplane_admitted": true,
        "ss2022_true_dataplane_admitted": true,
        "sip003_simple_obfs_http_admitted": true,
        "sip003_simple_obfs_tls_admitted": true,
        "sip003_v2ray_plugin_admitted": false,
        "sip003_plugin_transport_admitted": false,
        "shadowsocksr_true_dataplane_admitted": false,
        "shadowsocks_protocol_true_dataplane_admitted": false,
        "trojan_go_shared_transport_partial_admitted": true,
        "trojan_go_shared_transport_admitted": false,
        "shared_transport_true_dataplane_admitted": false,
        "outbound_true_dataplane_admitted": false
    });
    report["remaining_blockers"] = json!([
        "ShadowsocksR layered transport remains a separate blocker",
        "Shadowsocks family protocol-wide admission remains closed until SSR is recertified",
        "Trojan-Go full shared transport remains blocked until transport combinations and full grpc-go HTTP/2/TLS lifecycle are recertified together",
        "uTLS fingerprint, REALITY, and TLS fragmentation are still deferred",
        "Hysteria2, TUIC, Juicity, AnyTLS, REALITY, Vision, and QUIC/H3 true dataplanes are still incomplete",
        "matched Go default daemon vs true Rust candidate benchmark is still missing",
        "clean dae-wing and daed product-chain recertification is still missing"
    ]);
    report["validation_commands"] = json!([
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage94/sip003_v2ray_plugin_dataplane_admission.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage94_sip003_v2ray_plugin_dataplane_gate.json",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound stage94 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage94 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage94 -- --nocapture",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage94-sip003-v2ray-plugin-dataplane-admission --execute-smoke --ack-root-gate --benchmark-iters 10",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound -p dae-cli -p dae-product",
        "cargo fmt --manifest-path rust/Cargo.toml --all -- --check",
        "git diff --check"
    ]);
    report["source"] = json!([
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage94",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.9",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:12.5",
        "/root/project/outbound/dialer/shadowsocks/shadowsocks.go",
        "/root/project/outbound/transport/tls/tls.go",
        "/root/project/outbound/transport/ws/ws.go",
        "/root/project/outbound/transport/mux/conn.go",
        "rust/crates/dae-outbound/src/shadowsocks/sip003_v2ray_plugin_dataplane.rs",
        "rust/crates/dae-datapath/src/tcp_direct.rs"
    ]);

    if !opts.execute_smoke {
        return report;
    }
    if !opts.ack_root_gate {
        report["blocked"] = json!(true);
        report["blockers"] = json!([
            "stage94 root-gated smoke requires --ack-root-gate because it attempts SO_MARK/MPTCP underlay socket observation"
        ]);
        return report;
    }

    match run_stage94_smoke(opts) {
        Ok(outcome) => apply_stage94_outcome(&mut report, outcome),
        Err(err) => {
            report["blocked"] = json!(true);
            report["blockers"] = json!([err]);
        }
    }
    report
}
