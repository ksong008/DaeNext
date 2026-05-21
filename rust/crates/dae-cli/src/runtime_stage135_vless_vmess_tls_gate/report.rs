use super::smoke::{apply_stage135_outcome, run_stage135_smoke};
use super::*;

pub(super) fn stage135_report(opts: &Stage135Options) -> Value {
    if let Err(err) = opts.tls_options() {
        return json!({
            "name": "stage135-vless-vmess-tls-wss-httpupgrade-admission",
            "stage": "stage135",
            "blocked": true,
            "blockers": [format!("stage135 tls options invalid: {err}")]
        });
    }
    let mut report = json!({
        "name": "stage135-vless-vmess-tls-wss-httpupgrade-admission",
        "stage": "stage135",
        "evidence_class": "opt-in-protocol-vless-vmess-rustls-wss-https-httpupgrade-true-dataplane-smoke",
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
        "quic_h3_family_true_dataplane_admitted",
        "vless_protocol_partial_admitted",
        "vmess_protocol_partial_admitted",
        "vless_grpc_http2_lifecycle_admitted",
        "vmess_grpc_http2_lifecycle_admitted",
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
        "vless_wss_tls_lifecycle_admitted",
        "vmess_wss_tls_lifecycle_admitted",
        "vless_https_httpupgrade_tls_lifecycle_admitted",
        "vmess_https_httpupgrade_tls_lifecycle_admitted",
        "vless_vmess_tls_wss_httpupgrade_smoke_passed",
        "vless_utls_fingerprint_wire_admitted",
        "vmess_utls_fingerprint_wire_admitted",
        "vless_reality_full_handshake_admitted",
        "vless_vision_tls_reality_admitted",
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
    report["stage135_tls_contract"] = json!({
        "scope": "VLESS and VMess WSS plus HTTPS HTTPUpgrade carried over rustls TLS with ALPN http/1.1, then protocol TCP payload roundtrip",
        "tls_server_name": opts.tls_server_name,
        "alpn_protocol": opts.alpn_protocol,
        "selected_alpn": null,
        "certificate_der_len": null,
        "server": null,
        "wss_host": opts.wss_host,
        "wss_path": opts.wss_path,
        "httpupgrade_host": opts.httpupgrade_host,
        "httpupgrade_path": opts.httpupgrade_path,
        "payload_ascii": String::from_utf8_lossy(&opts.payload).to_string(),
        "payload_len": opts.payload.len(),
        "tls_handshake_validated": false,
        "wss_validated": false,
        "https_httpupgrade_validated": false,
        "rustls_tls_lifecycle": true,
        "utls_deferred": true,
        "reality_deferred": true,
        "vision_deferred": true,
        "xhttp_h2_h3_deferred": true,
        "tls_fragment_deferred": true,
        "default_go_path_preserved": true
    });
    report["underlay_socket"] = json!({
        "requested_mark": opts.so_mark,
        "requested_mptcp": opts.mptcp,
        "listener": null,
        "last_dial_report": null,
        "so_mark_observed": false,
        "mptcp_status_recorded": false
    });
    report["benchmark"] = json!({
        "benchmark_recorded": false,
        "iterations_per_transport": opts.benchmark_iters,
        "total_exchange_count": opts.benchmark_iters * 4,
        "elapsed_ns": null,
        "ns_per_vless_vmess_tls_transport_exchange": null,
        "scope": "root-gated local rustls WSS and HTTPS HTTPUpgrade smoke over SO_MARK/MPTCP TCP sockets for VLESS and VMess; uTLS, REALITY, Vision, xHTTP H2/H3, and matched Go default daemon baselines remain out of scope",
        "go_matched_default_daemon_baseline_recorded": false
    });
    report["protocol_matrix"] = json!({
        "vless_grpc_http2_lifecycle_admitted": true,
        "vmess_grpc_http2_lifecycle_admitted": true,
        "vless_wss_tls_lifecycle_admitted": false,
        "vmess_wss_tls_lifecycle_admitted": false,
        "vless_https_httpupgrade_tls_lifecycle_admitted": false,
        "vmess_https_httpupgrade_tls_lifecycle_admitted": false,
        "vless_protocol_true_dataplane_admitted": false,
        "vmess_protocol_true_dataplane_admitted": false,
        "shared_transport_true_dataplane_admitted": false,
        "outbound_true_dataplane_admitted": false
    });
    report["remaining_blockers"] = json!([
        "VLESS uTLS fingerprint, REALITY full handshake, XTLS Vision, and xHTTP H2/H3 lifecycle remain separate blockers",
        "VMess uTLS/WSS full-combination and xHTTP/H2 protocol-wide recertification remain separate blockers",
        "Trojan-Go full shared transport remains blocked",
        "shared_transport_true_dataplane and outbound_true_dataplane remain closed until all protocol rows close",
        "matched Go default daemon vs true Rust candidate benchmark remains missing",
        "default daemon and product-chain switches remain closed"
    ]);
    report["validation_commands"] = json!([
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage135/vless_vmess_tls_wss_httpupgrade_admission.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage135_vless_vmess_tls_wss_httpupgrade_gate.json",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound stage135 -- --nocapture",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage135-vless-vmess-tls-wss-httpupgrade-admission",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage135-vless-vmess-tls-wss-httpupgrade-admission --execute-smoke --ack-root-gate --benchmark-iters 2",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage135 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage135 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage134 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound -p dae-cli -p dae-product -q",
        "cargo fmt --manifest-path rust/Cargo.toml --all -- --check",
        "git diff --check"
    ]);
    report["source"] = json!([
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage135",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.5",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.7",
        "rust/crates/dae-outbound/src/vless/dataplane/tls_transports.rs",
        "rust/crates/dae-outbound/src/vmess/dataplane/tls_transports.rs",
        "rust/crates/dae-outbound/src/shared_transport/tls.rs"
    ]);

    if !opts.execute_smoke {
        return report;
    }
    if !opts.ack_root_gate {
        report["blocked"] = json!(true);
        report["blockers"] = json!([
            "stage135 root-gated smoke requires --ack-root-gate because it attempts SO_MARK/MPTCP underlay socket observation"
        ]);
        return report;
    }
    match run_stage135_smoke(opts) {
        Ok(outcome) => apply_stage135_outcome(&mut report, outcome),
        Err(err) => {
            report["blocked"] = json!(true);
            report["blockers"] = json!([err]);
        }
    }
    report
}
