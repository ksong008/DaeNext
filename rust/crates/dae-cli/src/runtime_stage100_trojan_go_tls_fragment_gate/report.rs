use super::smoke::{apply_stage100_outcome, run_stage100_smoke};
use super::*;

pub(super) fn stage100_report(opts: &Stage100Options) -> Value {
    let tls_options = match opts.tls_options() {
        Ok(options) => options,
        Err(err) => {
            return json!({
                "name": "stage100-trojan-go-tls-fragment-admission",
                "stage": "stage100",
                "blocked": true,
                "blockers": [format!("stage100 tls options invalid: {err}")]
            });
        }
    };
    let fragment_options = match opts.fragment_options() {
        Ok(options) => options,
        Err(err) => {
            return json!({
                "name": "stage100-trojan-go-tls-fragment-admission",
                "stage": "stage100",
                "blocked": true,
                "blockers": [format!("stage100 tls fragment options invalid: {err}")]
            });
        }
    };
    let payload_ascii = String::from_utf8_lossy(&opts.payload).to_string();
    let password_sha224_hex = trojan::packet::password_sha224_hex(&opts.password);
    let mut report = json!({
        "name": "stage100-trojan-go-tls-fragment-admission",
        "stage": "stage100",
        "evidence_class": "opt-in-protocol-trojan-go-wss-tls-fragment-true-dataplane-smoke",
        "execute_smoke": opts.execute_smoke,
        "read_only": !opts.execute_smoke,
        "blocked": false,
        "blockers": []
    });
    report["trojan_go_wss_admitted"] = json!(true);
    report["trojan_go_httpupgrade_admitted"] = json!(true);
    report["trojan_go_grpc_hunk_admitted"] = json!(true);
    report["trojan_go_inner_shadowsocks_admitted"] = json!(true);
    report["trojan_go_grpc_http2_tls_lifecycle_admitted"] = json!(true);
    report["trojan_go_grpc_cache_cleanup_admitted"] = json!(true);
    report["trojan_go_grpc_cancellation_stress_admitted"] = json!(true);
    report["trojan_go_tls_fragment_smoke_passed"] = json!(false);
    report["trojan_go_tls_fragment_admitted"] = json!(false);
    report["trojan_go_utls_fingerprint_admitted"] = json!(false);
    report["trojan_go_reality_mutation_admitted"] = json!(false);
    report["trojan_go_cross_combination_recertified"] = json!(false);
    report["trojan_go_shared_transport_partial_admitted"] = json!(true);
    report["trojan_go_shared_transport_admitted"] = json!(false);
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
    report["tls_fragment_contract"] = json!({
        "protocol": "trojan-go",
        "transport": "wss",
        "inner_protocol": "trojanc",
        "scope": "Rust TLS fragment wrapper sits between SO_MARK/MPTCP TCP underlay and rustls handshake, then carries WebSocket binary trojanc TCP request/response",
        "target": opts.target,
        "tls_server_name": tls_options.server_name,
        "alpn_protocol": tls_options.alpn_protocol,
        "selected_alpn": null,
        "certificate_der_len": null,
        "ws_host": opts.ws_host,
        "ws_path": opts.ws_path,
        "payload_ascii": payload_ascii,
        "password_sha224_hex": password_sha224_hex,
        "fragment_length": opts.fragment_length,
        "fragment_interval": opts.fragment_interval,
        "fragment_min_length": fragment_options.min_length,
        "fragment_max_length": fragment_options.max_length,
        "fragment_min_interval_ms": fragment_options.min_interval_ms,
        "fragment_max_interval_ms": fragment_options.max_interval_ms,
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
        "fragmented_write_count": 0,
        "fragment_record_count": 0,
        "handshake_record_fragmented": false,
        "fragment_payload_lens": [],
        "reassembled_record_matches": false,
        "first_fragmented_write": null,
        "utls_deferred": true,
        "reality_deferred": true,
        "grpc_no_double_tls_inherited": true,
        "default_go_path_preserved": true
    });
    report["fragment_helper_contract"] = json!({
        "go_source": "/root/project/outbound/transport/tls/fragment.go",
        "fragmented_content_type": 22,
        "short_write_passthrough": true,
        "non_handshake_passthrough": true,
        "incomplete_record_passthrough": true,
        "first_complete_handshake_record_only": true,
        "trailing_bytes_preserved": true,
        "zero_interval_batches_fragmented_records": true,
        "range_error_text": "invalid range: <value>"
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
        "ns_per_trojan_go_tls_fragment_exchange": null,
        "scope": "TLS fragment wrapper plus rustls TLS handshake plus WebSocket Upgrade/binary frame plus trojanc TCP request header parse plus payload echo over SO_MARKed Rust TCP socket",
        "go_matched_default_daemon_baseline_recorded": false,
        "go_baseline_gap": "all outbound protocols, daemon default lifecycle, and product-chain gates are not closed"
    });
    report["protocol_matrix"] = json!({
        "trojan_go_wss_admitted": true,
        "trojan_go_httpupgrade_admitted": true,
        "trojan_go_grpc_hunk_admitted": true,
        "trojan_go_inner_shadowsocks_admitted": true,
        "trojan_go_grpc_http2_tls_lifecycle_admitted": true,
        "trojan_go_grpc_cache_cleanup_admitted": true,
        "trojan_go_grpc_cancellation_stress_admitted": true,
        "trojan_go_tls_fragment_admitted": false,
        "trojan_go_utls_fingerprint_admitted": false,
        "trojan_go_reality_mutation_admitted": false,
        "trojan_go_cross_combination_recertified": false,
        "trojan_go_shared_transport_partial_admitted": true,
        "trojan_go_shared_transport_admitted": false,
        "shared_transport_true_dataplane_admitted": false,
        "outbound_true_dataplane_admitted": false,
        "quic_h3_session_protocols_admitted": false
    });
    report["remaining_blockers"] = json!([
        "Trojan-Go uTLS fingerprint row is still incomplete",
        "Trojan-Go REALITY handshake mutation row is still incomplete",
        "Trojan-Go cross-combination recertification is still incomplete",
        "VLESS and VMess TLS/WSS/gRPC/Meek/xHTTP full shared transport rows remain protocol-specific blockers",
        "Hysteria2, TUIC, Juicity, AnyTLS, REALITY, Vision, and QUIC/H3 true dataplanes are still incomplete",
        "matched Go default daemon vs true Rust candidate benchmark is still missing",
        "clean dae-wing and daed product-chain recertification is still missing"
    ]);
    report["validation_commands"] = json!([
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage100/trojan_go_tls_fragment_admission.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage100_trojan_go_tls_fragment_gate.json",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound stage100 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage100 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage100 -- --nocapture",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage100-trojan-go-tls-fragment-admission --execute-smoke --ack-root-gate --benchmark-iters 10",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound -p dae-cli -p dae-product",
        "cargo fmt --manifest-path rust/Cargo.toml --all -- --check",
        "git diff --check"
    ]);
    report["source"] = json!([
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage100",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.7",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.11",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.18",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.21",
        "/root/project/outbound/transport/tls/fragment.go",
        "/root/project/outbound/transport/ws/ws.go",
        "rust/crates/dae-outbound/src/shared_transport/tls_fragment.rs",
        "rust/crates/dae-outbound/src/trojan/websocket_tls_dataplane.rs",
        "rust/crates/dae-datapath/src/tcp_direct.rs"
    ]);

    if !opts.execute_smoke {
        return report;
    }
    if !opts.ack_root_gate {
        report["blocked"] = json!(true);
        report["blockers"] = json!([
            "stage100 root-gated smoke requires --ack-root-gate because it attempts SO_MARK/MPTCP underlay socket observation"
        ]);
        return report;
    }

    match run_stage100_smoke(opts) {
        Ok(outcome) => apply_stage100_outcome(&mut report, outcome),
        Err(err) => {
            report["blocked"] = json!(true);
            report["blockers"] = json!([err]);
        }
    }
    report
}
