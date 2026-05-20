use super::smoke::{apply_stage103_outcome, run_stage103_smoke};
use super::*;

pub(super) fn stage103_report(opts: &Stage103Options) -> Value {
    let spec = match shadowsocks::cipher_spec(&opts.cipher) {
        Ok(spec) => spec,
        Err(err) => {
            return json!({
                "name": "stage103-trojan-go-wss-tls-fragment-inner-ss-combination-admission",
                "stage": "stage103",
                "blocked": true,
                "blockers": [format!("stage103 cipher invalid: {err}")]
            });
        }
    };
    let tls_options = match opts.tls_options() {
        Ok(options) => options,
        Err(err) => {
            return json!({
                "name": "stage103-trojan-go-wss-tls-fragment-inner-ss-combination-admission",
                "stage": "stage103",
                "blocked": true,
                "blockers": [format!("stage103 tls options invalid: {err}")]
            });
        }
    };
    let fragment_options = match opts.fragment_options() {
        Ok(options) => options,
        Err(err) => {
            return json!({
                "name": "stage103-trojan-go-wss-tls-fragment-inner-ss-combination-admission",
                "stage": "stage103",
                "blocked": true,
                "blockers": [format!("stage103 tls fragment options invalid: {err}")]
            });
        }
    };
    if let Err(err) = trojan::TrojanMetadata::parse("tcp", &opts.target) {
        return json!({
            "name": "stage103-trojan-go-wss-tls-fragment-inner-ss-combination-admission",
            "stage": "stage103",
            "blocked": true,
            "blockers": [format!("stage103 target is invalid: {err}")]
        });
    }
    if let Err(err) = shadowsocks::ShadowsocksMetadata::parse(&opts.response_metadata_target) {
        return json!({
            "name": "stage103-trojan-go-wss-tls-fragment-inner-ss-combination-admission",
            "stage": "stage103",
            "blocked": true,
            "blockers": [format!("stage103 response metadata target is invalid: {err}")]
        });
    }

    let payload_ascii = String::from_utf8_lossy(&opts.payload).to_string();
    let password_sha224_hex = trojan::packet::password_sha224_hex(&opts.trojan_password);
    let mut report = json!({
        "name": "stage103-trojan-go-wss-tls-fragment-inner-ss-combination-admission",
        "stage": "stage103",
        "evidence_class": "opt-in-protocol-trojan-go-wss-tls-fragment-inner-shadowsocks-combination-true-dataplane-smoke",
        "execute_smoke": opts.execute_smoke,
        "read_only": !opts.execute_smoke,
        "blocked": false,
        "blockers": []
    });
    report["trojan_go_wss_admitted"] = json!(true);
    report["trojan_go_httpupgrade_admitted"] = json!(true);
    report["trojan_go_grpc_hunk_admitted"] = json!(true);
    report["trojan_go_inner_shadowsocks_admitted"] = json!(true);
    report["trojan_go_tls_fragment_admitted"] = json!(true);
    report["trojan_go_utls_fingerprint_selection_admitted"] = json!(true);
    report["trojan_go_utls_fingerprint_wire_admitted"] = json!(false);
    report["trojan_go_utls_fingerprint_admitted"] = json!(false);
    report["reality_session_id_aead_mutation_admitted"] = json!(true);
    report["reality_full_utls_handshake_admitted"] = json!(false);
    report["trojan_go_reality_mutation_admitted"] = json!(false);
    report["trojan_go_cross_combination_recertified"] = json!(false);
    report["trojan_go_wss_tls_fragment_inner_shadowsocks_combination_smoke_passed"] = json!(false);
    report["trojan_go_wss_tls_fragment_inner_shadowsocks_combination_admitted"] = json!(false);
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
    report["combination_contract"] = json!({
        "protocol": "trojan-go",
        "transport": "wss",
        "inner_transport": "inner_shadowsocks",
        "inner_protocol": "trojanc",
        "scope": "Rust SO_MARK/MPTCP TCP underlay -> TLS fragment wrapper -> rustls TLS -> WebSocket binary frame -> inner Shadowsocks AEAD -> raw trojanc TCP request/response",
        "target": opts.target,
        "response_metadata_target": opts.response_metadata_target,
        "tls_server_name": tls_options.server_name,
        "alpn_protocol": tls_options.alpn_protocol,
        "selected_alpn": null,
        "certificate_der_len": null,
        "ws_host": opts.ws_host,
        "ws_path": opts.ws_path
    });
    report["combination_contract"]["encryption"] = json!(format!("ss;{};<redacted>", spec.cipher));
    report["combination_contract"]["cipher"] = json!(spec.cipher);
    report["combination_contract"]["salt_len"] = json!(spec.salt_len);
    report["combination_contract"]["payload_ascii"] = json!(payload_ascii);
    report["combination_contract"]["payload_len"] = json!(opts.payload.len());
    report["combination_contract"]["password_sha224_hex"] = json!(password_sha224_hex);
    report["combination_contract"]["fragment_length"] = json!(opts.fragment_length);
    report["combination_contract"]["fragment_interval"] = json!(opts.fragment_interval);
    report["combination_contract"]["fragment_min_length"] = json!(fragment_options.min_length);
    report["combination_contract"]["fragment_max_length"] = json!(fragment_options.max_length);
    report["combination_contract"]["fragment_min_interval_ms"] =
        json!(fragment_options.min_interval_ms);
    report["combination_contract"]["fragment_max_interval_ms"] =
        json!(fragment_options.max_interval_ms);
    report["combination_contract"]["server"] = json!(null);
    report["combination_contract"]["tls_handshake_validated"] = json!(false);
    report["combination_contract"]["certificate_chain_validated"] = json!(false);
    report["combination_contract"]["server_name_validated"] = json!(false);
    report["combination_contract"]["alpn_validated"] = json!(false);
    report["combination_contract"]["websocket_upgrade_validated"] = json!(false);
    report["combination_contract"]["websocket_binary_frame_validated"] = json!(false);
    report["combination_contract"]["inner_shadowsocks_decrypt_validated"] = json!(false);
    report["combination_contract"]["inner_shadowsocks_is_client"] = json!(false);
    report["combination_contract"]["inner_shadowsocks_request_metadata_present"] = json!(false);
    report["combination_contract"]["response_metadata_validated"] = json!(false);
    report["combination_contract"]["password_sha224_validated"] = json!(false);
    report["combination_contract"]["tcp_command_validated"] = json!(false);
    report["combination_contract"]["target_metadata_validated"] = json!(false);
    report["combination_contract"]["payload_roundtrip_validated"] = json!(false);
    report["combination_contract"]["fragmented_write_count"] = json!(0);
    report["combination_contract"]["fragment_record_count"] = json!(0);
    report["combination_contract"]["handshake_record_fragmented"] = json!(false);
    report["combination_contract"]["fragment_payload_lens"] = json!([]);
    report["combination_contract"]["reassembled_record_matches"] = json!(false);
    report["combination_contract"]["first_fragmented_write"] = json!(null);
    report["combination_contract"]["utls_wire_deferred"] = json!(true);
    report["combination_contract"]["reality_full_handshake_deferred"] = json!(true);
    report["combination_contract"]["grpc_no_double_tls_inherited"] = json!(true);
    report["combination_contract"]["default_go_path_preserved"] = json!(true);
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
        "ns_per_trojan_go_combination_exchange": null,
        "scope": "TLS fragment wrapper plus rustls TLS handshake plus WebSocket Upgrade/binary frame plus inner Shadowsocks AEAD encrypt/decrypt plus trojanc TCP header parse and payload echo over SO_MARKed Rust TCP socket",
        "go_matched_default_daemon_baseline_recorded": false,
        "go_baseline_gap": "all outbound protocols, daemon default lifecycle, and product-chain gates are not closed"
    });
    report["protocol_matrix"] = json!({
        "trojan_go_wss_admitted": true,
        "trojan_go_httpupgrade_admitted": true,
        "trojan_go_grpc_hunk_admitted": true,
        "trojan_go_inner_shadowsocks_admitted": true,
        "trojan_go_tls_fragment_admitted": true,
        "trojan_go_utls_fingerprint_selection_admitted": true,
        "trojan_go_utls_fingerprint_wire_admitted": false,
        "reality_session_id_aead_mutation_admitted": true,
        "reality_full_utls_handshake_admitted": false,
        "trojan_go_reality_mutation_admitted": false,
        "trojan_go_wss_tls_fragment_inner_shadowsocks_combination_admitted": false,
        "trojan_go_cross_combination_recertified": false,
        "trojan_go_shared_transport_partial_admitted": true,
        "trojan_go_shared_transport_admitted": false,
        "shared_transport_true_dataplane_admitted": false,
        "outbound_true_dataplane_admitted": false,
        "quic_h3_session_protocols_admitted": false
    });
    report["remaining_blockers"] = json!([
        "Trojan-Go uTLS wire-level ClientHello fingerprint row is still incomplete",
        "Trojan-Go full REALITY/uTLS handshake mutation row is still incomplete",
        "Trojan-Go cross-combination recertification remains incomplete outside this WSS/TLS-fragment/inner-SS sub-combination",
        "Trojan-Go grpc must remain separately guarded because grpc includes TLS and must not be double-wrapped",
        "VLESS and VMess TLS/WSS/gRPC/Meek/xHTTP full shared transport rows remain protocol-specific blockers",
        "Hysteria2, TUIC, Juicity, AnyTLS, REALITY, Vision, and QUIC/H3 true dataplanes are still incomplete",
        "matched Go default daemon vs true Rust candidate benchmark is still missing",
        "clean dae-wing and daed product-chain recertification is still missing"
    ]);
    report["validation_commands"] = json!([
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage103/trojan_go_wss_tls_fragment_inner_ss_combination_admission.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage103_trojan_go_wss_tls_fragment_inner_ss_combination_gate.json",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound stage103 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage103 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage103 -- --nocapture",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage103-trojan-go-wss-tls-fragment-inner-ss-combination-admission --execute-smoke --ack-root-gate --benchmark-iters 10",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound -p dae-cli -p dae-product",
        "cargo fmt --manifest-path rust/Cargo.toml --all -- --check",
        "git diff --check"
    ]);
    report["source"] = json!([
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage103",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.7",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.11",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.18",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.21",
        "/root/project/outbound/transport/tls/fragment.go",
        "/root/project/outbound/transport/ws/ws.go",
        "/root/project/outbound/dialer/trojan/trojan.go",
        "rust/crates/dae-outbound/src/trojan/wss_inner_shadowsocks_dataplane.rs",
        "rust/crates/dae-datapath/src/tcp_direct.rs"
    ]);

    if !opts.execute_smoke {
        return report;
    }
    if !opts.ack_root_gate {
        report["blocked"] = json!(true);
        report["blockers"] = json!([
            "stage103 root-gated smoke requires --ack-root-gate because it attempts SO_MARK/MPTCP underlay socket observation"
        ]);
        return report;
    }

    match run_stage103_smoke(opts) {
        Ok(outcome) => apply_stage103_outcome(&mut report, outcome),
        Err(err) => {
            report["blocked"] = json!(true);
            report["blockers"] = json!([err]);
        }
    }
    report
}
