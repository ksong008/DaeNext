use dae_outbound::juicity;
use serde_json::{Value, json};

use super::options::Stage125Options;

pub(super) fn stage125_report(opts: &Stage125Options) -> Value {
    let mut report = json!({
        "name": "stage125-juicity-transport-packet-conn-admission",
        "stage": "stage125",
        "evidence_class": "juicity-udp-port-zero-transport-packet-conn-crypto-relay",
        "execute_smoke": opts.execute_smoke,
        "read_only": !opts.execute_smoke,
        "blocked": !opts.execute_smoke,
        "blockers": [
            "stage125 read-only fixture has not executed the TransportPacketConn UDP loopback smoke",
            "Juicity stream PacketConn relay, congestion behavior, full QUIC/H3 client integration, and default/product switching remain blocked",
            "external outbound/quic-go remains required"
        ]
    });
    for key in [
        "quinn_dependency_available",
        "h3_dependency_available",
        "h3_quinn_dependency_available",
        "tokio_quic_runtime_admitted",
        "quinn_runtime_tokio_feature_admitted",
        "quinn_rustls_aws_lc_rs_feature_admitted",
        "h3_quinn_bridge_admitted",
        "juicity_h3_loopback_dependency_admitted",
        "juicity_h3_loopback_smoke_executed",
        "juicity_h3_loopback_benchmark_recorded",
        "juicity_tls_verify_peer_certificate_hook_admitted",
        "juicity_tls_certchain_verification_admitted",
        "juicity_pinned_certchain_live_callback_matched",
        "juicity_h3_handshake_admitted",
        "juicity_native_optin_contract_admitted",
        "juicity_certchain_hash_algorithm_admitted",
        "juicity_pinned_certchain_url_base64_verify_vector_admitted",
        "juicity_pinned_certchain_std_base64_verify_vector_admitted",
        "juicity_pinned_certchain_hex_decode_caveat_recorded",
        "juicity_pinned_certchain_forces_insecure_verify_contract_admitted",
        "juicity_pinned_certchain_full_chain_hash_contract_admitted",
        "juicity_pinned_certchain_not_hysteria2_pin_sha256_recorded",
        "juicity_tls13_h3_alpn_config_contract_admitted",
        "juicity_underlay_contract_admitted",
        "juicity_udp_port_zero_dialauth_contract_recorded",
        "juicity_udp_port_zero_transport_packet_conn_route_admitted",
        "juicity_stream_packet_conn_contract_recorded",
        "juicity_dialauth_record_protocol_state_admitted",
        "juicity_stream_packet_conn_frame_admitted",
        "juicity_authenticate_header_layout_admitted",
        "juicity_auth_uni_stream_write_order_admitted",
        "juicity_dialauth_record_over_auth_stream_admitted",
        "juicity_live_auth_uni_stream_harness_admitted",
        "juicity_live_auth_uni_stream_write_order_admitted",
        "juicity_auth_token_live_ekm_admitted",
        "juicity_live_ekm_auth_header_admitted",
        "juicity_live_ekm_auth_stream_transcript_admitted",
        "juicity_send_authentication_lifecycle_admitted",
        "juicity_underlay_auth_channel_order_admitted",
        "juicity_multiple_dialauth_records_over_auth_stream_admitted",
        "juicity_auth_stream_finish_boundary_admitted",
        "hysteria2_udp_underlay_admitted",
        "tuic_udp_underlay_socket_admitted",
        "quic_h3_family_native_optin_contract_admitted",
        "anytls_true_dataplane_admitted",
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
        "juicity_transport_packet_conn_crypto_admitted",
        "juicity_transport_packet_conn_first_iv_admitted",
        "juicity_transport_packet_conn_udp_roundtrip_admitted",
        "juicity_transport_packet_conn_dataplane_admitted",
        "juicity_stream_packet_conn_dataplane_admitted",
        "juicity_packet_over_stream_admitted",
        "juicity_congestion_behavior_admitted",
        "juicity_true_quic_h3_dataplane_admitted",
        "hysteria2_true_quic_dataplane_admitted",
        "tuic_true_quic_dataplane_admitted",
        "quic_h3_family_true_dataplane_admitted",
        "outbound_true_dataplane_admitted",
        "matched_go_rust_default_daemon_benchmark_recorded",
        "default_switch_allowed",
        "default_path_mutation_allowed",
        "product_chain_switch_allowed",
        "true_rust_default_daemon_admitted",
    ] {
        report[key] = json!(false);
    }
    report["transport_packet_conn"] = json!({
        "target": opts.target,
        "local_server_addr": null,
        "cipher": juicity::JUICITY_TRANSPORT_PACKET_CONN_CIPHER,
        "reused_info_raw": juicity::JUICITY_TRANSPORT_PACKET_CONN_REUSED_INFO_RAW,
        "reused_info_len": juicity::JUICITY_TRANSPORT_PACKET_CONN_REUSED_INFO_RAW.len(),
        "hkdf_hash": "sha1",
        "nonce_len": juicity::JUICITY_TRANSPORT_PACKET_CONN_NONCE_LEN,
        "tag_len": juicity::JUICITY_TRANSPORT_PACKET_CONN_TAG_LEN,
        "underlay_psk_len": juicity::JUICITY_UNDERLAY_AUTH_PSK_LEN,
        "first_iv_len": juicity::JUICITY_UNDERLAY_AUTH_IV_LEN,
        "first_iv_zero_prefix_valid": false,
        "first_packet_uses_dialauth_iv": false,
        "generated_salt_count": 0,
        "generated_salts_zero_prefix_valid": false,
        "payload_len": opts.payload.len(),
        "response_payload_len": opts.response_payload.len(),
        "encrypted_packet_len": null,
        "encrypted_response_packet_len": null,
        "client_packet_sent_count": 0,
        "server_packet_received_count": 0,
        "server_decrypt_count": 0,
        "server_encrypt_count": 0,
        "client_response_received_count": 0,
        "client_decrypt_count": 0,
        "roundtrip_match_count": 0,
        "transport_packet_conn_crypto_validated": false,
        "transport_packet_conn_first_iv_validated": false,
        "transport_packet_conn_udp_roundtrip_validated": false,
        "boundary": "read-only fixture records TransportPacketConn crypto inputs only; execute --execute-smoke to run local UDP loopback seal/open"
    });
    report["benchmark"] = json!({
        "benchmark_recorded": false,
        "iterations": opts.benchmark_iters,
        "elapsed_ns": null,
        "ns_per_juicity_transport_packet_conn_roundtrip": null,
        "payload_len": opts.payload.len(),
        "encrypted_packet_len": null,
        "roundtrip_match_count": 0,
        "scope": "local UDP loopback TransportPacketConn seal/open using DialAuth firstIv/PSK, HKDF-SHA1 JuicityReusedInfo, zero nonce, and chacha20-poly1305; not stream_packet_conn, congestion, full QUIC/H3 client integration, or default/product switching",
        "go_matched_default_daemon_baseline_recorded": false
    });
    report["protocol_matrix"] = json!({
        "hysteria2_udp_underlay_admitted": true,
        "hysteria2_true_quic_dataplane_admitted": false,
        "tuic_udp_underlay_socket_admitted": true,
        "tuic_true_quic_dataplane_admitted": false,
        "juicity_h3_handshake_admitted": true,
        "juicity_tls_certchain_verification_admitted": true,
        "juicity_auth_token_live_ekm_admitted": true,
        "juicity_live_ekm_auth_header_admitted": true,
        "juicity_live_ekm_auth_stream_transcript_admitted": true,
        "juicity_send_authentication_lifecycle_admitted": true,
        "juicity_transport_packet_conn_crypto_admitted": false,
        "juicity_transport_packet_conn_first_iv_admitted": false,
        "juicity_transport_packet_conn_udp_roundtrip_admitted": false,
        "juicity_transport_packet_conn_dataplane_admitted": false,
        "juicity_stream_packet_conn_dataplane_admitted": false,
        "juicity_packet_over_stream_admitted": false,
        "juicity_congestion_behavior_admitted": false,
        "juicity_true_quic_h3_dataplane_admitted": false,
        "quic_h3_family_true_dataplane_admitted": false,
        "anytls_true_dataplane_admitted": true,
        "protocol_outbound_partial_admitted": true,
        "outbound_true_dataplane_admitted": false
    });
    report["remaining_blockers"] = json!([
        "Juicity stream_packet_conn packet-over-stream live relay for nonzero UDP targets",
        "Juicity congestion behavior and packet relay benchmark",
        "full Juicity QUIC/H3 client integration with outbound registry/dialer group/health policy",
        "Hysteria2 full QUIC and TUIC true QUIC dataplanes",
        "matched Go default daemon vs true Rust candidate benchmark",
        "clean dae-wing and daed product-chain recertification"
    ]);
    report["validation_commands"] = json!([
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage125/juicity_transport_packet_conn_admission.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage125_juicity_transport_packet_conn_gate.json",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound stage125 -- --nocapture",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage125-juicity-transport-packet-conn-admission",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage125-juicity-transport-packet-conn-admission --execute-smoke --benchmark-iters 100",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage125 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage125 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound stage124 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound -p dae-cli -p dae-product",
        "cargo fmt --manifest-path rust/Cargo.toml --all -- --check",
        "git diff --check"
    ]);
    report["source"] = json!([
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage125",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.16",
        "/root/project/outbound/protocol/juicity/dialer.go:DialContext",
        "/root/project/outbound/protocol/juicity/transport_packet_conn.go",
        "/root/project/outbound/protocol/shadowsocks/encrypt.go",
        "/root/project/outbound/ciphers/aead_cipher.go",
        "rust/crates/dae-outbound/src/juicity/transport_packet_conn.rs",
        "rust/crates/dae-cli/src/runtime_stage125_juicity_transport_packet_conn_gate/"
    ]);

    if !opts.execute_smoke {
        return report;
    }
    match juicity::run_transport_packet_conn_smoke(&juicity::JuicityTransportPacketConnOptions {
        target: opts.target.clone(),
        payload: opts.payload.clone(),
        response_payload: opts.response_payload.clone(),
        iterations: opts.benchmark_iters,
        timeout: opts.timeout,
    }) {
        Ok(outcome) => apply_stage125_outcome(&mut report, &outcome),
        Err(err) => {
            report["blocked"] = json!(true);
            report["blockers"] = json!([format!("{err}")]);
        }
    }
    report
}

fn apply_stage125_outcome(report: &mut Value, outcome: &juicity::JuicityTransportPacketConnReport) {
    let passed = outcome.juicity_transport_packet_conn_crypto_admitted
        && outcome.juicity_transport_packet_conn_first_iv_admitted
        && outcome.juicity_transport_packet_conn_udp_roundtrip_admitted
        && outcome.juicity_transport_packet_conn_dataplane_admitted;
    report["read_only"] = json!(false);
    report["blocked"] = json!(!passed);
    report["blockers"] = if passed {
        json!([])
    } else {
        json!(["stage125 TransportPacketConn smoke did not satisfy all admission checks"])
    };
    report["juicity_transport_packet_conn_crypto_admitted"] =
        json!(outcome.juicity_transport_packet_conn_crypto_admitted);
    report["juicity_transport_packet_conn_first_iv_admitted"] =
        json!(outcome.juicity_transport_packet_conn_first_iv_admitted);
    report["juicity_transport_packet_conn_udp_roundtrip_admitted"] =
        json!(outcome.juicity_transport_packet_conn_udp_roundtrip_admitted);
    report["juicity_transport_packet_conn_dataplane_admitted"] =
        json!(outcome.juicity_transport_packet_conn_dataplane_admitted);
    report["transport_packet_conn"] = json!({
        "target": outcome.target,
        "local_server_addr": outcome.local_server_addr,
        "cipher": outcome.cipher,
        "reused_info_raw": outcome.reused_info_raw,
        "reused_info_len": outcome.reused_info_len,
        "hkdf_hash": outcome.hkdf_hash,
        "nonce_len": outcome.nonce_len,
        "tag_len": outcome.tag_len,
        "underlay_psk_len": outcome.underlay_psk_len,
        "first_iv_len": outcome.first_iv_len,
        "first_iv_zero_prefix_valid": outcome.first_iv_zero_prefix_valid,
        "first_packet_uses_dialauth_iv": outcome.first_packet_uses_dialauth_iv,
        "generated_salt_count": outcome.generated_salt_count,
        "generated_salts_zero_prefix_valid": outcome.generated_salts_zero_prefix_valid,
        "payload_len": outcome.payload_len,
        "response_payload_len": outcome.response_payload_len,
        "encrypted_packet_len": outcome.encrypted_packet_len,
        "encrypted_response_packet_len": outcome.encrypted_response_packet_len,
        "client_packet_sent_count": outcome.client_packet_sent_count,
        "server_packet_received_count": outcome.server_packet_received_count,
        "server_decrypt_count": outcome.server_decrypt_count,
        "server_encrypt_count": outcome.server_encrypt_count,
        "client_response_received_count": outcome.client_response_received_count,
        "client_decrypt_count": outcome.client_decrypt_count,
        "roundtrip_match_count": outcome.roundtrip_match_count,
        "transport_packet_conn_crypto_validated": outcome.transport_packet_conn_crypto_validated,
        "transport_packet_conn_first_iv_validated": outcome.transport_packet_conn_first_iv_validated,
        "transport_packet_conn_udp_roundtrip_validated": outcome.transport_packet_conn_udp_roundtrip_validated,
        "boundary": "TransportPacketConn UDP port 0 crypto relay is admitted locally; stream_packet_conn, congestion, full QUIC/H3 client integration, outbound/default/product remain closed"
    });
    report["benchmark"] = json!({
        "benchmark_recorded": passed,
        "iterations": outcome.iterations,
        "elapsed_ns": outcome.elapsed_ns,
        "ns_per_juicity_transport_packet_conn_roundtrip": outcome.ns_per_juicity_transport_packet_conn_roundtrip,
        "payload_len": outcome.payload_len,
        "encrypted_packet_len": outcome.encrypted_packet_len,
        "roundtrip_match_count": outcome.roundtrip_match_count,
        "scope": "local UDP loopback TransportPacketConn seal/open using DialAuth firstIv/PSK, HKDF-SHA1 JuicityReusedInfo, zero nonce, and chacha20-poly1305; not stream_packet_conn, congestion, full QUIC/H3 client integration, or default/product switching",
        "go_matched_default_daemon_baseline_recorded": false
    });
    report["protocol_matrix"]["juicity_transport_packet_conn_crypto_admitted"] =
        json!(outcome.juicity_transport_packet_conn_crypto_admitted);
    report["protocol_matrix"]["juicity_transport_packet_conn_first_iv_admitted"] =
        json!(outcome.juicity_transport_packet_conn_first_iv_admitted);
    report["protocol_matrix"]["juicity_transport_packet_conn_udp_roundtrip_admitted"] =
        json!(outcome.juicity_transport_packet_conn_udp_roundtrip_admitted);
    report["protocol_matrix"]["juicity_transport_packet_conn_dataplane_admitted"] =
        json!(outcome.juicity_transport_packet_conn_dataplane_admitted);
}
