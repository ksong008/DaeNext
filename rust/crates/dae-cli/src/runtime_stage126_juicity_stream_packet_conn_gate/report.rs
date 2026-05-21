use dae_outbound::{TrojanMetadata, juicity};
use serde_json::{Value, json};

use super::options::Stage126Options;

pub(super) fn stage126_report(opts: &Stage126Options) -> Value {
    let request_frame = juicity::seal_stream_packet_frame(&opts.target, &opts.payload).ok();
    let response_frame =
        juicity::seal_stream_packet_frame(&opts.response_target, &opts.response_payload).ok();
    let initial_metadata_len = TrojanMetadata::parse("udp", &opts.target)
        .and_then(|metadata| metadata.encode())
        .ok()
        .map(|encoded| encoded.len());
    let request_stream_write_len = initial_metadata_len
        .zip(request_frame.as_ref().map(|frame| frame.encoded.len()))
        .map(|(metadata_len, frame_len)| 1 + metadata_len + frame_len);

    let mut report = json!({
        "name": "stage126-juicity-stream-packet-conn-admission",
        "stage": "stage126",
        "evidence_class": "juicity-nonzero-udp-stream-packet-conn-live-relay",
        "execute_smoke": opts.execute_smoke,
        "read_only": !opts.execute_smoke,
        "blocked": !opts.execute_smoke,
        "blockers": [
            "stage126 read-only fixture has not executed the stream_packet_conn live stream smoke",
            "Juicity congestion behavior, full QUIC/H3 client integration, and default/product switching remain blocked",
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
        "juicity_transport_packet_conn_crypto_admitted",
        "juicity_transport_packet_conn_first_iv_admitted",
        "juicity_transport_packet_conn_udp_roundtrip_admitted",
        "juicity_transport_packet_conn_dataplane_admitted",
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
        "juicity_stream_packet_conn_live_stream_admitted",
        "juicity_stream_packet_conn_frame_order_admitted",
        "juicity_packet_over_stream_admitted",
        "juicity_stream_packet_conn_dataplane_admitted",
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
    report["stream_packet_conn"] = json!({
        "server_name": opts.server_name,
        "target": opts.target,
        "response_target": opts.response_target,
        "alpn_protocol": juicity::DEFAULT_H3_ALPN,
        "client_selected_alpn": null,
        "server_selected_alpn": null,
        "tls13_only_configured": true,
        "quic_datagram_disabled": true,
        "keepalive_secs": juicity::DEFAULT_H3_KEEPALIVE_SECS,
        "handshake_idle_timeout_secs": juicity::DEFAULT_H3_HANDSHAKE_IDLE_TIMEOUT_SECS,
        "loopback_addr": null,
        "connection_network_byte": 3,
        "initial_metadata_len": initial_metadata_len,
        "request_frame_metadata_len": request_frame.as_ref().map(|frame| frame.metadata_len),
        "request_payload_len": opts.payload.len(),
        "request_frame_len": request_frame.as_ref().map(|frame| frame.encoded.len()),
        "request_stream_write_len": request_stream_write_len,
        "response_frame_metadata_len": response_frame.as_ref().map(|frame| frame.metadata_len),
        "response_payload_len": opts.response_payload.len(),
        "response_frame_len": response_frame.as_ref().map(|frame| frame.encoded.len()),
        "open_bi_stream_count": 0,
        "client_stream_finish_count": 0,
        "client_stream_acked_count": 0,
        "server_accept_bi_stream_count": 0,
        "server_request_read_count": 0,
        "server_request_match_count": 0,
        "server_response_write_count": 0,
        "server_stream_finish_count": 0,
        "server_stream_acked_count": 0,
        "client_response_read_count": 0,
        "client_response_match_count": 0,
        "quic_handshake_validated": false,
        "stream_packet_conn_frame_order_validated": false,
        "stream_packet_conn_close_boundary_validated": false,
        "stream_packet_conn_live_relay_validated": false,
        "boundary": "read-only fixture records stream_packet_conn frame shape only; execute --execute-smoke to run local QUIC bidirectional stream relay"
    });
    report["benchmark"] = json!({
        "benchmark_recorded": false,
        "iterations": opts.benchmark_iters,
        "elapsed_ns": null,
        "ns_per_juicity_stream_packet_conn_exchange": null,
        "request_frame_len": request_frame.as_ref().map(|frame| frame.encoded.len()),
        "response_frame_len": response_frame.as_ref().map(|frame| frame.encoded.len()),
        "client_response_match_count": 0,
        "scope": "local QUIC TLS1.3 h3 bidirectional stream relay for Juicity nonzero UDP stream_packet_conn; packet frame is metadata + uint16 length + payload, not QUIC datagram, congestion, full client integration, or default/product switching",
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
        "juicity_transport_packet_conn_crypto_admitted": true,
        "juicity_transport_packet_conn_first_iv_admitted": true,
        "juicity_transport_packet_conn_udp_roundtrip_admitted": true,
        "juicity_transport_packet_conn_dataplane_admitted": true,
        "juicity_stream_packet_conn_live_stream_admitted": false,
        "juicity_stream_packet_conn_frame_order_admitted": false,
        "juicity_packet_over_stream_admitted": false,
        "juicity_stream_packet_conn_dataplane_admitted": false,
        "juicity_congestion_behavior_admitted": false,
        "juicity_true_quic_h3_dataplane_admitted": false,
        "quic_h3_family_true_dataplane_admitted": false,
        "anytls_true_dataplane_admitted": true,
        "protocol_outbound_partial_admitted": true,
        "outbound_true_dataplane_admitted": false
    });
    report["remaining_blockers"] = json!([
        "Juicity congestion behavior and packet relay benchmark under sustained load",
        "full Juicity QUIC/H3 client integration with outbound registry/dialer group/health policy",
        "Hysteria2 full QUIC and TUIC true QUIC dataplanes",
        "matched Go default daemon vs true Rust candidate benchmark",
        "clean dae-wing and daed product-chain recertification"
    ]);
    report["validation_commands"] = json!([
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage126/juicity_stream_packet_conn_admission.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage126_juicity_stream_packet_conn_gate.json",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound stage126 -- --nocapture",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage126-juicity-stream-packet-conn-admission",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage126-juicity-stream-packet-conn-admission --execute-smoke --benchmark-iters 5",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage126 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage126 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound stage125 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound -p dae-cli -p dae-product",
        "cargo fmt --manifest-path rust/Cargo.toml --all -- --check",
        "git diff --check"
    ]);
    report["source"] = json!([
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage126",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.16",
        "/root/project/outbound/protocol/juicity/dialer.go:DialContext",
        "/root/project/outbound/protocol/juicity/stream_conn.go",
        "/root/project/outbound/protocol/juicity/stream_packet_conn.go",
        "rust/crates/dae-outbound/src/juicity/stream_packet_conn.rs",
        "rust/crates/dae-cli/src/runtime_stage126_juicity_stream_packet_conn_gate/"
    ]);

    if !opts.execute_smoke {
        return report;
    }
    match juicity::run_stream_packet_conn_smoke(&juicity::JuicityStreamPacketConnOptions {
        server_name: opts.server_name.clone(),
        target: opts.target.clone(),
        response_target: opts.response_target.clone(),
        payload: opts.payload.clone(),
        response_payload: opts.response_payload.clone(),
        iterations: opts.benchmark_iters,
        timeout: opts.timeout,
    }) {
        Ok(outcome) => apply_stage126_outcome(&mut report, &outcome),
        Err(err) => {
            report["blocked"] = json!(true);
            report["blockers"] = json!([format!("{err}")]);
        }
    }
    report
}

fn apply_stage126_outcome(report: &mut Value, outcome: &juicity::JuicityStreamPacketConnReport) {
    let passed = outcome.juicity_stream_packet_conn_live_stream_admitted
        && outcome.juicity_stream_packet_conn_frame_order_admitted
        && outcome.juicity_packet_over_stream_admitted
        && outcome.juicity_stream_packet_conn_dataplane_admitted;
    report["read_only"] = json!(false);
    report["blocked"] = json!(!passed);
    report["blockers"] = if passed {
        json!([])
    } else {
        json!(["stage126 stream_packet_conn smoke did not satisfy all admission checks"])
    };
    report["juicity_stream_packet_conn_live_stream_admitted"] =
        json!(outcome.juicity_stream_packet_conn_live_stream_admitted);
    report["juicity_stream_packet_conn_frame_order_admitted"] =
        json!(outcome.juicity_stream_packet_conn_frame_order_admitted);
    report["juicity_packet_over_stream_admitted"] =
        json!(outcome.juicity_packet_over_stream_admitted);
    report["juicity_stream_packet_conn_dataplane_admitted"] =
        json!(outcome.juicity_stream_packet_conn_dataplane_admitted);
    report["stream_packet_conn"] = json!({
        "server_name": outcome.server_name,
        "target": outcome.target,
        "response_target": outcome.response_target,
        "alpn_protocol": outcome.alpn_protocol,
        "client_selected_alpn": outcome.client_selected_alpn,
        "server_selected_alpn": outcome.server_selected_alpn,
        "tls13_only_configured": outcome.tls13_only_configured,
        "quic_datagram_disabled": outcome.quic_datagram_disabled,
        "keepalive_secs": outcome.keepalive_secs,
        "handshake_idle_timeout_secs": outcome.handshake_idle_timeout_secs,
        "loopback_addr": outcome.loopback_addr,
        "connection_network_byte": outcome.connection_network_byte,
        "initial_metadata_len": outcome.initial_metadata_len,
        "request_frame_metadata_len": outcome.request_frame_metadata_len,
        "request_payload_len": outcome.request_payload_len,
        "request_frame_len": outcome.request_frame_len,
        "request_stream_write_len": outcome.request_stream_write_len,
        "response_frame_metadata_len": outcome.response_frame_metadata_len,
        "response_payload_len": outcome.response_payload_len,
        "response_frame_len": outcome.response_frame_len,
        "open_bi_stream_count": outcome.open_bi_stream_count,
        "client_stream_finish_count": outcome.client_stream_finish_count,
        "client_stream_acked_count": outcome.client_stream_acked_count,
        "server_accept_bi_stream_count": outcome.server_accept_bi_stream_count,
        "server_request_read_count": outcome.server_request_read_count,
        "server_request_match_count": outcome.server_request_match_count,
        "server_response_write_count": outcome.server_response_write_count,
        "server_stream_finish_count": outcome.server_stream_finish_count,
        "server_stream_acked_count": outcome.server_stream_acked_count,
        "client_response_read_count": outcome.client_response_read_count,
        "client_response_match_count": outcome.client_response_match_count,
        "quic_handshake_validated": outcome.quic_handshake_validated,
        "stream_packet_conn_frame_order_validated": outcome.stream_packet_conn_frame_order_validated,
        "stream_packet_conn_close_boundary_validated": outcome.stream_packet_conn_close_boundary_validated,
        "stream_packet_conn_live_relay_validated": outcome.stream_packet_conn_live_relay_validated,
        "boundary": "nonzero UDP stream_packet_conn packet-over-stream live relay is admitted locally; congestion, full QUIC/H3 client integration, outbound/default/product remain closed"
    });
    report["benchmark"] = json!({
        "benchmark_recorded": passed,
        "iterations": outcome.iterations,
        "elapsed_ns": outcome.elapsed_ns,
        "ns_per_juicity_stream_packet_conn_exchange": outcome.ns_per_juicity_stream_packet_conn_exchange,
        "request_frame_len": outcome.request_frame_len,
        "response_frame_len": outcome.response_frame_len,
        "client_response_match_count": outcome.client_response_match_count,
        "scope": "local QUIC TLS1.3 h3 bidirectional stream relay for Juicity nonzero UDP stream_packet_conn; packet frame is metadata + uint16 length + payload, not QUIC datagram, congestion, full client integration, or default/product switching",
        "go_matched_default_daemon_baseline_recorded": false
    });
    report["protocol_matrix"]["juicity_stream_packet_conn_live_stream_admitted"] =
        json!(outcome.juicity_stream_packet_conn_live_stream_admitted);
    report["protocol_matrix"]["juicity_stream_packet_conn_frame_order_admitted"] =
        json!(outcome.juicity_stream_packet_conn_frame_order_admitted);
    report["protocol_matrix"]["juicity_packet_over_stream_admitted"] =
        json!(outcome.juicity_packet_over_stream_admitted);
    report["protocol_matrix"]["juicity_stream_packet_conn_dataplane_admitted"] =
        json!(outcome.juicity_stream_packet_conn_dataplane_admitted);
}
