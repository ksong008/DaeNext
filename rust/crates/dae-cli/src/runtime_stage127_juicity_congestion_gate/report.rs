use dae_outbound::{TrojanMetadata, juicity};
use serde_json::{Value, json};

use super::options::Stage127Options;

pub(super) fn stage127_report(opts: &Stage127Options) -> Value {
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
    let effective_congestion = juicity::normalize_congestion_control(&opts.congestion_control);

    let mut report = json!({
        "name": "stage127-juicity-congestion-admission",
        "stage": "stage127",
        "evidence_class": "juicity-bbr-congestion-sustained-packet-over-stream-relay",
        "execute_smoke": opts.execute_smoke,
        "read_only": !opts.execute_smoke,
        "blocked": !opts.execute_smoke,
        "blockers": [
            "stage127 read-only fixture has not executed the BBR sustained stream_packet_conn smoke",
            "full Juicity QUIC/H3 client integration and default/product switching remain blocked",
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
        "juicity_stream_packet_conn_live_stream_admitted",
        "juicity_stream_packet_conn_frame_order_admitted",
        "juicity_packet_over_stream_admitted",
        "juicity_stream_packet_conn_dataplane_admitted",
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
        "juicity_congestion_bbr_controller_admitted",
        "juicity_congestion_sustained_relay_admitted",
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
    let mut congestion = json!({});
    congestion["server_name"] = json!(opts.server_name);
    congestion["target"] = json!(opts.target);
    congestion["response_target"] = json!(opts.response_target);
    congestion["alpn_protocol"] = json!(juicity::DEFAULT_H3_ALPN);
    congestion["client_selected_alpn"] = json!(null);
    congestion["server_selected_alpn"] = json!(null);
    congestion["tls13_only_configured"] = json!(true);
    congestion["quic_datagram_disabled"] = json!(true);
    congestion["keepalive_secs"] = json!(juicity::DEFAULT_H3_KEEPALIVE_SECS);
    congestion["handshake_idle_timeout_secs"] =
        json!(juicity::DEFAULT_H3_HANDSHAKE_IDLE_TIMEOUT_SECS);
    congestion["loopback_addr"] = json!(null);
    congestion["congestion_control_requested"] = json!(opts.congestion_control);
    congestion["congestion_control_effective"] = json!(effective_congestion);
    congestion["go_congestion_control_default"] = json!(juicity::GO_JUICITY_CONGESTION_DEFAULT);
    congestion["go_cwnd_param"] = json!(juicity::GO_JUICITY_CONGESTION_CWND_PARAM);
    congestion["go_bbr_initial_congestion_window_packets"] =
        json!(juicity::GO_BBR_INITIAL_CONGESTION_WINDOW_PACKETS);
    congestion["go_bbr_initial_packet_size_ipv4"] = json!(juicity::GO_BBR_INITIAL_PACKET_SIZE_IPV4);
    congestion["rust_bbr_initial_window_bytes"] = json!(juicity::RUST_BBR_INITIAL_WINDOW_BYTES);
    congestion["bbr_factory_configured"] = json!(true);
    congestion["iterations"] = json!(opts.benchmark_iters);
    congestion["max_in_flight_streams"] = json!(opts.max_in_flight_streams);
    congestion["max_in_flight_observed"] = json!(0);
    congestion["connection_network_byte"] = json!(3);
    congestion["initial_metadata_len"] = json!(initial_metadata_len);
    congestion["request_frame_metadata_len"] =
        json!(request_frame.as_ref().map(|frame| frame.metadata_len));
    congestion["request_payload_len"] = json!(opts.payload.len());
    congestion["request_frame_len"] =
        json!(request_frame.as_ref().map(|frame| frame.encoded.len()));
    congestion["request_stream_write_len"] = json!(request_stream_write_len);
    congestion["response_frame_metadata_len"] =
        json!(response_frame.as_ref().map(|frame| frame.metadata_len));
    congestion["response_payload_len"] = json!(opts.response_payload.len());
    congestion["response_frame_len"] =
        json!(response_frame.as_ref().map(|frame| frame.encoded.len()));
    congestion["total_request_payload_bytes"] = json!(opts.payload.len() * opts.benchmark_iters);
    congestion["total_response_payload_bytes"] =
        json!(opts.response_payload.len() * opts.benchmark_iters);
    for key in [
        "open_bi_stream_count",
        "client_stream_finish_count",
        "client_stream_acked_count",
        "server_accept_bi_stream_count",
        "server_request_read_count",
        "server_request_match_count",
        "server_response_write_count",
        "server_stream_finish_count",
        "server_stream_acked_count",
        "client_response_read_count",
        "client_response_match_count",
        "client_sent_packets_delta",
    ] {
        congestion[key] = json!(0);
    }
    for key in [
        "client_cwnd_bytes",
        "client_congestion_events",
        "client_lost_packets",
        "client_current_mtu",
        "client_rtt_ns",
        "server_sent_packets",
        "server_cwnd_bytes",
        "server_congestion_events",
        "server_lost_packets",
        "server_current_mtu",
        "server_rtt_ns",
    ] {
        congestion[key] = json!(null);
    }
    for key in [
        "quic_handshake_validated",
        "stream_packet_conn_sustained_relay_validated",
        "stream_packet_conn_congestion_stats_recorded",
        "stream_packet_conn_bbr_controller_validated",
    ] {
        congestion[key] = json!(false);
    }
    congestion["boundary"] = json!(
        "read-only fixture records BBR/congestion and sustained relay shape only; execute --execute-smoke to run local sustained packet-over-stream benchmark"
    );
    report["stream_packet_congestion"] = congestion;
    report["benchmark"] = json!({
        "benchmark_recorded": false,
        "iterations": opts.benchmark_iters,
        "max_in_flight_streams": opts.max_in_flight_streams,
        "elapsed_ns": null,
        "ns_per_juicity_stream_packet_congestion_exchange": null,
        "request_payload_len": opts.payload.len(),
        "response_payload_len": opts.response_payload.len(),
        "total_request_payload_bytes": opts.payload.len() * opts.benchmark_iters,
        "total_response_payload_bytes": opts.response_payload.len() * opts.benchmark_iters,
        "client_response_match_count": 0,
        "client_cwnd_bytes": null,
        "server_cwnd_bytes": null,
        "scope": "local QUIC TLS1.3 h3 BBR-configured sustained stream_packet_conn relay; not full Juicity client integration, outbound registry switching, default daemon, or product-chain switching",
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
        "juicity_stream_packet_conn_live_stream_admitted": true,
        "juicity_stream_packet_conn_frame_order_admitted": true,
        "juicity_packet_over_stream_admitted": true,
        "juicity_stream_packet_conn_dataplane_admitted": true,
        "juicity_congestion_bbr_controller_admitted": false,
        "juicity_congestion_sustained_relay_admitted": false,
        "juicity_congestion_behavior_admitted": false,
        "juicity_true_quic_h3_dataplane_admitted": false,
        "quic_h3_family_true_dataplane_admitted": false,
        "anytls_true_dataplane_admitted": true,
        "protocol_outbound_partial_admitted": true,
        "outbound_true_dataplane_admitted": false
    });
    report["remaining_blockers"] = json!([
        "full Juicity QUIC/H3 client integration with outbound registry/dialer group/health policy",
        "Hysteria2 full QUIC and TUIC true QUIC dataplanes",
        "matched Go default daemon vs true Rust candidate benchmark",
        "clean dae-wing and daed product-chain recertification"
    ]);
    report["validation_commands"] = json!([
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage127/juicity_congestion_admission.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage127_juicity_congestion_gate.json",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound stage127 -- --nocapture",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage127-juicity-congestion-admission",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage127-juicity-congestion-admission --execute-smoke --benchmark-iters 16 --max-in-flight-streams 4",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage127 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage127 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound stage126 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound -p dae-cli -p dae-product",
        "cargo fmt --manifest-path rust/Cargo.toml --all -- --check",
        "git diff --check"
    ]);
    report["source"] = json!([
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage127",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.16",
        "/root/project/outbound/dialer/juicity/juicity.go",
        "/root/project/outbound/protocol/juicity/dialer.go",
        "/root/project/outbound/protocol/juicity/client.go",
        "/root/project/outbound/protocol/tuic/common/congestion.go",
        "/root/project/outbound/protocol/tuic/congestion/bbr/bbr_sender.go",
        "rust/crates/dae-outbound/src/juicity/stream_packet_congestion.rs",
        "rust/crates/dae-cli/src/runtime_stage127_juicity_congestion_gate/"
    ]);

    if !opts.execute_smoke {
        return report;
    }
    match juicity::run_stream_packet_congestion_smoke(
        &juicity::JuicityStreamPacketCongestionOptions {
            server_name: opts.server_name.clone(),
            target: opts.target.clone(),
            response_target: opts.response_target.clone(),
            payload: opts.payload.clone(),
            response_payload: opts.response_payload.clone(),
            iterations: opts.benchmark_iters,
            max_in_flight_streams: opts.max_in_flight_streams,
            congestion_control: opts.congestion_control.clone(),
            timeout: opts.timeout,
        },
    ) {
        Ok(outcome) => apply_stage127_outcome(&mut report, &outcome),
        Err(err) => {
            report["blocked"] = json!(true);
            report["blockers"] = json!([format!("{err}")]);
        }
    }
    report
}

fn apply_stage127_outcome(
    report: &mut Value,
    outcome: &juicity::JuicityStreamPacketCongestionReport,
) {
    let passed = outcome.juicity_congestion_bbr_controller_admitted
        && outcome.juicity_congestion_sustained_relay_admitted
        && outcome.juicity_congestion_behavior_admitted;
    report["read_only"] = json!(false);
    report["blocked"] = json!(!passed);
    report["blockers"] = if passed {
        json!([])
    } else {
        json!(["stage127 congestion smoke did not satisfy all admission checks"])
    };
    report["juicity_congestion_bbr_controller_admitted"] =
        json!(outcome.juicity_congestion_bbr_controller_admitted);
    report["juicity_congestion_sustained_relay_admitted"] =
        json!(outcome.juicity_congestion_sustained_relay_admitted);
    report["juicity_congestion_behavior_admitted"] =
        json!(outcome.juicity_congestion_behavior_admitted);
    let mut congestion = json!({});
    congestion["server_name"] = json!(outcome.server_name);
    congestion["target"] = json!(outcome.target);
    congestion["response_target"] = json!(outcome.response_target);
    congestion["alpn_protocol"] = json!(outcome.alpn_protocol);
    congestion["client_selected_alpn"] = json!(outcome.client_selected_alpn);
    congestion["server_selected_alpn"] = json!(outcome.server_selected_alpn);
    congestion["tls13_only_configured"] = json!(outcome.tls13_only_configured);
    congestion["quic_datagram_disabled"] = json!(outcome.quic_datagram_disabled);
    congestion["keepalive_secs"] = json!(outcome.keepalive_secs);
    congestion["handshake_idle_timeout_secs"] = json!(outcome.handshake_idle_timeout_secs);
    congestion["loopback_addr"] = json!(outcome.loopback_addr);
    congestion["congestion_control_requested"] = json!(outcome.congestion_control_requested);
    congestion["congestion_control_effective"] = json!(outcome.congestion_control_effective);
    congestion["go_congestion_control_default"] = json!(outcome.go_congestion_control_default);
    congestion["go_cwnd_param"] = json!(outcome.go_cwnd_param);
    congestion["go_bbr_initial_congestion_window_packets"] =
        json!(outcome.go_bbr_initial_congestion_window_packets);
    congestion["go_bbr_initial_packet_size_ipv4"] = json!(outcome.go_bbr_initial_packet_size_ipv4);
    congestion["rust_bbr_initial_window_bytes"] = json!(outcome.rust_bbr_initial_window_bytes);
    congestion["bbr_factory_configured"] = json!(outcome.bbr_factory_configured);
    congestion["iterations"] = json!(outcome.iterations);
    congestion["max_in_flight_streams"] = json!(outcome.max_in_flight_streams);
    congestion["max_in_flight_observed"] = json!(outcome.max_in_flight_observed);
    congestion["connection_network_byte"] = json!(outcome.connection_network_byte);
    congestion["initial_metadata_len"] = json!(outcome.initial_metadata_len);
    congestion["request_frame_metadata_len"] = json!(outcome.request_frame_metadata_len);
    congestion["request_payload_len"] = json!(outcome.request_payload_len);
    congestion["request_frame_len"] = json!(outcome.request_frame_len);
    congestion["request_stream_write_len"] = json!(outcome.request_stream_write_len);
    congestion["response_frame_metadata_len"] = json!(outcome.response_frame_metadata_len);
    congestion["response_payload_len"] = json!(outcome.response_payload_len);
    congestion["response_frame_len"] = json!(outcome.response_frame_len);
    congestion["total_request_payload_bytes"] = json!(outcome.total_request_payload_bytes);
    congestion["total_response_payload_bytes"] = json!(outcome.total_response_payload_bytes);
    congestion["open_bi_stream_count"] = json!(outcome.open_bi_stream_count);
    congestion["client_stream_finish_count"] = json!(outcome.client_stream_finish_count);
    congestion["client_stream_acked_count"] = json!(outcome.client_stream_acked_count);
    congestion["server_accept_bi_stream_count"] = json!(outcome.server_accept_bi_stream_count);
    congestion["server_request_read_count"] = json!(outcome.server_request_read_count);
    congestion["server_request_match_count"] = json!(outcome.server_request_match_count);
    congestion["server_response_write_count"] = json!(outcome.server_response_write_count);
    congestion["server_stream_finish_count"] = json!(outcome.server_stream_finish_count);
    congestion["server_stream_acked_count"] = json!(outcome.server_stream_acked_count);
    congestion["client_response_read_count"] = json!(outcome.client_response_read_count);
    congestion["client_response_match_count"] = json!(outcome.client_response_match_count);
    congestion["client_sent_packets_delta"] = json!(outcome.client_sent_packets_delta);
    congestion["client_cwnd_bytes"] = json!(outcome.client_cwnd_bytes);
    congestion["client_congestion_events"] = json!(outcome.client_congestion_events);
    congestion["client_lost_packets"] = json!(outcome.client_lost_packets);
    congestion["client_current_mtu"] = json!(outcome.client_current_mtu);
    congestion["client_rtt_ns"] = json!(outcome.client_rtt_ns);
    congestion["server_sent_packets"] = json!(outcome.server_sent_packets);
    congestion["server_cwnd_bytes"] = json!(outcome.server_cwnd_bytes);
    congestion["server_congestion_events"] = json!(outcome.server_congestion_events);
    congestion["server_lost_packets"] = json!(outcome.server_lost_packets);
    congestion["server_current_mtu"] = json!(outcome.server_current_mtu);
    congestion["server_rtt_ns"] = json!(outcome.server_rtt_ns);
    congestion["quic_handshake_validated"] = json!(outcome.quic_handshake_validated);
    congestion["stream_packet_conn_sustained_relay_validated"] =
        json!(outcome.stream_packet_conn_sustained_relay_validated);
    congestion["stream_packet_conn_congestion_stats_recorded"] =
        json!(outcome.stream_packet_conn_congestion_stats_recorded);
    congestion["stream_packet_conn_bbr_controller_validated"] =
        json!(outcome.stream_packet_conn_bbr_controller_validated);
    congestion["boundary"] = json!(
        "BBR-configured sustained stream_packet_conn relay is admitted locally; full Juicity client integration, outbound/default/product remain closed"
    );
    report["stream_packet_congestion"] = congestion;
    report["benchmark"] = json!({
        "benchmark_recorded": passed,
        "iterations": outcome.iterations,
        "max_in_flight_streams": outcome.max_in_flight_streams,
        "elapsed_ns": outcome.elapsed_ns,
        "ns_per_juicity_stream_packet_congestion_exchange": outcome.ns_per_juicity_stream_packet_congestion_exchange,
        "request_payload_len": outcome.request_payload_len,
        "response_payload_len": outcome.response_payload_len,
        "total_request_payload_bytes": outcome.total_request_payload_bytes,
        "total_response_payload_bytes": outcome.total_response_payload_bytes,
        "client_response_match_count": outcome.client_response_match_count,
        "client_cwnd_bytes": outcome.client_cwnd_bytes,
        "server_cwnd_bytes": outcome.server_cwnd_bytes,
        "scope": "local QUIC TLS1.3 h3 BBR-configured sustained stream_packet_conn relay; not full Juicity client integration, outbound registry switching, default daemon, or product-chain switching",
        "go_matched_default_daemon_baseline_recorded": false
    });
    report["protocol_matrix"]["juicity_congestion_bbr_controller_admitted"] =
        json!(outcome.juicity_congestion_bbr_controller_admitted);
    report["protocol_matrix"]["juicity_congestion_sustained_relay_admitted"] =
        json!(outcome.juicity_congestion_sustained_relay_admitted);
    report["protocol_matrix"]["juicity_congestion_behavior_admitted"] =
        json!(outcome.juicity_congestion_behavior_admitted);
}
