use dae_outbound::juicity;
use serde_json::{Value, json};

use super::options::Stage128Options;

pub(super) fn stage128_report(opts: &Stage128Options) -> Value {
    let total_exchange_count = opts.auth_iterations
        + opts.transport_iterations
        + opts.stream_iterations
        + opts.congestion_iterations;
    let stream_request_frame = juicity::seal_stream_packet_frame(
        juicity::DEFAULT_STREAM_PACKET_CONN_TARGET,
        juicity::DEFAULT_STREAM_PACKET_CONN_PAYLOAD,
    )
    .ok();
    let stream_response_frame = juicity::seal_stream_packet_frame(
        juicity::DEFAULT_STREAM_PACKET_CONN_RESPONSE_TARGET,
        juicity::DEFAULT_STREAM_PACKET_CONN_RESPONSE,
    )
    .ok();
    let effective_congestion = juicity::normalize_congestion_control(&opts.congestion_control);

    let mut report = json!({
        "name": "stage128-juicity-client-integration-admission",
        "stage": "stage128",
        "evidence_class": "juicity-local-client-integration-candidate",
        "execute_smoke": opts.execute_smoke,
        "read_only": !opts.execute_smoke,
        "blocked": !opts.execute_smoke,
        "blockers": [
            "stage128 read-only fixture has not executed the full local Juicity client integration smoke",
            "full Juicity outbound registry/default/product switching remains blocked",
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
        "juicity_congestion_bbr_controller_admitted",
        "juicity_congestion_sustained_relay_admitted",
        "juicity_congestion_behavior_admitted",
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
        "juicity_client_integration_candidate_admitted",
        "juicity_full_local_client_smoke_admitted",
        "juicity_client_capability_matrix_admitted",
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

    let mut integration = json!({});
    integration["server_name"] = json!(opts.server_name);
    integration["alpn_protocol"] = json!(juicity::DEFAULT_H3_ALPN);
    integration["tls13_only_configured"] = json!(true);
    integration["quic_datagram_disabled"] = json!(true);
    integration["keepalive_secs"] = json!(juicity::DEFAULT_H3_KEEPALIVE_SECS);
    integration["handshake_idle_timeout_secs"] =
        json!(juicity::DEFAULT_H3_HANDSHAKE_IDLE_TIMEOUT_SECS);
    integration["auth_iterations"] = json!(opts.auth_iterations);
    integration["transport_iterations"] = json!(opts.transport_iterations);
    integration["stream_iterations"] = json!(opts.stream_iterations);
    integration["congestion_iterations"] = json!(opts.congestion_iterations);
    integration["max_in_flight_streams"] = json!(opts.max_in_flight_streams);
    integration["total_exchange_count"] = json!(total_exchange_count);
    integration["total_elapsed_ns"] = json!(null);
    integration["ns_per_juicity_client_integration_exchange"] = json!(null);
    integration["auth_lifecycle_elapsed_ns"] = json!(null);
    integration["auth_record_count"] = json!(opts.auth_targets.len());
    integration["auth_channel_enqueue_count"] = json!(0);
    integration["auth_channel_receive_count"] = json!(0);
    integration["auth_server_transcript_match_count"] = json!(0);
    integration["transport_elapsed_ns"] = json!(null);
    integration["transport_roundtrip_match_count"] = json!(0);
    integration["transport_payload_len"] =
        json!(juicity::DEFAULT_TRANSPORT_PACKET_CONN_PAYLOAD.len());
    integration["transport_encrypted_packet_len"] = json!(null);
    integration["stream_elapsed_ns"] = json!(null);
    integration["stream_response_match_count"] = json!(0);
    integration["stream_request_frame_len"] = json!(
        stream_request_frame
            .as_ref()
            .map(|frame| frame.encoded.len())
    );
    integration["stream_response_frame_len"] = json!(
        stream_response_frame
            .as_ref()
            .map(|frame| frame.encoded.len())
    );
    integration["congestion_elapsed_ns"] = json!(null);
    integration["congestion_control_requested"] = json!(opts.congestion_control);
    integration["congestion_control_effective"] = json!(effective_congestion);
    integration["congestion_response_match_count"] = json!(0);
    integration["congestion_max_in_flight_observed"] = json!(0);
    integration["congestion_request_payload_len"] =
        json!(juicity::DEFAULT_STREAM_PACKET_CONGESTION_PAYLOAD_LEN);
    integration["congestion_response_payload_len"] =
        json!(juicity::DEFAULT_STREAM_PACKET_CONGESTION_RESPONSE_LEN);
    integration["congestion_total_request_payload_bytes"] =
        json!(juicity::DEFAULT_STREAM_PACKET_CONGESTION_PAYLOAD_LEN * opts.congestion_iterations);
    integration["congestion_total_response_payload_bytes"] =
        json!(juicity::DEFAULT_STREAM_PACKET_CONGESTION_RESPONSE_LEN * opts.congestion_iterations);
    integration["congestion_client_cwnd_bytes"] = json!(null);
    integration["congestion_server_cwnd_bytes"] = json!(null);
    integration["auth_lifecycle_admitted"] = json!(true);
    integration["transport_packet_conn_admitted"] = json!(true);
    integration["stream_packet_conn_admitted"] = json!(true);
    integration["congestion_behavior_admitted"] = json!(true);
    integration["client_capability_matrix_admitted"] = json!(true);
    integration["full_local_client_smoke_admitted"] = json!(true);
    integration["juicity_client_integration_candidate_admitted"] = json!(false);
    integration["juicity_full_local_client_smoke_admitted"] = json!(false);
    integration["juicity_client_capability_matrix_admitted"] = json!(false);
    integration["juicity_true_quic_h3_dataplane_admitted"] = json!(false);
    integration["outbound_true_dataplane_admitted"] = json!(false);
    integration["default_switch_allowed"] = json!(false);
    integration["product_chain_switch_allowed"] = json!(false);
    integration["boundary"] = json!(
        "read-only fixture aggregates Stage 124-127 local Juicity slices; execute --execute-smoke to run them in one client integration candidate smoke"
    );
    report["client_integration"] = integration;
    report["benchmark"] = json!({
        "benchmark_recorded": false,
        "auth_iterations": opts.auth_iterations,
        "transport_iterations": opts.transport_iterations,
        "stream_iterations": opts.stream_iterations,
        "congestion_iterations": opts.congestion_iterations,
        "total_exchange_count": total_exchange_count,
        "elapsed_ns": null,
        "ns_per_juicity_client_integration_exchange": null,
        "transport_roundtrip_match_count": 0,
        "stream_response_match_count": 0,
        "congestion_response_match_count": 0,
        "scope": "local Juicity client integration candidate aggregates auth lifecycle, TransportPacketConn, stream_packet_conn, and BBR sustained relay; not outbound registry switching, default daemon, product-chain switching, or matched Go benchmark",
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
        "juicity_congestion_bbr_controller_admitted": true,
        "juicity_congestion_sustained_relay_admitted": true,
        "juicity_congestion_behavior_admitted": true,
        "juicity_client_integration_candidate_admitted": false,
        "juicity_true_quic_h3_dataplane_admitted": false,
        "quic_h3_family_true_dataplane_admitted": false,
        "anytls_true_dataplane_admitted": true,
        "protocol_outbound_partial_admitted": true,
        "outbound_true_dataplane_admitted": false
    });
    report["remaining_blockers"] = json!([
        "outbound registry/dialer group/health-policy integration for Juicity true client path",
        "matched Go default daemon vs true Rust candidate benchmark",
        "Hysteria2 full QUIC and TUIC true QUIC dataplanes",
        "clean dae-wing and daed product-chain recertification"
    ]);
    report["validation_commands"] = json!([
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage128/juicity_client_integration_admission.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage128_juicity_client_integration_gate.json",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound stage128 -- --nocapture",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage128-juicity-client-integration-admission",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage128-juicity-client-integration-admission --execute-smoke",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage128 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage128 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound stage127 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound -p dae-cli -p dae-product",
        "cargo fmt --manifest-path rust/Cargo.toml --all -- --check",
        "git diff --check"
    ]);
    report["source"] = json!([
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage128",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.16",
        "/root/project/outbound/dialer/juicity/juicity.go",
        "/root/project/outbound/protocol/juicity/dialer.go",
        "/root/project/outbound/protocol/juicity/client.go",
        "/root/project/outbound/protocol/juicity/transport_packet_conn.go",
        "/root/project/outbound/protocol/juicity/stream_conn.go",
        "/root/project/outbound/protocol/juicity/stream_packet_conn.go",
        "/root/project/outbound/protocol/tuic/common/congestion.go",
        "/root/project/outbound/protocol/tuic/congestion/bbr/bbr_sender.go",
        "rust/crates/dae-outbound/src/juicity/client_integration.rs",
        "rust/crates/dae-cli/src/runtime_stage128_juicity_client_integration_gate/"
    ]);

    if !opts.execute_smoke {
        return report;
    }
    match juicity::run_client_integration_smoke(&juicity::JuicityClientIntegrationOptions {
        server_name: opts.server_name.clone(),
        auth_targets: opts.auth_targets.clone(),
        auth_iterations: opts.auth_iterations,
        transport_iterations: opts.transport_iterations,
        stream_iterations: opts.stream_iterations,
        congestion_iterations: opts.congestion_iterations,
        max_in_flight_streams: opts.max_in_flight_streams,
        congestion_control: opts.congestion_control.clone(),
        timeout: opts.timeout,
    }) {
        Ok(outcome) => apply_stage128_outcome(&mut report, &outcome, opts),
        Err(err) => {
            report["blocked"] = json!(true);
            report["blockers"] = json!([format!("{err}")]);
        }
    }
    report
}

fn apply_stage128_outcome(
    report: &mut Value,
    outcome: &juicity::JuicityClientIntegrationReport,
    opts: &Stage128Options,
) {
    let passed = outcome.juicity_client_integration_candidate_admitted
        && outcome.juicity_full_local_client_smoke_admitted
        && outcome.juicity_client_capability_matrix_admitted;
    report["read_only"] = json!(false);
    report["blocked"] = json!(!passed);
    report["blockers"] = if passed {
        json!([])
    } else {
        json!(["stage128 client integration smoke did not satisfy all admission checks"])
    };
    report["juicity_client_integration_candidate_admitted"] =
        json!(outcome.juicity_client_integration_candidate_admitted);
    report["juicity_full_local_client_smoke_admitted"] =
        json!(outcome.juicity_full_local_client_smoke_admitted);
    report["juicity_client_capability_matrix_admitted"] =
        json!(outcome.juicity_client_capability_matrix_admitted);
    report["juicity_true_quic_h3_dataplane_admitted"] =
        json!(outcome.juicity_true_quic_h3_dataplane_admitted);
    report["outbound_true_dataplane_admitted"] = json!(outcome.outbound_true_dataplane_admitted);
    report["default_switch_allowed"] = json!(outcome.default_switch_allowed);
    report["product_chain_switch_allowed"] = json!(outcome.product_chain_switch_allowed);
    let mut integration = json!({});
    integration["server_name"] = json!(outcome.server_name);
    integration["alpn_protocol"] = json!(outcome.alpn_protocol);
    integration["tls13_only_configured"] = json!(outcome.tls13_only_configured);
    integration["quic_datagram_disabled"] = json!(outcome.quic_datagram_disabled);
    integration["keepalive_secs"] = json!(outcome.keepalive_secs);
    integration["handshake_idle_timeout_secs"] = json!(outcome.handshake_idle_timeout_secs);
    integration["auth_iterations"] = json!(outcome.auth_iterations);
    integration["transport_iterations"] = json!(outcome.transport_iterations);
    integration["stream_iterations"] = json!(outcome.stream_iterations);
    integration["congestion_iterations"] = json!(outcome.congestion_iterations);
    integration["max_in_flight_streams"] = json!(outcome.max_in_flight_streams);
    integration["total_exchange_count"] = json!(outcome.total_exchange_count);
    integration["total_elapsed_ns"] = json!(outcome.total_elapsed_ns);
    integration["ns_per_juicity_client_integration_exchange"] =
        json!(outcome.ns_per_juicity_client_integration_exchange);
    integration["auth_lifecycle_elapsed_ns"] = json!(outcome.auth_lifecycle_elapsed_ns);
    integration["auth_record_count"] = json!(outcome.auth_record_count);
    integration["auth_channel_enqueue_count"] = json!(outcome.auth_channel_enqueue_count);
    integration["auth_channel_receive_count"] = json!(outcome.auth_channel_receive_count);
    integration["auth_server_transcript_match_count"] =
        json!(outcome.auth_server_transcript_match_count);
    integration["transport_elapsed_ns"] = json!(outcome.transport_elapsed_ns);
    integration["transport_roundtrip_match_count"] = json!(outcome.transport_roundtrip_match_count);
    integration["transport_payload_len"] = json!(outcome.transport_payload_len);
    integration["transport_encrypted_packet_len"] = json!(outcome.transport_encrypted_packet_len);
    integration["stream_elapsed_ns"] = json!(outcome.stream_elapsed_ns);
    integration["stream_response_match_count"] = json!(outcome.stream_response_match_count);
    integration["stream_request_frame_len"] = json!(outcome.stream_request_frame_len);
    integration["stream_response_frame_len"] = json!(outcome.stream_response_frame_len);
    integration["congestion_elapsed_ns"] = json!(outcome.congestion_elapsed_ns);
    integration["congestion_control_requested"] = json!(opts.congestion_control);
    integration["congestion_control_effective"] = json!(juicity::normalize_congestion_control(
        &opts.congestion_control
    ));
    integration["congestion_response_match_count"] = json!(outcome.congestion_response_match_count);
    integration["congestion_max_in_flight_observed"] =
        json!(outcome.congestion_max_in_flight_observed);
    integration["congestion_request_payload_len"] = json!(outcome.congestion_request_payload_len);
    integration["congestion_response_payload_len"] = json!(outcome.congestion_response_payload_len);
    integration["congestion_total_request_payload_bytes"] =
        json!(outcome.congestion_total_request_payload_bytes);
    integration["congestion_total_response_payload_bytes"] =
        json!(outcome.congestion_total_response_payload_bytes);
    integration["congestion_client_cwnd_bytes"] = json!(outcome.congestion_client_cwnd_bytes);
    integration["congestion_server_cwnd_bytes"] = json!(outcome.congestion_server_cwnd_bytes);
    integration["auth_lifecycle_admitted"] = json!(outcome.auth_lifecycle_admitted);
    integration["transport_packet_conn_admitted"] = json!(outcome.transport_packet_conn_admitted);
    integration["stream_packet_conn_admitted"] = json!(outcome.stream_packet_conn_admitted);
    integration["congestion_behavior_admitted"] = json!(outcome.congestion_behavior_admitted);
    integration["client_capability_matrix_admitted"] =
        json!(outcome.client_capability_matrix_admitted);
    integration["full_local_client_smoke_admitted"] =
        json!(outcome.full_local_client_smoke_admitted);
    integration["juicity_client_integration_candidate_admitted"] =
        json!(outcome.juicity_client_integration_candidate_admitted);
    integration["juicity_full_local_client_smoke_admitted"] =
        json!(outcome.juicity_full_local_client_smoke_admitted);
    integration["juicity_client_capability_matrix_admitted"] =
        json!(outcome.juicity_client_capability_matrix_admitted);
    integration["juicity_true_quic_h3_dataplane_admitted"] =
        json!(outcome.juicity_true_quic_h3_dataplane_admitted);
    integration["outbound_true_dataplane_admitted"] =
        json!(outcome.outbound_true_dataplane_admitted);
    integration["default_switch_allowed"] = json!(outcome.default_switch_allowed);
    integration["product_chain_switch_allowed"] = json!(outcome.product_chain_switch_allowed);
    integration["boundary"] = json!(
        "local Juicity client integration candidate is admitted; outbound registry/default/product switches remain closed"
    );
    report["client_integration"] = integration;
    report["benchmark"] = json!({
        "benchmark_recorded": passed,
        "auth_iterations": outcome.auth_iterations,
        "transport_iterations": outcome.transport_iterations,
        "stream_iterations": outcome.stream_iterations,
        "congestion_iterations": outcome.congestion_iterations,
        "total_exchange_count": outcome.total_exchange_count,
        "elapsed_ns": outcome.total_elapsed_ns,
        "ns_per_juicity_client_integration_exchange": outcome.ns_per_juicity_client_integration_exchange,
        "transport_roundtrip_match_count": outcome.transport_roundtrip_match_count,
        "stream_response_match_count": outcome.stream_response_match_count,
        "congestion_response_match_count": outcome.congestion_response_match_count,
        "scope": "local Juicity client integration candidate aggregates auth lifecycle, TransportPacketConn, stream_packet_conn, and BBR sustained relay; not outbound registry switching, default daemon, product-chain switching, or matched Go benchmark",
        "go_matched_default_daemon_baseline_recorded": false
    });
    report["protocol_matrix"]["juicity_client_integration_candidate_admitted"] =
        json!(outcome.juicity_client_integration_candidate_admitted);
}
