use super::*;

#[test]
fn case_juicity_stream_packet_congestion_runs_sustained_bbr_relay() {
    let outcome = juicity::run_stream_packet_congestion_smoke(
        &juicity::JuicityStreamPacketCongestionOptions {
            iterations: 6,
            max_in_flight_streams: 3,
            timeout: Duration::from_secs(10),
            ..Default::default()
        },
    )
    .unwrap();

    assert_eq!(outcome.server_name, juicity::DEFAULT_H3_SERVER_NAME);
    assert_eq!(
        outcome.target,
        juicity::DEFAULT_STREAM_PACKET_CONGESTION_TARGET
    );
    assert_eq!(
        outcome.response_target,
        juicity::DEFAULT_STREAM_PACKET_CONGESTION_RESPONSE_TARGET
    );
    assert_eq!(outcome.alpn_protocol, "h3");
    assert_eq!(outcome.client_selected_alpn, "h3");
    assert_eq!(outcome.server_selected_alpn, "h3");
    assert!(outcome.tls13_only_configured);
    assert!(outcome.quic_datagram_disabled);
    assert_eq!(outcome.keepalive_secs, 5);
    assert_eq!(outcome.handshake_idle_timeout_secs, 8);
    assert_eq!(outcome.congestion_control_requested, "bbr");
    assert_eq!(outcome.congestion_control_effective, "bbr");
    assert_eq!(outcome.congestion_control_default, "bbr");
    assert_eq!(outcome.cwnd_param, 10);
    assert_eq!(outcome.bbr_initial_congestion_window_packets, 32);
    assert_eq!(outcome.bbr_initial_packet_size_ipv4, 1280);
    assert_eq!(outcome.rust_bbr_initial_window_bytes, 40960);
    assert!(outcome.bbr_factory_configured);

    assert_eq!(outcome.iterations, 6);
    assert_eq!(outcome.max_in_flight_streams, 3);
    assert_eq!(outcome.max_in_flight_observed, 3);
    assert_eq!(outcome.connection_network_byte, 3);
    assert_eq!(
        outcome.request_payload_len,
        juicity::DEFAULT_STREAM_PACKET_CONGESTION_PAYLOAD_LEN
    );
    assert_eq!(
        outcome.response_payload_len,
        juicity::DEFAULT_STREAM_PACKET_CONGESTION_RESPONSE_LEN
    );
    assert_eq!(
        outcome.total_request_payload_bytes,
        outcome.request_payload_len * outcome.iterations
    );
    assert_eq!(
        outcome.total_response_payload_bytes,
        outcome.response_payload_len * outcome.iterations
    );
    assert_eq!(outcome.open_bi_stream_count, 6);
    assert_eq!(outcome.client_stream_finish_count, 6);
    assert_eq!(outcome.client_stream_acked_count, 6);
    assert_eq!(outcome.server_accept_bi_stream_count, 6);
    assert_eq!(outcome.server_request_read_count, 6);
    assert_eq!(outcome.server_request_match_count, 6);
    assert_eq!(outcome.server_response_write_count, 6);
    assert_eq!(outcome.server_stream_finish_count, 6);
    assert_eq!(outcome.server_stream_acked_count, 6);
    assert_eq!(outcome.client_response_read_count, 6);
    assert_eq!(outcome.client_response_match_count, 6);
    assert!(outcome.client_sent_packets_delta > 0);
    assert!(outcome.client_cwnd_bytes > 0);
    assert!(outcome.server_cwnd_bytes > 0);
    assert!(outcome.client_current_mtu > 0);
    assert!(outcome.server_current_mtu > 0);

    assert!(outcome.quic_handshake_validated);
    assert!(outcome.stream_packet_conn_sustained_relay_validated);
    assert!(outcome.stream_packet_conn_congestion_stats_recorded);
    assert!(outcome.stream_packet_conn_bbr_controller_validated);
    assert!(outcome.juicity_stream_packet_conn_dataplane_admitted);
    assert!(outcome.juicity_packet_over_stream_admitted);
    assert!(outcome.juicity_congestion_bbr_controller_admitted);
    assert!(outcome.juicity_congestion_sustained_relay_admitted);
    assert!(outcome.juicity_congestion_behavior_admitted);
    assert!(!outcome.juicity_true_quic_h3_dataplane_admitted);
}
