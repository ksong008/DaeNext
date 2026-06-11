use super::*;

#[test]
fn case_juicity_stream_packet_conn_relays_nonzero_udp_over_live_stream() {
    let report = juicity::run_stream_packet_conn_smoke(&juicity::JuicityStreamPacketConnOptions {
        iterations: 1,
        timeout: Duration::from_secs(5),
        ..Default::default()
    })
    .unwrap();

    assert_eq!(report.target, "juicity-stream.fixture.invalid:5353");
    assert_eq!(
        report.response_target,
        "juicity-stream-response.fixture.invalid:5353"
    );
    assert_eq!(report.client_selected_alpn, "h3");
    assert_eq!(report.server_selected_alpn, "h3");
    assert_eq!(report.connection_network_byte, 3);
    assert_eq!(
        report.request_payload_len,
        juicity::DEFAULT_STREAM_PACKET_CONN_PAYLOAD.len()
    );
    assert_eq!(
        report.response_payload_len,
        juicity::DEFAULT_STREAM_PACKET_CONN_RESPONSE.len()
    );
    assert_eq!(
        report.request_frame_len,
        report.request_frame_metadata_len + 2 + report.request_payload_len
    );
    assert_eq!(
        report.response_frame_len,
        report.response_frame_metadata_len + 2 + report.response_payload_len
    );
    assert_eq!(
        report.request_stream_write_len,
        1 + report.initial_metadata_len + report.request_frame_len
    );
    assert_eq!(report.open_bi_stream_count, 1);
    assert_eq!(report.client_stream_finish_count, 1);
    assert_eq!(report.client_stream_acked_count, 1);
    assert_eq!(report.server_accept_bi_stream_count, 1);
    assert_eq!(report.server_request_read_count, 1);
    assert_eq!(report.server_request_match_count, 1);
    assert_eq!(report.server_response_write_count, 1);
    assert_eq!(report.server_stream_finish_count, 1);
    assert_eq!(report.server_stream_acked_count, 1);
    assert_eq!(report.client_response_read_count, 1);
    assert_eq!(report.client_response_match_count, 1);
    assert!(report.quic_handshake_validated);
    assert!(report.stream_packet_conn_frame_order_validated);
    assert!(report.stream_packet_conn_close_boundary_validated);
    assert!(report.stream_packet_conn_live_relay_validated);
    assert!(report.juicity_stream_packet_conn_live_stream_admitted);
    assert!(report.juicity_stream_packet_conn_frame_order_admitted);
    assert!(report.juicity_packet_over_stream_admitted);
    assert!(report.juicity_stream_packet_conn_dataplane_admitted);

    assert!(!report.juicity_congestion_behavior_admitted);
    assert!(!report.juicity_true_quic_h3_dataplane_admitted);
}
