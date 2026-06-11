use super::*;

#[test]
fn case_juicity_live_auth_stream_harness_sends_transcript_over_uni_stream() {
    let report = juicity::run_live_auth_stream_smoke(&juicity::JuicityLiveAuthStreamOptions {
        iterations: 1,
        timeout: Duration::from_secs(5),
        ..Default::default()
    })
    .unwrap();

    assert_eq!(report.target, "juicity-auth-stream.fixture.invalid:0");
    assert_eq!(report.alpn_protocol, "h3");
    assert_eq!(report.client_selected_alpn, "h3");
    assert_eq!(report.server_selected_alpn, "h3");
    assert!(report.tls13_only_configured);
    assert!(report.quic_datagram_disabled);
    assert_eq!(report.keepalive_secs, 5);
    assert_eq!(report.handshake_idle_timeout_secs, 8);
    assert_eq!(report.open_uni_stream_count, 1);
    assert_eq!(report.uni_stream_finish_count, 1);
    assert_eq!(report.uni_stream_acked_count, 1);
    assert_eq!(report.server_received_count, 1);
    assert_eq!(report.server_transcript_match_count, 1);
    assert_eq!(report.authenticate_header_len, 50);
    assert_eq!(report.dialauth_record_len, 103);
    assert_eq!(report.transcript_len, 153);
    assert_eq!(report.server_received_len, report.transcript_len);
    assert_eq!(report.auth_header_offset, 0);
    assert_eq!(report.dialauth_record_offset, 50);
    assert!(report.auth_header_written_first);
    assert!(report.dialauth_record_matches_auth_stream_contract);
    assert!(report.live_auth_uni_stream_write_order_validated);
    assert!(report.quic_handshake_validated);
    assert!(report.juicity_authenticate_header_layout_admitted);
    assert!(report.juicity_auth_uni_stream_write_order_admitted);
    assert!(report.juicity_dialauth_record_over_auth_stream_admitted);
    assert!(report.juicity_live_auth_uni_stream_harness_admitted);
    assert!(report.juicity_live_auth_uni_stream_write_order_admitted);

    assert!(!report.juicity_auth_token_live_ekm_admitted);
    assert!(!report.juicity_dialauth_over_h3_admitted);
    assert!(!report.juicity_transport_packet_conn_dataplane_admitted);
    assert!(!report.juicity_stream_packet_conn_dataplane_admitted);
    assert!(!report.juicity_true_quic_h3_dataplane_admitted);
}
