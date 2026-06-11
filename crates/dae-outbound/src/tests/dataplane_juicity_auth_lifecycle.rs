use super::*;

#[test]
fn case_juicity_auth_lifecycle_preserves_channel_order_and_finish_boundary() {
    let report = juicity::run_auth_lifecycle_smoke(&juicity::JuicityAuthLifecycleOptions {
        iterations: 1,
        timeout: Duration::from_secs(5),
        ..Default::default()
    })
    .unwrap();

    assert_eq!(report.targets, juicity::DEFAULT_AUTH_LIFECYCLE_TARGETS);
    assert_eq!(report.client_selected_alpn, "h3");
    assert_eq!(report.server_selected_alpn, "h3");
    assert_eq!(report.ekm_label_len, 16);
    assert_eq!(
        report.ekm_context_len,
        juicity::DEFAULT_LIVE_EKM_AUTH_PASSWORD.len()
    );
    assert_eq!(report.ekm_token_len, 32);
    assert!(report.client_ekm_token_nonzero);
    assert!(report.server_ekm_token_exported);
    assert_eq!(report.authenticate_header_len, 50);
    assert_eq!(report.record_count, 3);
    assert_eq!(report.dialauth_record_lens, vec![98, 98, 98]);
    assert_eq!(report.auth_header_offset, 0);
    assert_eq!(report.first_dialauth_record_offset, 50);
    assert_eq!(report.last_dialauth_record_end, report.transcript_len);
    assert_eq!(report.transcript_len, 344);
    assert_eq!(report.underlay_auth_channel_capacity, 64);
    assert_eq!(report.channel_enqueue_count, 3);
    assert_eq!(report.channel_receive_count, 3);
    assert!(report.channel_closed_after_records);
    assert!(report.auth_header_written_first);
    assert!(report.underlay_auth_channel_order_validated);
    assert!(report.multiple_dialauth_records_over_auth_stream_validated);
    assert_eq!(report.open_uni_stream_count, 1);
    assert_eq!(report.uni_stream_finish_count, 1);
    assert_eq!(report.uni_stream_acked_count, 1);
    assert_eq!(report.server_received_count, 1);
    assert_eq!(report.server_received_len, report.transcript_len);
    assert_eq!(report.server_read_to_end_count, 1);
    assert_eq!(report.server_transcript_match_count, 1);
    assert!(report.quic_handshake_validated);
    assert!(report.auth_stream_finish_boundary_validated);
    assert!(report.send_authentication_lifecycle_validated);
    assert!(report.juicity_send_authentication_lifecycle_admitted);
    assert!(report.juicity_underlay_auth_channel_order_admitted);
    assert!(report.juicity_multiple_dialauth_records_over_auth_stream_admitted);
    assert!(report.juicity_auth_stream_finish_boundary_admitted);

    assert!(!report.juicity_dialauth_over_h3_admitted);
    assert!(!report.juicity_transport_packet_conn_dataplane_admitted);
    assert!(!report.juicity_stream_packet_conn_dataplane_admitted);
    assert!(!report.juicity_true_quic_h3_dataplane_admitted);
}
