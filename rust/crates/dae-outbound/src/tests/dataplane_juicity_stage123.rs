use super::*;

#[test]
fn stage123_juicity_live_ekm_auth_token_matches_across_quic_connection() {
    let report = juicity::run_live_ekm_auth_smoke(&juicity::JuicityLiveEkmAuthOptions {
        iterations: 1,
        timeout: Duration::from_secs(5),
        ..Default::default()
    })
    .unwrap();

    assert_eq!(report.target, "juicity-ekm-auth.example:0");
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
    assert_eq!(report.dialauth_record_len, 92);
    assert_eq!(report.transcript_len, 142);
    assert_eq!(report.open_uni_stream_count, 1);
    assert_eq!(report.uni_stream_finish_count, 1);
    assert_eq!(report.uni_stream_acked_count, 1);
    assert_eq!(report.server_received_count, 1);
    assert_eq!(report.server_received_len, report.transcript_len);
    assert_eq!(report.server_transcript_match_count, 1);
    assert!(report.quic_handshake_validated);
    assert!(report.live_ekm_auth_stream_validated);
    assert!(report.juicity_auth_token_live_ekm_admitted);
    assert!(report.juicity_live_ekm_auth_header_admitted);
    assert!(report.juicity_live_ekm_auth_stream_transcript_admitted);

    assert!(!report.juicity_dialauth_over_h3_admitted);
    assert!(!report.juicity_transport_packet_conn_dataplane_admitted);
    assert!(!report.juicity_stream_packet_conn_dataplane_admitted);
    assert!(!report.juicity_true_quic_h3_dataplane_admitted);
}
