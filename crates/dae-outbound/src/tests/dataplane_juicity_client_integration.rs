use super::*;

#[test]
fn case_juicity_client_integration_candidate_runs_all_local_slices() {
    let outcome =
        juicity::run_client_integration_smoke(&juicity::JuicityClientIntegrationOptions {
            auth_iterations: 1,
            transport_iterations: 3,
            stream_iterations: 2,
            congestion_iterations: 4,
            max_in_flight_streams: 2,
            timeout: Duration::from_secs(12),
            ..Default::default()
        })
        .unwrap();

    assert_eq!(outcome.server_name, juicity::DEFAULT_H3_SERVER_NAME);
    assert_eq!(outcome.alpn_protocol, "h3");
    assert!(outcome.tls13_only_configured);
    assert!(outcome.quic_datagram_disabled);
    assert_eq!(outcome.keepalive_secs, 5);
    assert_eq!(outcome.handshake_idle_timeout_secs, 8);
    assert_eq!(outcome.auth_iterations, 1);
    assert_eq!(outcome.transport_iterations, 3);
    assert_eq!(outcome.stream_iterations, 2);
    assert_eq!(outcome.congestion_iterations, 4);
    assert_eq!(outcome.max_in_flight_streams, 2);
    assert_eq!(outcome.total_exchange_count, 10);

    assert_eq!(outcome.auth_record_count, 3);
    assert_eq!(outcome.auth_channel_enqueue_count, 3);
    assert_eq!(outcome.auth_channel_receive_count, 3);
    assert_eq!(outcome.auth_server_transcript_match_count, 1);
    assert_eq!(outcome.transport_roundtrip_match_count, 3);
    assert!(outcome.transport_payload_len > 0);
    assert!(outcome.transport_encrypted_packet_len > outcome.transport_payload_len);
    assert_eq!(outcome.stream_response_match_count, 2);
    assert!(outcome.stream_request_frame_len > 0);
    assert!(outcome.stream_response_frame_len > 0);
    assert_eq!(outcome.congestion_response_match_count, 4);
    assert_eq!(outcome.congestion_max_in_flight_observed, 2);
    assert_eq!(
        outcome.congestion_request_payload_len,
        juicity::DEFAULT_STREAM_PACKET_CONGESTION_PAYLOAD_LEN
    );
    assert_eq!(
        outcome.congestion_response_payload_len,
        juicity::DEFAULT_STREAM_PACKET_CONGESTION_RESPONSE_LEN
    );
    assert_eq!(
        outcome.congestion_total_request_payload_bytes,
        outcome.congestion_request_payload_len * outcome.congestion_iterations
    );
    assert_eq!(
        outcome.congestion_total_response_payload_bytes,
        outcome.congestion_response_payload_len * outcome.congestion_iterations
    );
    assert!(outcome.congestion_client_cwnd_bytes > 0);
    assert!(outcome.congestion_server_cwnd_bytes > 0);

    assert!(outcome.auth_lifecycle_admitted);
    assert!(outcome.transport_packet_conn_admitted);
    assert!(outcome.stream_packet_conn_admitted);
    assert!(outcome.congestion_behavior_admitted);
    assert!(outcome.client_capability_matrix_admitted);
    assert!(outcome.full_local_client_smoke_admitted);
    assert!(outcome.juicity_client_integration_candidate_admitted);
    assert!(outcome.juicity_full_local_client_smoke_admitted);
    assert!(outcome.juicity_client_capability_matrix_admitted);
    assert!(!outcome.juicity_true_quic_h3_dataplane_admitted);
    assert!(!outcome.outbound_true_dataplane_admitted);
    assert!(!outcome.final_native_admission_allowed);
    assert!(!outcome.final_state_admission_allowed);
}
