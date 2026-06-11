use super::*;

#[test]
fn case_juicity_transport_packet_conn_encrypts_and_roundtrips_udp_payload() {
    let report =
        juicity::run_transport_packet_conn_smoke(&juicity::JuicityTransportPacketConnOptions {
            iterations: 2,
            timeout: Duration::from_secs(3),
            ..Default::default()
        })
        .unwrap();

    assert_eq!(report.target, "juicity-packet-zero.fixture.invalid:0");
    assert_eq!(report.cipher, "chacha20-poly1305");
    assert_eq!(report.reused_info_raw, "juicity-reused-info");
    assert_eq!(report.reused_info_len, "juicity-reused-info".len());
    assert_eq!(report.hkdf_hash, "sha1");
    assert_eq!(report.nonce_len, 12);
    assert_eq!(report.tag_len, 16);
    assert_eq!(report.underlay_psk_len, 32);
    assert_eq!(report.first_iv_len, 32);
    assert!(report.first_iv_zero_prefix_valid);
    assert!(report.first_packet_uses_dialauth_iv);
    assert_eq!(report.generated_salt_count, 1);
    assert!(report.generated_salts_zero_prefix_valid);
    assert_eq!(
        report.payload_len,
        juicity::DEFAULT_TRANSPORT_PACKET_CONN_PAYLOAD.len()
    );
    assert_eq!(
        report.response_payload_len,
        juicity::DEFAULT_TRANSPORT_PACKET_CONN_RESPONSE.len()
    );
    assert_eq!(report.encrypted_packet_len, report.payload_len + 32 + 16);
    assert_eq!(
        report.encrypted_response_packet_len,
        report.response_payload_len + 32 + 16
    );
    assert_eq!(report.client_packet_sent_count, 2);
    assert_eq!(report.server_packet_received_count, 2);
    assert_eq!(report.server_decrypt_count, 2);
    assert_eq!(report.server_encrypt_count, 2);
    assert_eq!(report.client_response_received_count, 2);
    assert_eq!(report.client_decrypt_count, 2);
    assert_eq!(report.roundtrip_match_count, 2);
    assert!(report.transport_packet_conn_crypto_validated);
    assert!(report.transport_packet_conn_first_iv_validated);
    assert!(report.transport_packet_conn_udp_roundtrip_validated);
    assert!(report.juicity_transport_packet_conn_crypto_admitted);
    assert!(report.juicity_transport_packet_conn_first_iv_admitted);
    assert!(report.juicity_transport_packet_conn_udp_roundtrip_admitted);
    assert!(report.juicity_transport_packet_conn_dataplane_admitted);

    assert!(!report.juicity_stream_packet_conn_dataplane_admitted);
    assert!(!report.juicity_packet_over_stream_admitted);
    assert!(!report.juicity_congestion_behavior_admitted);
    assert!(!report.juicity_true_quic_h3_dataplane_admitted);
}
