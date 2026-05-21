use std::time::Duration;

use super::*;

#[test]
fn stage118_juicity_h3_loopback_smoke_echoes_payload_and_records_certchain_callback() {
    let payload = b"stage118-unit-h3-loopback";
    let report = juicity::run_h3_loopback_smoke(&juicity::JuicityH3LoopbackOptions {
        payload: payload.to_vec(),
        iterations: 1,
        timeout: Duration::from_secs(5),
        ..Default::default()
    })
    .unwrap();

    assert_eq!(report.server_name, juicity::DEFAULT_H3_SERVER_NAME);
    assert_eq!(report.alpn_protocol, juicity::DEFAULT_H3_ALPN);
    assert_eq!(report.client_selected_alpn, juicity::DEFAULT_H3_ALPN);
    assert_eq!(report.server_selected_alpn, juicity::DEFAULT_H3_ALPN);
    assert!(report.tls13_only_configured);
    assert!(report.quic_datagram_disabled);
    assert_eq!(report.keepalive_secs, juicity::DEFAULT_H3_KEEPALIVE_SECS);
    assert_eq!(
        report.handshake_idle_timeout_secs,
        juicity::DEFAULT_H3_HANDSHAKE_IDLE_TIMEOUT_SECS
    );
    assert_eq!(report.payload_len, payload.len());
    assert_eq!(report.echoed_payload, payload);
    assert_eq!(report.h3_status, 200);
    assert!(report.h3_request_response_validated);
    assert!(report.quic_handshake_validated);
    assert!(report.certificate_chain_callback_observed);
    assert_eq!(report.certificate_chain_der_count, 1);
    assert_eq!(report.certificate_chain_hash_hex.len(), 64);
    assert_eq!(report.verifier_server_name, juicity::DEFAULT_H3_SERVER_NAME);
    assert!(report.juicity_h3_handshake_admitted);
    assert!(report.juicity_tls_verify_peer_certificate_hook_admitted);
    assert!(!report.juicity_tls_certchain_verification_admitted);
    assert!(!report.juicity_dialauth_over_h3_admitted);
    assert!(!report.juicity_transport_packet_conn_dataplane_admitted);
    assert!(!report.juicity_stream_packet_conn_dataplane_admitted);
    assert!(!report.juicity_true_quic_h3_dataplane_admitted);
}
