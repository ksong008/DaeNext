use super::*;

#[test]
fn case_tuic_true_quic_dataplane_smoke_admits_tuic_only() {
    let mut options = tuic::TuicTrueQuicDataplaneOptions::default();
    options.quic.datagram_iterations = 2;

    let outcome = tuic::run_true_quic_dataplane_smoke(&options).unwrap();

    assert_eq!(outcome.property_protocol, "tuic");
    assert_eq!(outcome.property_name, "tuic-loopback");
    assert_eq!(
        outcome.property_address,
        "tuic-loopback.fixture.invalid:443"
    );
    assert_eq!(outcome.chain_adapter_mode, "rust-native");
    assert!(outcome.chain_parent_dialer_non_nil);
    assert_eq!(outcome.user, tuic::DEFAULT_TUIC_UUID);
    assert!(outcome.uuid_validated);
    assert!(outcome.password_present);
    assert_eq!(outcome.sni, "localhost");
    assert!(outcome.allow_insecure);
    assert!(!outcome.disable_sni);
    assert!(outcome.disable_sni_probe_sni.is_empty());
    assert!(outcome.disable_sni_probe_allow_insecure);
    assert_eq!(outcome.udp_relay_mode, "native");
    assert!(outcome.underlay.tcp_underlay_uses_udp);
    assert!(outcome.underlay.tcp_underlay_preserves_mark);
    assert!(outcome.underlay.tcp_underlay_drops_mptcp);
    assert!(outcome.underlay.udp_underlay_uses_original);
    assert_eq!(outcome.underlay.tcp_request.underlay_mark, 131);

    assert!(outcome.quic.quic_handshake_validated);
    assert!(outcome.quic.auth_stream_validated);
    assert!(outcome.quic.datagram_packet_relay_validated);
    assert!(outcome.quic.congestion_behavior_recorded);
    assert_eq!(outcome.quic.client_selected_alpn, tuic::DEFAULT_TUIC_ALPN);
    assert_eq!(outcome.quic.server_selected_alpn, tuic::DEFAULT_TUIC_ALPN);
    assert_eq!(outcome.quic.datagram_iterations, 2);
    assert_eq!(outcome.quic.total_exchange_count, 3);
    assert_eq!(
        outcome.quic.authenticate_frame_len,
        tuic::TUIC_AUTHENTICATE_FRAME_LEN
    );
    assert_eq!(outcome.quic.ekm_token_len, tuic::TUIC_AUTH_TOKEN_LEN);
    assert_eq!(outcome.quic.client_datagram_match_count, 2);
    assert_eq!(outcome.quic.server_datagram_match_count, 2);

    assert!(outcome.tuic_rust_native_contract_admitted);
    assert!(outcome.tuic_uuid_password_contract_admitted);
    assert!(outcome.tuic_tls13_datagram_config_contract_admitted);
    assert!(outcome.tuic_disable_sni_contract_admitted);
    assert!(outcome.tuic_udp_relay_mode_native_admitted);
    assert!(outcome.tuic_underlay_contract_admitted);
    assert!(outcome.tuic_udp_underlay_socket_admitted);
    assert!(outcome.tuic_so_mark_loopback_observed);
    assert!(outcome.tuic_full_quic_handshake_admitted);
    assert!(outcome.tuic_auth_stream_admitted);
    assert!(outcome.tuic_datagram_packet_relay_admitted);
    assert!(outcome.tuic_congestion_behavior_admitted);
    assert!(outcome.tuic_true_quic_dataplane_admitted);

    assert!(!outcome.quic_h3_family_true_dataplane_admitted);
    assert!(!outcome.outbound_true_dataplane_admitted);
    assert!(!outcome.native_daemon_benchmark_recorded);
    assert!(!outcome.production_admission_allowed);
    assert!(!outcome.host_mutation_allowed);
    assert!(!outcome.final_state_admission_allowed);
    assert!(!outcome.true_rust_native_daemon_admitted);
}
