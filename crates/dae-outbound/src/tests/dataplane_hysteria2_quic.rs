use super::*;

#[test]
fn case_hysteria2_port_hopping_scheduler_normalizes_and_rotates_ports() {
    let schedule = hysteria2::build_port_hop_schedule(
        "hysteria2-loopback.fixture.invalid:8444,443,8443-8445",
        30_000,
        5,
    )
    .unwrap();

    assert!(schedule.port_hopping);
    assert_eq!(schedule.host, "hysteria2-loopback.fixture.invalid");
    assert_eq!(schedule.normalized_ports, vec![443, 8443, 8444, 8445]);
    assert_eq!(schedule.selected_ports, vec![443, 8443, 8444, 8445, 443]);
    assert_eq!(schedule.udp_hop_interval_ms, 30_000);
    assert!(schedule.scheduler_admitted);
}

#[test]
fn case_hysteria2_true_quic_dataplane_smoke_admits_hysteria2_only() {
    let mut options = hysteria2::Hysteria2TrueQuicDataplaneOptions::default();
    options.quic.stream_iterations = 1;
    options.quic.datagram_iterations = 2;

    let outcome = hysteria2::run_true_quic_dataplane_smoke(&options).unwrap();

    assert_eq!(outcome.property_protocol, "hysteria2");
    assert_eq!(outcome.property_name, "hysteria2-loopback");
    assert_eq!(
        outcome.property_address,
        "hysteria2-loopback.fixture.invalid:443,8443-8444"
    );
    assert_eq!(outcome.chain_adapter_mode, "rust-native");
    assert!(outcome.chain_parent_dialer_non_nil);
    assert_eq!(outcome.underlay.underlay_network, "udp");
    assert_eq!(outcome.underlay.route_cache_key_network, "udp");
    assert!(outcome.underlay.server.port_hopping);
    assert!(!outcome.underlay.udp_mptcp_effective);
    assert!(outcome.port_hopping.scheduler_admitted);
    assert_eq!(outcome.port_hopping.normalized_ports, vec![443, 8443, 8444]);
    assert!(outcome.quic.quic_handshake_validated);
    assert!(outcome.quic.raw_cert_pin_matched);
    assert!(outcome.quic.tcp_target_over_quic_validated);
    assert!(outcome.quic.udp_target_over_quic_datagram_validated);
    assert_eq!(outcome.quic.stream_iterations, 1);
    assert_eq!(outcome.quic.datagram_iterations, 2);
    assert_eq!(outcome.quic.total_exchange_count, 3);
    assert!(outcome.hysteria2_rust_native_contract_admitted);
    assert!(outcome.hysteria2_udp_underlay_admitted);
    assert!(outcome.hysteria2_full_quic_handshake_admitted);
    assert!(outcome.hysteria2_stream_mux_admitted);
    assert!(outcome.hysteria2_packet_datagram_admitted);
    assert!(outcome.hysteria2_port_hopping_scheduler_admitted);
    assert!(outcome.hysteria2_tcp_target_over_quic_admitted);
    assert!(outcome.hysteria2_udp_target_over_quic_admitted);
    assert!(outcome.hysteria2_true_quic_dataplane_admitted);

    assert!(!outcome.tuic_true_quic_dataplane_admitted);
    assert!(!outcome.quic_h3_family_true_dataplane_admitted);
    assert!(!outcome.outbound_true_dataplane_admitted);
    assert!(!outcome.native_daemon_benchmark_recorded);
    assert!(!outcome.final_native_admission_allowed);
    assert!(!outcome.host_mutation_allowed);
    assert!(!outcome.final_state_admission_allowed);
    assert!(!outcome.true_rust_native_daemon_admitted);
}
