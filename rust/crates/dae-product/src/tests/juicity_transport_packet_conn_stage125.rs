use super::*;

#[test]
fn stage125_juicity_transport_packet_conn_gate_matches_golden_fixture() {
    let fixture = load("product/daemon/stage125_juicity_transport_packet_conn_gate.json");
    let contract = stage125_juicity_transport_packet_conn_gate_contract();

    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.stage_complete,
        fixture["stage_complete"].as_bool().unwrap()
    );
    assert_eq!(
        contract.juicity_transport_packet_conn_dataplane_admitted,
        fixture["juicity_transport_packet_conn_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.gate_decision,
        fixture["gate_decision"].as_str().unwrap()
    );
    assert_eq!(contract.reused_info_raw, "juicity-reused-info");
    assert_string_vec(&contract.benchmark, &fixture["benchmark"]);
    assert_string_vec(&contract.remaining_blockers, &fixture["remaining_blockers"]);
}

#[test]
fn stage125_juicity_transport_packet_conn_keeps_stream_and_defaults_closed() {
    let contract = stage125_juicity_transport_packet_conn_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.juicity_send_authentication_lifecycle_admitted);
    assert!(contract.juicity_transport_packet_conn_crypto_admitted);
    assert!(contract.juicity_transport_packet_conn_first_iv_admitted);
    assert!(contract.juicity_transport_packet_conn_udp_roundtrip_admitted);
    assert!(contract.juicity_transport_packet_conn_dataplane_admitted);
    assert_eq!(contract.cipher, "chacha20-poly1305");
    assert_eq!(contract.reused_info_raw, "juicity-reused-info");
    assert_eq!(contract.underlay_psk_len, 32);
    assert_eq!(contract.first_iv_len, 32);
    assert_eq!(contract.nonce_len, 12);
    assert_eq!(contract.tag_len, 16);
    assert!(contract.anytls_true_dataplane_admitted);
    assert!(contract.protocol_outbound_partial_admitted);
    assert!(contract.outbound_quic_go_dependency_preserved);
    assert!(contract.external_outbound_required);
    assert!(contract.external_quic_go_required);
    assert!(contract.go_default_path_preserved);
    assert!(contract.go_fallback_required);

    assert!(!contract.juicity_stream_packet_conn_dataplane_admitted);
    assert!(!contract.juicity_packet_over_stream_admitted);
    assert!(!contract.juicity_congestion_behavior_admitted);
    assert!(!contract.juicity_true_quic_h3_dataplane_admitted);
    assert!(!contract.hysteria2_true_quic_dataplane_admitted);
    assert!(!contract.tuic_true_quic_dataplane_admitted);
    assert!(!contract.quic_h3_family_true_dataplane_admitted);
    assert!(!contract.outbound_true_dataplane_admitted);
    assert!(!contract.matched_go_rust_default_daemon_benchmark_recorded);
    assert!(!contract.default_switch_allowed);
    assert!(!contract.default_path_mutation_allowed);
    assert!(!contract.product_chain_switch_allowed);
    assert!(!contract.true_rust_default_daemon_admitted);

    assert_contains_text(&contract.remaining_blockers, "stream_packet_conn");
    assert_contains_text(&contract.validation_commands, "stage125");
}
