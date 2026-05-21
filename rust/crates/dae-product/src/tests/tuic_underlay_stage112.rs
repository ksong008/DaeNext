use super::*;

#[test]
fn stage112_tuic_underlay_gate_matches_golden_fixture() {
    let fixture = load("product/daemon/stage112_tuic_udp_underlay_gate.json");
    let contract = stage112_tuic_underlay_gate_contract();

    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.stage_complete,
        fixture["stage_complete"].as_bool().unwrap()
    );
    assert_eq!(
        contract.tuic_udp_underlay_socket_admitted,
        fixture["tuic_udp_underlay_socket_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.tuic_true_quic_dataplane_admitted,
        fixture["tuic_true_quic_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.gate_decision,
        fixture["gate_decision"].as_str().unwrap()
    );
    assert_string_vec(&contract.benchmark, &fixture["benchmark"]);
    assert_string_vec(&contract.remaining_blockers, &fixture["remaining_blockers"]);
}

#[test]
fn stage112_tuic_underlay_keeps_defaults_closed() {
    let contract = stage112_tuic_underlay_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.tuic_native_optin_contract_admitted);
    assert!(contract.tuic_uuid_password_contract_admitted);
    assert!(contract.tuic_tls13_datagram_config_contract_admitted);
    assert!(contract.tuic_disable_sni_contract_admitted);
    assert!(contract.tuic_udp_relay_mode_go_parity_caveat_recorded);
    assert!(contract.tuic_underlay_contract_admitted);
    assert!(contract.tuic_udp_underlay_socket_admitted);
    assert!(contract.tuic_so_mark_loopback_observed);
    assert!(!contract.tuic_full_quic_handshake_admitted);
    assert!(!contract.tuic_auth_stream_admitted);
    assert!(!contract.tuic_datagram_packet_relay_admitted);
    assert!(!contract.tuic_udp_relay_mode_quic_effective_relay_admitted);
    assert!(!contract.tuic_true_quic_dataplane_admitted);
    assert!(contract.hysteria2_udp_underlay_admitted);
    assert!(!contract.hysteria2_true_quic_dataplane_admitted);
    assert!(!contract.juicity_true_quic_h3_dataplane_admitted);
    assert!(!contract.quic_h3_family_true_dataplane_admitted);
    assert!(contract.anytls_true_dataplane_admitted);
    assert!(contract.protocol_outbound_partial_admitted);
    assert!(!contract.outbound_true_dataplane_admitted);
    assert!(!contract.default_switch_allowed);
    assert!(!contract.default_path_mutation_allowed);
    assert!(!contract.product_chain_switch_allowed);
    assert!(!contract.true_rust_default_daemon_admitted);
    assert!(contract.outbound_quic_go_dependency_preserved);
    assert!(contract.external_outbound_required);
    assert!(contract.external_quic_go_required);
    assert!(contract.go_default_path_preserved);
    assert!(contract.go_fallback_required);

    assert_contains_text(&contract.remaining_blockers, "TUIC full QUIC");
    assert_contains_text(&contract.validation_commands, "stage112");
}
