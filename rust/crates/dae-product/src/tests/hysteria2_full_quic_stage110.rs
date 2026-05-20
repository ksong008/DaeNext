use super::*;

#[test]
fn stage110_hysteria2_full_quic_queue_gate_matches_golden_fixture() {
    let fixture =
        load("product/daemon/stage110_hysteria2_full_quic_client_blocker_queue_gate.json");
    let contract = stage110_hysteria2_full_quic_queue_gate_contract();

    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.stage_complete,
        fixture["stage_complete"].as_bool().unwrap()
    );
    assert_eq!(
        contract.hysteria2_udp_underlay_admitted,
        fixture["hysteria2_udp_underlay_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.hysteria2_true_quic_dataplane_admitted,
        fixture["hysteria2_true_quic_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.gate_decision,
        fixture["gate_decision"].as_str().unwrap()
    );
    assert_string_vec(
        &contract.benchmark_carry_forward,
        &fixture["benchmark_carry_forward"],
    );
    assert_string_vec(&contract.remaining_blockers, &fixture["remaining_blockers"]);
}

#[test]
fn stage110_hysteria2_full_quic_queue_keeps_defaults_closed() {
    let contract = stage110_hysteria2_full_quic_queue_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.hysteria2_native_optin_contract_admitted);
    assert!(contract.hysteria2_udp_underlay_admitted);
    assert!(!contract.hysteria2_full_quic_handshake_admitted);
    assert!(!contract.hysteria2_stream_mux_admitted);
    assert!(!contract.hysteria2_packet_datagram_admitted);
    assert!(!contract.hysteria2_port_hopping_scheduler_admitted);
    assert!(!contract.hysteria2_true_quic_dataplane_admitted);
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

    assert_contains_text(&contract.remaining_blockers, "Hysteria2 full QUIC");
    assert_contains_text(&contract.validation_commands, "stage110");
}
