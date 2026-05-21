use super::*;

#[test]
fn stage114_juicity_h3_queue_gate_matches_golden_fixture() {
    let fixture = load("product/daemon/stage114_juicity_h3_client_blocker_queue_gate.json");
    let contract = stage114_juicity_h3_queue_gate_contract();

    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.stage_complete,
        fixture["stage_complete"].as_bool().unwrap()
    );
    assert_eq!(
        contract.juicity_native_optin_contract_admitted,
        fixture["juicity_native_optin_contract_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.juicity_true_quic_h3_dataplane_admitted,
        fixture["juicity_true_quic_h3_dataplane_admitted"]
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
fn stage114_juicity_h3_queue_keeps_defaults_closed() {
    let contract = stage114_juicity_h3_queue_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.juicity_native_optin_contract_admitted);
    assert!(contract.juicity_uuid_password_contract_admitted);
    assert!(contract.juicity_tls13_h3_alpn_config_contract_admitted);
    assert!(contract.juicity_pinned_certchain_decode_contract_admitted);
    assert!(contract.juicity_underlay_contract_admitted);
    assert!(contract.juicity_udp_port_zero_dialauth_contract_recorded);
    assert!(contract.juicity_stream_packet_conn_contract_recorded);
    assert!(!contract.juicity_h3_handshake_admitted);
    assert!(!contract.juicity_tls_certchain_verification_admitted);
    assert!(!contract.juicity_dialauth_over_h3_admitted);
    assert!(!contract.juicity_transport_packet_conn_dataplane_admitted);
    assert!(!contract.juicity_stream_packet_conn_dataplane_admitted);
    assert!(!contract.juicity_packet_over_stream_admitted);
    assert!(!contract.juicity_congestion_behavior_admitted);
    assert!(!contract.juicity_true_quic_h3_dataplane_admitted);
    assert!(contract.hysteria2_udp_underlay_admitted);
    assert!(contract.tuic_udp_underlay_socket_admitted);
    assert!(!contract.hysteria2_true_quic_dataplane_admitted);
    assert!(!contract.tuic_true_quic_dataplane_admitted);
    assert!(!contract.quic_h3_family_true_dataplane_admitted);
    assert!(contract.anytls_true_dataplane_admitted);
    assert!(contract.protocol_outbound_partial_admitted);
    assert!(!contract.outbound_true_dataplane_admitted);
    assert!(!contract.matched_go_rust_default_daemon_benchmark_recorded);
    assert!(!contract.default_switch_allowed);
    assert!(!contract.default_path_mutation_allowed);
    assert!(!contract.product_chain_switch_allowed);
    assert!(!contract.true_rust_default_daemon_admitted);
    assert!(contract.outbound_quic_go_dependency_preserved);
    assert!(contract.external_outbound_required);
    assert!(contract.external_quic_go_required);
    assert!(contract.go_default_path_preserved);
    assert!(contract.go_fallback_required);

    assert_contains_text(&contract.remaining_blockers, "Juicity H3");
    assert_contains_text(&contract.validation_commands, "stage114");
}
