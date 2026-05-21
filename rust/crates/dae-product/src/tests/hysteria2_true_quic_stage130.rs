use super::*;

#[test]
fn stage130_hysteria2_true_quic_gate_matches_golden_fixture() {
    let fixture = load("product/daemon/stage130_hysteria2_true_quic_dataplane_gate.json");
    let contract = stage130_hysteria2_true_quic_gate_contract();

    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.stage_complete,
        fixture["stage_complete"].as_bool().unwrap()
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
    assert_string_vec(&contract.benchmark, &fixture["benchmark"]);
    assert_string_vec(&contract.remaining_blockers, &fixture["remaining_blockers"]);
}

#[test]
fn stage130_hysteria2_true_quic_opens_only_hysteria2_protocol_gate() {
    let contract = stage130_hysteria2_true_quic_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.hysteria2_native_optin_contract_admitted);
    assert!(contract.hysteria2_udp_underlay_admitted);
    assert!(contract.hysteria2_full_quic_handshake_admitted);
    assert!(contract.hysteria2_stream_mux_admitted);
    assert!(contract.hysteria2_packet_datagram_admitted);
    assert!(contract.hysteria2_port_hopping_scheduler_admitted);
    assert!(contract.hysteria2_tcp_target_over_quic_admitted);
    assert!(contract.hysteria2_udp_target_over_quic_admitted);
    assert!(contract.hysteria2_true_quic_dataplane_admitted);
    assert!(contract.juicity_true_quic_h3_dataplane_admitted);
    assert_eq!(contract.server, "stage130.example:443,8443-8444");
    assert_eq!(contract.normalized_ports, vec![443, 8443, 8444]);
    assert_eq!(contract.default_stream_iterations, 2);
    assert_eq!(contract.default_datagram_iterations, 4);
    assert_eq!(contract.default_total_exchange_count, 6);
    assert!(contract.anytls_true_dataplane_admitted);
    assert!(contract.protocol_outbound_partial_admitted);
    assert!(contract.outbound_quic_go_dependency_preserved);
    assert!(contract.external_outbound_required);
    assert!(contract.external_quic_go_required);
    assert!(contract.go_default_path_preserved);
    assert!(contract.go_fallback_required);

    assert!(!contract.tuic_true_quic_dataplane_admitted);
    assert!(!contract.quic_h3_family_true_dataplane_admitted);
    assert!(!contract.outbound_true_dataplane_admitted);
    assert!(!contract.matched_go_rust_default_daemon_benchmark_recorded);
    assert!(!contract.default_switch_allowed);
    assert!(!contract.default_path_mutation_allowed);
    assert!(!contract.product_chain_switch_allowed);
    assert!(!contract.true_rust_default_daemon_admitted);
}
