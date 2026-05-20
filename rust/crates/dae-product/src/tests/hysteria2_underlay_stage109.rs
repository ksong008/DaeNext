use super::*;

#[test]
fn stage109_hysteria2_underlay_gate_matches_golden_fixture() {
    let fixture = load("product/daemon/stage109_hysteria2_udp_underlay_gate.json");
    let contract = stage109_hysteria2_underlay_gate_contract();

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
    assert_string_vec(&contract.benchmark, &fixture["benchmark"]);
    assert_string_vec(&contract.remaining_blockers, &fixture["remaining_blockers"]);
}

#[test]
fn stage109_hysteria2_underlay_keeps_full_quic_and_defaults_closed() {
    let contract = stage109_hysteria2_underlay_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.hysteria2_native_optin_contract_admitted);
    assert!(contract.hysteria2_port_hopping_contract_admitted);
    assert!(contract.hysteria2_pin_sha256_raw_cert_hash_admitted);
    assert!(contract.hysteria2_udp_underlay_admitted);
    assert!(!contract.hysteria2_full_quic_stack_observed);
    assert!(!contract.hysteria2_true_quic_dataplane_admitted);
    assert!(contract.quic_h3_family_native_optin_contract_admitted);
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
    assert_contains_text(&contract.validation_commands, "stage109");
}
