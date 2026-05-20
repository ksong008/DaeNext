use super::*;

#[test]
fn stage102_reality_session_mutation_gate_matches_golden_fixture() {
    let fixture = load("product/daemon/stage102_reality_session_id_mutation_gate.json");
    let contract = stage102_reality_session_mutation_gate_contract();

    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.stage_complete,
        fixture["stage_complete"].as_bool().unwrap()
    );
    assert_eq!(
        contract.reality_session_id_aead_mutation_admitted,
        fixture["reality_session_id_aead_mutation_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.reality_full_utls_handshake_admitted,
        fixture["reality_full_utls_handshake_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.trojan_go_shared_transport_admitted,
        fixture["trojan_go_shared_transport_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.gate_decision,
        fixture["gate_decision"].as_str().unwrap()
    );
    assert_string_vec(&contract.remaining_blockers, &fixture["remaining_blockers"]);
}

#[test]
fn stage102_reality_session_mutation_keeps_full_handshake_and_defaults_closed() {
    let contract = stage102_reality_session_mutation_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.reality_session_id_aead_mutation_admitted);
    assert!(!contract.reality_full_utls_handshake_admitted);
    assert!(!contract.trojan_go_reality_mutation_admitted);
    assert!(!contract.trojan_go_utls_fingerprint_wire_admitted);
    assert!(!contract.trojan_go_cross_combination_recertified);
    assert!(contract.trojan_go_shared_transport_partial_admitted);
    assert!(!contract.trojan_go_shared_transport_admitted);
    assert!(!contract.outbound_true_dataplane_admitted);
    assert!(!contract.default_switch_allowed);
    assert!(!contract.product_chain_switch_allowed);
    assert!(contract.go_default_path_preserved);
    assert!(contract.go_fallback_required);

    assert_contains_text(&contract.remaining_blockers, "VerifyPeerCertificate");
    assert_contains_text(&contract.remaining_blockers, "uTLS");
}
