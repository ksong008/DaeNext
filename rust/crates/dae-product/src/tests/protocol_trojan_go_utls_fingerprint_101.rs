use super::*;

#[test]
fn stage101_utls_fingerprint_gate_matches_golden_fixture() {
    let fixture = load("product/daemon/stage101_trojan_go_utls_fingerprint_gate.json");
    let contract = stage101_trojan_go_utls_fingerprint_gate_contract();

    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.stage_complete,
        fixture["stage_complete"].as_bool().unwrap()
    );
    assert_eq!(
        contract.trojan_go_utls_fingerprint_selection_admitted,
        fixture["trojan_go_utls_fingerprint_selection_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.trojan_go_utls_fingerprint_wire_admitted,
        fixture["trojan_go_utls_fingerprint_wire_admitted"]
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
        contract.supported_name_count,
        fixture["supported_name_count"].as_u64().unwrap() as usize
    );
    assert_eq!(
        contract.gate_decision,
        fixture["gate_decision"].as_str().unwrap()
    );
    assert_string_vec(&contract.remaining_blockers, &fixture["remaining_blockers"]);
}

#[test]
fn stage101_utls_fingerprint_keeps_wire_and_defaults_closed() {
    let contract = stage101_trojan_go_utls_fingerprint_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.trojan_go_tls_fragment_admitted);
    assert!(contract.trojan_go_utls_fingerprint_selection_admitted);
    assert!(!contract.trojan_go_utls_fingerprint_wire_admitted);
    assert!(!contract.trojan_go_utls_fingerprint_admitted);
    assert!(!contract.trojan_go_reality_mutation_admitted);
    assert!(!contract.trojan_go_cross_combination_recertified);
    assert!(contract.trojan_go_shared_transport_partial_admitted);
    assert!(!contract.trojan_go_shared_transport_admitted);
    assert!(!contract.outbound_true_dataplane_admitted);
    assert!(!contract.default_switch_allowed);
    assert!(!contract.product_chain_switch_allowed);
    assert!(contract.go_default_path_preserved);
    assert!(contract.go_fallback_required);
    assert_eq!(contract.supported_name_count, 45);

    assert_contains_text(&contract.remaining_blockers, "wire-level");
    assert_contains_text(&contract.remaining_blockers, "REALITY");
}
