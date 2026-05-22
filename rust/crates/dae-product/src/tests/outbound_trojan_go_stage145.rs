use super::*;

#[test]
fn stage145_trojan_go_recertification_gate_matches_golden_fixture() {
    let fixture =
        load("product/daemon/stage145_trojan_go_fallback_aware_recertification_gate.json");
    let contract = stage145_trojan_go_recertification_gate_contract();

    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.gate_decision,
        fixture["gate_decision"].as_str().unwrap()
    );
    assert_string_vec(&contract.remaining_blockers, &fixture["remaining_blockers"]);
}

#[test]
fn stage145_trojan_go_recertification_keeps_shared_transport_closed() {
    let contract = stage145_trojan_go_recertification_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.trojan_go_fallback_aware_recertified);
    assert!(contract.trojan_go_shared_transport_go_fallback_required);
    assert!(contract.trojan_go_grpc_no_double_tls_guarded);
    assert!(!contract.trojan_go_shared_transport_admitted);
    assert!(!contract.trojan_go_utls_fingerprint_wire_admitted);
    assert!(!contract.trojan_go_reality_mutation_admitted);
    assert!(!contract.trojan_go_cross_combination_recertified);
    assert!(!contract.shared_transport_true_dataplane_admitted);
    assert!(!contract.outbound_true_dataplane_admitted);
    assert!(!contract.default_switch_allowed);
    assert!(!contract.product_chain_switch_allowed);
}
