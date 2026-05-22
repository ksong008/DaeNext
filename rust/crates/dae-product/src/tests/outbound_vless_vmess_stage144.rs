use super::*;

#[test]
fn stage144_vless_vmess_recertification_gate_matches_golden_fixture() {
    let fixture =
        load("product/daemon/stage144_vless_vmess_fallback_aware_recertification_gate.json");
    let contract = stage144_vless_vmess_recertification_gate_contract();

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
fn stage144_vless_vmess_recertification_keeps_default_closed() {
    let contract = stage144_vless_vmess_recertification_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.vless_vmess_fallback_aware_recertified);
    assert!(contract.vless_reality_go_fallback_admitted);
    assert!(contract.vless_vision_go_fallback_admitted);
    assert!(!contract.vless_protocol_true_dataplane_admitted);
    assert!(!contract.vmess_protocol_true_dataplane_admitted);
    assert!(!contract.shared_transport_true_dataplane_admitted);
    assert!(!contract.outbound_true_dataplane_admitted);
    assert!(!contract.default_switch_allowed);
    assert!(!contract.product_chain_switch_allowed);
}
