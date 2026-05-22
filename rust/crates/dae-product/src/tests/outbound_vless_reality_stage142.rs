use super::*;

#[test]
fn stage142_vless_reality_fallback_gate_matches_golden_fixture() {
    let fixture = load("product/daemon/stage142_vless_reality_full_handshake_fallback_gate.json");
    let contract = stage142_vless_reality_fallback_gate_contract();

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
fn stage142_vless_reality_fallback_keeps_true_rust_switches_closed() {
    let contract = stage142_vless_reality_fallback_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.vless_reality_go_fallback_admitted);
    assert!(contract.vless_reality_full_handshake_go_fallback_required);
    assert!(!contract.vless_reality_full_handshake_admitted);
    assert!(!contract.vless_reality_verify_peer_certificate_admitted);
    assert!(!contract.vless_reality_spider_fallback_admitted);
    assert!(!contract.vless_utls_fingerprint_wire_admitted);
    assert!(!contract.vless_vision_tls_reality_admitted);
    assert!(!contract.vless_protocol_true_dataplane_admitted);
    assert!(!contract.outbound_true_dataplane_admitted);
    assert!(!contract.default_switch_allowed);
    assert!(!contract.product_chain_switch_allowed);
}
