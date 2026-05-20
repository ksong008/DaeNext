use super::*;

#[test]
fn stage104_anytls_session_gate_matches_golden_fixture() {
    let fixture = load("product/daemon/stage104_anytls_session_frame_gate.json");
    let contract = stage104_anytls_session_gate_contract();

    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.stage_complete,
        fixture["stage_complete"].as_bool().unwrap()
    );
    assert_eq!(
        contract.anytls_session_frame_true_dataplane_admitted,
        fixture["anytls_session_frame_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.anytls_true_dataplane_admitted,
        fixture["anytls_true_dataplane_admitted"].as_bool().unwrap()
    );
    assert_eq!(
        contract.outbound_true_dataplane_admitted,
        fixture["outbound_true_dataplane_admitted"]
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
fn stage104_anytls_session_keeps_full_protocol_and_defaults_closed() {
    let contract = stage104_anytls_session_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.anytls_native_optin_contract_admitted);
    assert!(contract.anytls_session_frame_true_dataplane_admitted);
    assert!(!contract.anytls_true_dataplane_admitted);
    assert!(!contract.quic_h3_family_true_dataplane_admitted);
    assert!(contract.protocol_outbound_partial_admitted);
    assert!(!contract.outbound_true_dataplane_admitted);
    assert!(!contract.default_switch_allowed);
    assert!(!contract.product_chain_switch_allowed);
    assert!(contract.go_default_path_preserved);
    assert!(contract.go_fallback_required);

    assert_contains_text(&contract.remaining_blockers, "idle session reuse");
    assert_contains_text(&contract.remaining_blockers, "UDP packet stream");
}
