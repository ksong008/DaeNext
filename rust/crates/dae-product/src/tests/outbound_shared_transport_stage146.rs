use super::*;

#[test]
fn stage146_shared_transport_outbound_recertification_gate_matches_golden_fixture() {
    let fixture = load(
        "product/daemon/stage146_shared_transport_outbound_fallback_aware_recertification_gate.json",
    );
    let contract = stage146_shared_transport_outbound_recertification_gate_contract();

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
fn stage146_shared_transport_outbound_recertification_keeps_default_closed() {
    let contract = stage146_shared_transport_outbound_recertification_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.shared_transport_fallback_aware_recertified);
    assert!(contract.outbound_fallback_aware_recertified);
    assert!(contract.fallback_dependency_policy_recorded);
    assert!(contract.vless_vmess_fallback_aware_recertified);
    assert!(contract.trojan_go_fallback_aware_recertified);
    assert!(contract.quic_h3_family_true_dataplane_admitted);
    assert!(contract.external_outbound_required);
    assert!(contract.external_quic_go_required);
    assert!(contract.go_default_path_preserved);

    assert!(!contract.vless_protocol_true_dataplane_admitted);
    assert!(!contract.vmess_protocol_true_dataplane_admitted);
    assert!(!contract.trojan_go_shared_transport_admitted);
    assert!(!contract.shared_transport_true_dataplane_admitted);
    assert!(!contract.outbound_true_dataplane_admitted);
    assert!(!contract.matched_go_rust_default_daemon_benchmark_recorded);
    assert!(!contract.default_switch_allowed);
    assert!(!contract.product_chain_switch_allowed);

    assert_eq!(contract.next_admission_queue[0].stage, "stage147");
    assert_eq!(contract.next_admission_queue[1].stage, "stage148");
}
