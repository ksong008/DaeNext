use super::*;

#[test]
fn stage133_outbound_true_dataplane_readiness_gate_matches_golden_fixture() {
    let fixture = load("product/daemon/stage133_outbound_true_dataplane_readiness_gate.json");
    let contract = stage133_outbound_true_dataplane_readiness_gate_contract();

    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.stage_complete,
        fixture["stage_complete"].as_bool().unwrap()
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
    assert_string_vec(
        &contract.benchmark_carry_forward,
        &fixture["benchmark_carry_forward"],
    );
    assert_string_vec(&contract.remaining_blockers, &fixture["remaining_blockers"]);
}

#[test]
fn stage133_outbound_true_dataplane_readiness_keeps_total_admission_closed() {
    let contract = stage133_outbound_true_dataplane_readiness_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.socks5_protocol_true_dataplane_admitted);
    assert!(contract.http_connect_true_dataplane_admitted);
    assert!(contract.https_proxy_true_dataplane_admitted);
    assert!(contract.shadowsocks_protocol_true_dataplane_admitted);
    assert!(contract.trojan_protocol_true_dataplane_admitted);
    assert!(contract.anytls_true_dataplane_admitted);
    assert!(contract.quic_h3_family_true_dataplane_admitted);
    assert!(contract.trojan_go_shared_transport_partial_admitted);
    assert!(contract.vmess_protocol_partial_admitted);
    assert!(contract.vless_protocol_partial_admitted);
    assert!(contract.outbound_quic_go_dependency_preserved);
    assert!(contract.external_outbound_required);
    assert!(contract.external_quic_go_required);
    assert!(contract.go_default_path_preserved);
    assert!(contract.go_fallback_required);

    assert!(!contract.trojan_go_utls_fingerprint_wire_admitted);
    assert!(!contract.reality_full_utls_handshake_admitted);
    assert!(!contract.trojan_go_cross_combination_recertified);
    assert!(!contract.trojan_go_shared_transport_admitted);
    assert!(!contract.vmess_protocol_true_dataplane_admitted);
    assert!(!contract.vless_protocol_true_dataplane_admitted);
    assert!(!contract.shared_transport_true_dataplane_admitted);
    assert!(!contract.outbound_true_dataplane_admitted);
    assert!(!contract.matched_go_rust_default_daemon_benchmark_recorded);
    assert!(!contract.default_switch_allowed);
    assert!(!contract.default_path_mutation_allowed);
    assert!(!contract.product_chain_switch_allowed);
    assert!(!contract.true_rust_default_daemon_admitted);

    assert_eq!(contract.next_admission_queue[0].stage, "stage134");
    assert_eq!(contract.next_admission_queue[1].stage, "stage135");
    assert_eq!(contract.next_admission_queue[2].stage, "stage136");
    assert_eq!(contract.next_admission_queue[3].stage, "stage137");
}
