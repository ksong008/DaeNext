use super::*;

#[test]
fn stage129_juicity_outbound_dataplane_gate_matches_golden_fixture() {
    let fixture = load("product/daemon/stage129_juicity_outbound_dataplane_gate.json");
    let contract = stage129_juicity_outbound_dataplane_gate_contract();

    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.stage_complete,
        fixture["stage_complete"].as_bool().unwrap()
    );
    assert_eq!(
        contract.juicity_true_quic_h3_dataplane_admitted,
        fixture["juicity_true_quic_h3_dataplane_admitted"]
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
fn stage129_juicity_outbound_dataplane_opens_only_juicity_true_h3() {
    let contract = stage129_juicity_outbound_dataplane_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.juicity_client_integration_candidate_admitted);
    assert!(contract.juicity_outbound_registry_admitted);
    assert!(contract.juicity_group_selection_admitted);
    assert!(contract.juicity_health_policy_admitted);
    assert!(contract.juicity_true_quic_h3_dataplane_admitted);
    assert_eq!(contract.group_name, "stage129-juicity");
    assert_eq!(contract.selection_policy, "min");
    assert_eq!(contract.network_type, "tcp4");
    assert_eq!(contract.raw_link_count, 3);
    assert_eq!(contract.valid_dialer_count, 2);
    assert_eq!(contract.skipped_link_count, 1);
    assert_eq!(contract.selected_index, 1);
    assert_eq!(contract.selected_latency_ms, 52);
    assert_eq!(contract.selected_name, "stage129-fast");
    assert_eq!(contract.selected_address, "fast.example:8443");
    assert_eq!(contract.selected_protocol, "juicity");
    assert_eq!(contract.default_total_exchange_count, 19);
    assert!(contract.anytls_true_dataplane_admitted);
    assert!(contract.protocol_outbound_partial_admitted);
    assert!(contract.outbound_quic_go_dependency_preserved);
    assert!(contract.external_outbound_required);
    assert!(contract.external_quic_go_required);
    assert!(contract.go_default_path_preserved);
    assert!(contract.go_fallback_required);

    assert!(!contract.hysteria2_true_quic_dataplane_admitted);
    assert!(!contract.tuic_true_quic_dataplane_admitted);
    assert!(!contract.quic_h3_family_true_dataplane_admitted);
    assert!(!contract.outbound_true_dataplane_admitted);
    assert!(!contract.matched_go_rust_default_daemon_benchmark_recorded);
    assert!(!contract.default_switch_allowed);
    assert!(!contract.default_path_mutation_allowed);
    assert!(!contract.product_chain_switch_allowed);
    assert!(!contract.true_rust_default_daemon_admitted);
}
