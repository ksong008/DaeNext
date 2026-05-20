use super::*;

#[test]
fn stage100_trojan_go_tls_fragment_gate_matches_golden_fixture() {
    let fixture = load("product/daemon/stage100_trojan_go_tls_fragment_gate.json");
    let contract = stage100_trojan_go_tls_fragment_gate_contract();

    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.stage_complete,
        fixture["stage_complete"].as_bool().unwrap()
    );
    assert_eq!(
        contract.trojan_go_tls_fragment_admitted,
        fixture["trojan_go_tls_fragment_admitted"]
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
fn stage100_trojan_go_tls_fragment_keeps_full_transport_and_defaults_closed() {
    let contract = stage100_trojan_go_tls_fragment_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.trojan_go_wss_admitted);
    assert!(contract.trojan_go_httpupgrade_admitted);
    assert!(contract.trojan_go_grpc_hunk_admitted);
    assert!(contract.trojan_go_inner_shadowsocks_admitted);
    assert!(contract.trojan_go_grpc_http2_tls_lifecycle_admitted);
    assert!(contract.trojan_go_grpc_cache_cleanup_admitted);
    assert!(contract.trojan_go_grpc_cancellation_stress_admitted);
    assert!(contract.trojan_go_tls_fragment_admitted);
    assert!(!contract.trojan_go_utls_fingerprint_admitted);
    assert!(!contract.trojan_go_reality_mutation_admitted);
    assert!(!contract.trojan_go_cross_combination_recertified);
    assert!(contract.trojan_go_shared_transport_partial_admitted);
    assert!(!contract.trojan_go_shared_transport_admitted);
    assert!(!contract.shared_transport_true_dataplane_admitted);
    assert!(!contract.outbound_true_dataplane_admitted);
    assert!(!contract.default_switch_allowed);
    assert!(!contract.product_chain_switch_allowed);
    assert!(contract.go_default_path_preserved);
    assert!(contract.go_fallback_required);

    assert_contains_text(&contract.remaining_blockers, "uTLS");
    assert_contains_text(&contract.remaining_blockers, "cross-combination");
}
