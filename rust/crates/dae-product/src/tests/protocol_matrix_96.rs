use super::*;

#[test]
fn stage96_protocol_matrix_gate_matches_golden_fixture() {
    let fixture = load("product/daemon/stage96_protocol_matrix_recertification_gate.json");
    let contract = stage96_protocol_matrix_gate_contract();

    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.stage_complete,
        fixture["stage_complete"].as_bool().unwrap()
    );
    assert_eq!(
        contract.shadowsocks_protocol_true_dataplane_admitted,
        fixture["shadowsocks_protocol_true_dataplane_admitted"]
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
    assert_string_vec(
        &contract.benchmark_carry_forward,
        &fixture["benchmark_carry_forward"],
    );
    assert_string_vec(&contract.carried_blockers, &fixture["carried_blockers"]);
}

#[test]
fn stage96_protocol_matrix_gate_keeps_defaults_closed() {
    let contract = stage96_protocol_matrix_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.socks5_protocol_true_dataplane_admitted);
    assert!(contract.http_connect_true_dataplane_admitted);
    assert!(contract.https_proxy_true_dataplane_admitted);
    assert!(contract.shadowsocks_protocol_true_dataplane_admitted);
    assert!(contract.trojan_protocol_true_dataplane_admitted);
    assert!(contract.trojan_go_shared_transport_partial_admitted);
    assert!(!contract.trojan_go_shared_transport_admitted);
    assert!(!contract.vmess_protocol_true_dataplane_admitted);
    assert!(!contract.vless_protocol_true_dataplane_admitted);
    assert!(!contract.shared_transport_true_dataplane_admitted);
    assert!(!contract.quic_h3_family_true_dataplane_admitted);
    assert!(!contract.anytls_true_dataplane_admitted);
    assert!(contract.protocol_outbound_partial_admitted);
    assert!(!contract.outbound_true_dataplane_admitted);
    assert!(!contract.default_switch_allowed);
    assert!(!contract.default_path_mutation_allowed);
    assert!(!contract.product_chain_switch_allowed);
    assert!(!contract.true_rust_default_daemon_admitted);
    assert!(contract.go_default_path_preserved);
    assert!(contract.go_fallback_required);

    assert_contains_text(&contract.carried_blockers, "Trojan-Go full grpc-go");
    assert_contains_text(&contract.carried_blockers, "matched Go default daemon");
    assert_contains_text(
        &contract.validation_commands,
        "stage96-protocol-matrix-recertification",
    );
}
