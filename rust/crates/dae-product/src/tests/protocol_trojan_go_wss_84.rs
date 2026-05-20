use super::*;

#[test]
fn stage84_trojan_go_wss_gate_matches_golden_fixture() {
    let fixture = load("product/daemon/stage84_trojan_go_wss_dataplane_gate.json");
    let contract = stage84_trojan_go_wss_gate_contract();

    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.stage_complete,
        fixture["stage_complete"].as_bool().unwrap()
    );
    assert_eq!(
        contract.trojan_protocol_true_dataplane_admitted,
        fixture["trojan_protocol_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.trojan_go_wss_admitted,
        fixture["trojan_go_wss_admitted"].as_bool().unwrap()
    );
    assert_eq!(
        contract.trojan_go_shared_transport_partial_admitted,
        fixture["trojan_go_shared_transport_partial_admitted"]
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
        contract.trojan_go_grpc_admitted,
        fixture["trojan_go_grpc_admitted"].as_bool().unwrap()
    );
    assert_eq!(
        contract.trojan_go_httpupgrade_admitted,
        fixture["trojan_go_httpupgrade_admitted"].as_bool().unwrap()
    );
    assert_eq!(
        contract.trojan_go_inner_shadowsocks_admitted,
        fixture["trojan_go_inner_shadowsocks_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.shared_transport_true_dataplane_admitted,
        fixture["shared_transport_true_dataplane_admitted"]
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
        contract.default_switch_allowed,
        fixture["default_switch_allowed"].as_bool().unwrap()
    );
    assert_eq!(
        contract.product_chain_switch_allowed,
        fixture["product_chain_switch_allowed"].as_bool().unwrap()
    );
    assert_eq!(
        contract.gate_decision,
        fixture["gate_decision"].as_str().unwrap()
    );
    assert_string_vec(&contract.carried_blockers, &fixture["carried_blockers"]);
}

#[test]
fn stage84_trojan_go_wss_gate_keeps_full_trojan_go_and_defaults_closed() {
    let contract = stage84_trojan_go_wss_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.trojan_protocol_true_dataplane_admitted);
    assert!(contract.trojan_go_wss_admitted);
    assert!(contract.trojan_go_shared_transport_partial_admitted);
    assert!(!contract.trojan_go_shared_transport_admitted);
    assert!(!contract.trojan_go_grpc_admitted);
    assert!(!contract.trojan_go_httpupgrade_admitted);
    assert!(!contract.trojan_go_inner_shadowsocks_admitted);
    assert!(!contract.ss2022_true_dataplane_admitted);
    assert!(!contract.vless_tls_underlay_admitted);
    assert!(!contract.vmess_tls_underlay_admitted);
    assert!(!contract.shared_transport_true_dataplane_admitted);
    assert!(!contract.outbound_true_dataplane_admitted);
    assert!(!contract.default_switch_allowed);
    assert!(!contract.product_chain_switch_allowed);
    assert!(contract.go_default_path_preserved);
    assert!(contract.go_fallback_required);

    let areas = contract.rows.iter().map(|row| row.area).collect::<Vec<_>>();
    assert_eq!(
        areas,
        vec![
            "Prior standard Trojan evidence",
            "Trojan-Go WSS data plane",
            "Trojan-Go remaining shared transports",
            "Trojan-Go inner Shadowsocks",
            "Other protocols and global TLS features"
        ]
    );
    assert_contains_text(&contract.carried_blockers, "gRPC");
    assert_contains_text(&contract.carried_blockers, "inner Shadowsocks");
    assert_contains_text(
        &contract.validation_commands,
        "stage84-trojan-go-wss-dataplane-admission",
    );
}
