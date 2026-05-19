use super::*;

#[test]
fn stage81_shared_tls_underlay_gate_matches_golden_fixture() {
    let fixture = load("product/daemon/stage81_shared_tls_underlay_dataplane_gate.json");
    let contract = stage81_shared_tls_underlay_gate_contract();

    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.stage_complete,
        fixture["stage_complete"].as_bool().unwrap()
    );
    assert_eq!(
        contract.shared_tls_underlay_admitted,
        fixture["shared_tls_underlay_admitted"].as_bool().unwrap()
    );
    assert_eq!(
        contract.shared_transport_true_dataplane_admitted,
        fixture["shared_transport_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.https_proxy_tls_underlay_admitted,
        fixture["https_proxy_tls_underlay_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.trojan_tls_underlay_admitted,
        fixture["trojan_tls_underlay_admitted"].as_bool().unwrap()
    );
    assert_eq!(
        contract.vless_tls_underlay_admitted,
        fixture["vless_tls_underlay_admitted"].as_bool().unwrap()
    );
    assert_eq!(
        contract.vmess_tls_underlay_admitted,
        fixture["vmess_tls_underlay_admitted"].as_bool().unwrap()
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
        contract.true_rust_default_daemon_admitted,
        fixture["true_rust_default_daemon_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.gate_decision,
        fixture["gate_decision"].as_str().unwrap()
    );
    assert_string_vec(&contract.carried_blockers, &fixture["carried_blockers"]);
}

#[test]
fn stage81_shared_tls_underlay_gate_keeps_protocol_tls_rows_closed() {
    let contract = stage81_shared_tls_underlay_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.shared_tls_underlay_admitted);
    assert!(!contract.shared_transport_true_dataplane_admitted);
    assert!(!contract.https_proxy_tls_underlay_admitted);
    assert!(!contract.trojan_tls_underlay_admitted);
    assert!(!contract.trojan_go_shared_transport_admitted);
    assert!(!contract.trojan_protocol_true_dataplane_admitted);
    assert!(!contract.vless_tls_underlay_admitted);
    assert!(!contract.vless_reality_underlay_admitted);
    assert!(!contract.vless_vision_admitted);
    assert!(!contract.vless_shared_transport_admitted);
    assert!(!contract.vless_protocol_true_dataplane_admitted);
    assert!(!contract.vmess_tls_underlay_admitted);
    assert!(!contract.vmess_shared_transport_admitted);
    assert!(!contract.vmess_protocol_true_dataplane_admitted);
    assert!(!contract.ss2022_true_dataplane_admitted);
    assert!(!contract.outbound_true_dataplane_admitted);
    assert!(!contract.default_switch_allowed);
    assert!(!contract.product_chain_switch_allowed);
    assert!(!contract.true_rust_default_daemon_admitted);
    assert!(contract.go_default_path_preserved);
    assert!(contract.go_fallback_required);

    let areas = contract.rows.iter().map(|row| row.area).collect::<Vec<_>>();
    assert_eq!(
        areas,
        vec![
            "Prior outbound protocol evidence",
            "Shared rustls TLS underlay",
            "uTLS, REALITY, TLS fragment, and Vision",
            "Protocol-specific TLS consumers",
            "overall outbound/default admission"
        ]
    );
    assert_contains_text(&contract.carried_blockers, "uTLS");
    assert_contains_text(&contract.carried_blockers, "HTTPS proxy");
    assert_contains_text(
        &contract.validation_commands,
        "stage81-shared-tls-underlay-dataplane-admission",
    );
}
