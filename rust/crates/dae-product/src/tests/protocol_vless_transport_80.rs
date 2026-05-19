use super::*;

#[test]
fn stage80_vless_xhttp_xmux_gate_matches_golden_fixture() {
    let fixture = load("product/daemon/stage80_vless_xhttp_xmux_dataplane_gate.json");
    let contract = stage80_vless_xhttp_xmux_gate_contract();

    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.stage_complete,
        fixture["stage_complete"].as_bool().unwrap()
    );
    assert_eq!(
        contract.vless_xhttp_admitted,
        fixture["vless_xhttp_admitted"].as_bool().unwrap()
    );
    assert_eq!(
        contract.vless_xhttp_xmux_admitted,
        fixture["vless_xhttp_xmux_admitted"].as_bool().unwrap()
    );
    assert_eq!(
        contract.vless_shared_transport_partial_admitted,
        fixture["vless_shared_transport_partial_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.vless_shared_transport_admitted,
        fixture["vless_shared_transport_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.vless_protocol_true_dataplane_admitted,
        fixture["vless_protocol_true_dataplane_admitted"]
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
fn stage80_vless_xhttp_xmux_gate_blocks_default_admission() {
    let contract = stage80_vless_xhttp_xmux_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.vless_xhttp_admitted);
    assert!(contract.vless_xhttp_xmux_admitted);
    assert!(contract.vless_shared_transport_partial_admitted);
    assert!(contract.vless_protocol_partial_admitted);
    assert!(!contract.vless_shared_transport_admitted);
    assert!(!contract.vless_protocol_true_dataplane_admitted);
    assert!(!contract.vless_tls_underlay_admitted);
    assert!(!contract.vless_reality_underlay_admitted);
    assert!(!contract.vless_vision_admitted);
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
            "Prior VLESS shared transport evidence",
            "VLESS xHTTP xmux data plane",
            "VLESS xHTTP full lifecycle",
            "VLESS TLS, REALITY, Vision, and remaining transports",
            "Prior VMess shared transport evidence",
            "overall outbound/default admission"
        ]
    );
    assert_contains_text(&contract.carried_blockers, "downloadSettings");
    assert!(
        !contract
            .carried_blockers
            .iter()
            .any(|blocker| blocker.contains("xmux pool"))
    );
    assert_contains_text(
        &contract.validation_commands,
        "stage80-vless-xhttp-xmux-dataplane-admission",
    );
}
