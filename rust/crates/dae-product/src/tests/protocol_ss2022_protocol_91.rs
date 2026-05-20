use super::*;

#[test]
fn stage91_ss2022_protocol_gate_matches_golden_fixture() {
    let fixture = load("product/daemon/stage91_ss2022_protocol_wide_gate.json");
    let contract = stage91_ss2022_protocol_gate_contract();

    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.stage_complete,
        fixture["stage_complete"].as_bool().unwrap()
    );
    assert_eq!(
        contract.ss2022_true_dataplane_admitted,
        fixture["ss2022_true_dataplane_admitted"].as_bool().unwrap()
    );
    assert_eq!(
        contract.shadowsocks_protocol_true_dataplane_admitted,
        fixture["shadowsocks_protocol_true_dataplane_admitted"]
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
fn stage91_ss2022_protocol_gate_keeps_family_and_defaults_closed() {
    let contract = stage91_ss2022_protocol_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.ss2022_tcp_true_dataplane_admitted);
    assert!(contract.ss2022_multi_psk_identity_header_dataplane_admitted);
    assert!(contract.ss2022_udp_true_dataplane_admitted);
    assert!(contract.ss2022_true_dataplane_admitted);
    assert!(!contract.sip003_plugin_transport_admitted);
    assert!(!contract.shadowsocksr_true_dataplane_admitted);
    assert!(!contract.shadowsocks_protocol_true_dataplane_admitted);
    assert!(!contract.outbound_true_dataplane_admitted);
    assert!(!contract.default_switch_allowed);
    assert!(!contract.product_chain_switch_allowed);
    assert!(contract.go_default_path_preserved);
    assert!(contract.go_fallback_required);

    assert!(contract.gate_decision.contains("Stage 88"));
    assert_contains_text(&contract.carried_blockers, "SIP003 plugin");
    assert_contains_text(
        &contract.validation_commands,
        "stage91-ss2022-protocol-wide-admission",
    );
}
