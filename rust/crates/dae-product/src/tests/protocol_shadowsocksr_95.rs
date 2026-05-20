use super::*;

#[test]
fn stage95_shadowsocksr_gate_matches_golden_fixture() {
    let fixture = load("product/daemon/stage95_shadowsocksr_three_layer_dataplane_gate.json");
    let contract = stage95_shadowsocksr_gate_contract();

    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.stage_complete,
        fixture["stage_complete"].as_bool().unwrap()
    );
    assert_eq!(
        contract.shadowsocksr_true_dataplane_admitted,
        fixture["shadowsocksr_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
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
fn stage95_shadowsocksr_gate_opens_family_but_keeps_defaults_closed() {
    let contract = stage95_shadowsocksr_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.shadowsocks_aead_protocol_true_dataplane_admitted);
    assert!(contract.ss2022_true_dataplane_admitted);
    assert!(contract.sip003_plugin_transport_admitted);
    assert!(contract.shadowsocksr_true_dataplane_admitted);
    assert!(contract.shadowsocks_protocol_true_dataplane_admitted);
    assert!(!contract.outbound_true_dataplane_admitted);
    assert!(!contract.default_switch_allowed);
    assert!(!contract.product_chain_switch_allowed);
    assert!(contract.go_default_path_preserved);
    assert!(contract.go_fallback_required);

    assert!(contract.gate_decision.contains("ShadowsocksR three-layer"));
    assert_contains_text(&contract.carried_blockers, "default switch");
    assert_contains_text(
        &contract.validation_commands,
        "stage95-shadowsocksr-three-layer-dataplane-admission",
    );
}
