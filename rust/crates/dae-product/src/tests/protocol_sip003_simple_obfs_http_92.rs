use super::*;

#[test]
fn stage92_sip003_simple_obfs_http_gate_matches_golden_fixture() {
    let fixture = load("product/daemon/stage92_sip003_simple_obfs_http_dataplane_gate.json");
    let contract = stage92_sip003_simple_obfs_http_gate_contract();

    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.stage_complete,
        fixture["stage_complete"].as_bool().unwrap()
    );
    assert_eq!(
        contract.sip003_simple_obfs_http_admitted,
        fixture["sip003_simple_obfs_http_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.sip003_plugin_transport_admitted,
        fixture["sip003_plugin_transport_admitted"]
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
fn stage92_sip003_simple_obfs_http_gate_keeps_family_and_defaults_closed() {
    let contract = stage92_sip003_simple_obfs_http_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.shadowsocks_aead_protocol_true_dataplane_admitted);
    assert!(contract.ss2022_true_dataplane_admitted);
    assert!(contract.sip003_simple_obfs_http_admitted);
    assert!(!contract.sip003_simple_obfs_tls_admitted);
    assert!(!contract.sip003_v2ray_plugin_admitted);
    assert!(!contract.sip003_plugin_transport_admitted);
    assert!(!contract.shadowsocksr_true_dataplane_admitted);
    assert!(!contract.shadowsocks_protocol_true_dataplane_admitted);
    assert!(!contract.trojan_go_shared_transport_admitted);
    assert!(!contract.shared_transport_true_dataplane_admitted);
    assert!(!contract.outbound_true_dataplane_admitted);
    assert!(!contract.default_switch_allowed);
    assert!(!contract.product_chain_switch_allowed);
    assert!(contract.go_default_path_preserved);
    assert!(contract.go_fallback_required);

    assert!(contract.gate_decision.contains("simple-obfs HTTP"));
    assert_contains_text(&contract.carried_blockers, "simple-obfs TLS");
    assert_contains_text(&contract.carried_blockers, "v2ray-plugin");
    assert_contains_text(
        &contract.validation_commands,
        "stage92-sip003-simple-obfs-http-dataplane-admission",
    );
}
