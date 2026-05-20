use super::*;

#[test]
fn stage89_ss2022_multi_psk_gate_matches_golden_fixture() {
    let fixture = load("product/daemon/stage89_ss2022_multi_psk_tcp_dataplane_gate.json");
    let contract = stage89_ss2022_multi_psk_gate_contract();

    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.stage_complete,
        fixture["stage_complete"].as_bool().unwrap()
    );
    assert_eq!(
        contract.ss2022_tcp_true_dataplane_admitted,
        fixture["ss2022_tcp_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.ss2022_multi_psk_identity_header_dataplane_admitted,
        fixture["ss2022_multi_psk_identity_header_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.ss2022_true_dataplane_admitted,
        fixture["ss2022_true_dataplane_admitted"].as_bool().unwrap()
    );
    assert_eq!(
        contract.gate_decision,
        fixture["gate_decision"].as_str().unwrap()
    );
    assert_string_vec(&contract.carried_blockers, &fixture["carried_blockers"]);
}

#[test]
fn stage89_ss2022_multi_psk_gate_keeps_udp_and_defaults_closed() {
    let contract = stage89_ss2022_multi_psk_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.ss2022_tcp_true_dataplane_admitted);
    assert!(contract.ss2022_multi_psk_identity_header_dataplane_admitted);
    assert!(!contract.ss2022_udp_true_dataplane_admitted);
    assert!(!contract.ss2022_true_dataplane_admitted);
    assert!(!contract.shadowsocks_protocol_true_dataplane_admitted);
    assert!(!contract.trojan_go_shared_transport_admitted);
    assert!(!contract.shared_transport_true_dataplane_admitted);
    assert!(!contract.outbound_true_dataplane_admitted);
    assert!(!contract.default_switch_allowed);
    assert!(!contract.product_chain_switch_allowed);
    assert!(contract.go_default_path_preserved);
    assert!(contract.go_fallback_required);

    assert!(contract.gate_decision.contains("BLAKE3-512"));
    assert_contains_text(&contract.carried_blockers, "SS2022 UDP");
    assert_contains_text(
        &contract.validation_commands,
        "stage89-ss2022-multi-psk-tcp-dataplane-admission",
    );
}
