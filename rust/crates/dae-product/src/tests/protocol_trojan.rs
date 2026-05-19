use super::*;

#[test]
fn stage60_trojan_tcp_gate_matches_golden_fixture() {
    let fixture = load("product/daemon/stage60_trojan_tcp_dataplane_gate.json");
    let contract = stage60_trojan_tcp_gate_contract();

    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.stage_complete,
        fixture["stage_complete"].as_bool().unwrap()
    );
    assert_eq!(
        contract.shadowsocks_aead_protocol_true_dataplane_admitted,
        fixture["shadowsocks_aead_protocol_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.ss2022_true_dataplane_admitted,
        fixture["ss2022_true_dataplane_admitted"].as_bool().unwrap()
    );
    assert_eq!(
        contract.trojanc_tcp_true_dataplane_admitted,
        fixture["trojanc_tcp_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.trojan_protocol_partial_admitted,
        fixture["trojan_protocol_partial_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.trojan_protocol_true_dataplane_admitted,
        fixture["trojan_protocol_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.trojan_tls_underlay_admitted,
        fixture["trojan_tls_underlay_admitted"].as_bool().unwrap()
    );
    assert_eq!(
        contract.trojan_udp_over_tcp_admitted,
        fixture["trojan_udp_over_tcp_admitted"].as_bool().unwrap()
    );
    assert_eq!(
        contract.trojan_go_shared_transport_admitted,
        fixture["trojan_go_shared_transport_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.trojan_go_inner_shadowsocks_admitted,
        fixture["trojan_go_inner_shadowsocks_admitted"]
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
        contract.go_default_path_preserved,
        fixture["go_default_path_preserved"].as_bool().unwrap()
    );
    assert_eq!(
        contract.go_fallback_required,
        fixture["go_fallback_required"].as_bool().unwrap()
    );
    assert_eq!(
        contract.gate_decision,
        fixture["gate_decision"].as_str().unwrap()
    );
    assert_string_vec(&contract.carried_blockers, &fixture["carried_blockers"]);
}

#[test]
fn stage60_trojan_tcp_gate_blocks_default_admission() {
    let contract = stage60_trojan_tcp_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.shadowsocks_aead_protocol_true_dataplane_admitted);
    assert!(!contract.shadowsocks_protocol_true_dataplane_admitted);
    assert!(!contract.ss2022_true_dataplane_admitted);
    assert!(contract.trojanc_tcp_true_dataplane_admitted);
    assert!(contract.trojan_protocol_partial_admitted);
    assert!(!contract.trojan_protocol_true_dataplane_admitted);
    assert!(!contract.trojan_tls_underlay_admitted);
    assert!(!contract.trojan_udp_over_tcp_admitted);
    assert!(!contract.trojan_go_shared_transport_admitted);
    assert!(!contract.trojan_go_inner_shadowsocks_admitted);
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
            "Prior outbound carried evidence",
            "SS2022 true dataplane",
            "trojanc TCP data plane",
            "Trojan and Trojan-Go remaining layers",
            "overall outbound/default admission"
        ]
    );
    assert_contains_text(&contract.carried_blockers, "SS2022 TCP/UDP");
    assert_contains_text(&contract.carried_blockers, "Trojan TLS underlay");
    assert_contains_text(
        &contract.validation_commands,
        "stage60-trojan-tcp-dataplane-admission",
    );
}

#[test]
fn stage61_trojan_udp_over_tcp_gate_matches_golden_fixture() {
    let fixture = load("product/daemon/stage61_trojan_udp_over_tcp_dataplane_gate.json");
    let contract = stage61_trojan_udp_over_tcp_gate_contract();

    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.stage_complete,
        fixture["stage_complete"].as_bool().unwrap()
    );
    assert_eq!(
        contract.trojanc_tcp_true_dataplane_admitted,
        fixture["trojanc_tcp_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.trojan_udp_over_tcp_admitted,
        fixture["trojan_udp_over_tcp_admitted"].as_bool().unwrap()
    );
    assert_eq!(
        contract.trojan_protocol_partial_admitted,
        fixture["trojan_protocol_partial_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.trojan_protocol_true_dataplane_admitted,
        fixture["trojan_protocol_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.trojan_tls_underlay_admitted,
        fixture["trojan_tls_underlay_admitted"].as_bool().unwrap()
    );
    assert_eq!(
        contract.trojan_go_shared_transport_admitted,
        fixture["trojan_go_shared_transport_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.trojan_go_inner_shadowsocks_admitted,
        fixture["trojan_go_inner_shadowsocks_admitted"]
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
        contract.go_default_path_preserved,
        fixture["go_default_path_preserved"].as_bool().unwrap()
    );
    assert_eq!(
        contract.go_fallback_required,
        fixture["go_fallback_required"].as_bool().unwrap()
    );
    assert_eq!(
        contract.gate_decision,
        fixture["gate_decision"].as_str().unwrap()
    );
    assert_string_vec(&contract.carried_blockers, &fixture["carried_blockers"]);
}

#[test]
fn stage61_trojan_udp_over_tcp_gate_blocks_default_admission() {
    let contract = stage61_trojan_udp_over_tcp_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.trojanc_tcp_true_dataplane_admitted);
    assert!(contract.trojan_udp_over_tcp_admitted);
    assert!(contract.trojan_protocol_partial_admitted);
    assert!(!contract.trojan_protocol_true_dataplane_admitted);
    assert!(!contract.trojan_tls_underlay_admitted);
    assert!(!contract.trojan_go_shared_transport_admitted);
    assert!(!contract.trojan_go_inner_shadowsocks_admitted);
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
            "trojanc TCP carried evidence",
            "Trojan UDP-over-TCP PacketConn data plane",
            "TCP underlay evidence",
            "Trojan TLS and Trojan-Go remaining layers",
            "overall outbound/default admission"
        ]
    );
    assert_contains_text(&contract.carried_blockers, "Trojan TLS underlay");
    assert_contains_text(&contract.carried_blockers, "SS2022 TCP/UDP");
    assert_contains_text(
        &contract.validation_commands,
        "stage61-trojan-udp-over-tcp-dataplane-admission",
    );
}
