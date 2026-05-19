use super::*;

#[test]
fn stage65_vmess_aead_tcp_gate_matches_golden_fixture() {
    let fixture = load("product/daemon/stage65_vmess_aead_tcp_dataplane_gate.json");
    let contract = stage65_vmess_aead_tcp_gate_contract();

    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.stage_complete,
        fixture["stage_complete"].as_bool().unwrap()
    );
    assert_eq!(
        contract.vless_protocol_partial_admitted,
        fixture["vless_protocol_partial_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.vmess_aead_tcp_true_dataplane_admitted,
        fixture["vmess_aead_tcp_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.vmess_protocol_partial_admitted,
        fixture["vmess_protocol_partial_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.vmess_protocol_true_dataplane_admitted,
        fixture["vmess_protocol_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.vmess_tls_underlay_admitted,
        fixture["vmess_tls_underlay_admitted"].as_bool().unwrap()
    );
    assert_eq!(
        contract.vmess_shared_transport_admitted,
        fixture["vmess_shared_transport_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.vmess_udp_packet_addr_admitted,
        fixture["vmess_udp_packet_addr_admitted"].as_bool().unwrap()
    );
    assert_eq!(
        contract.vmess_mux_admitted,
        fixture["vmess_mux_admitted"].as_bool().unwrap()
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
fn stage65_vmess_aead_tcp_gate_blocks_default_admission() {
    let contract = stage65_vmess_aead_tcp_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.vless_protocol_partial_admitted);
    assert!(!contract.vless_protocol_true_dataplane_admitted);
    assert!(contract.vmess_aead_tcp_true_dataplane_admitted);
    assert!(contract.vmess_protocol_partial_admitted);
    assert!(!contract.vmess_protocol_true_dataplane_admitted);
    assert!(!contract.vmess_tls_underlay_admitted);
    assert!(!contract.vmess_shared_transport_admitted);
    assert!(!contract.vmess_udp_packet_addr_admitted);
    assert!(!contract.vmess_mux_admitted);
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
            "Prior protocol carried evidence",
            "VMess AEAD raw TCP data plane",
            "VMess transport rows",
            "VMess UDP and mux rows",
            "overall outbound/default admission"
        ]
    );
    assert_contains_text(&contract.carried_blockers, "VMess TLS/shared transport");
    assert_contains_text(&contract.carried_blockers, "SS2022");
    assert_contains_text(
        &contract.validation_commands,
        "stage65-vmess-aead-tcp-dataplane-admission",
    );
}

#[test]
fn stage66_vmess_aead_udp_over_tcp_gate_matches_golden_fixture() {
    let fixture = load("product/daemon/stage66_vmess_aead_udp_over_tcp_dataplane_gate.json");
    let contract = stage66_vmess_aead_udp_over_tcp_gate_contract();

    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.stage_complete,
        fixture["stage_complete"].as_bool().unwrap()
    );
    assert_eq!(
        contract.vmess_aead_tcp_true_dataplane_admitted,
        fixture["vmess_aead_tcp_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.vmess_aead_udp_over_tcp_admitted,
        fixture["vmess_aead_udp_over_tcp_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.vmess_protocol_partial_admitted,
        fixture["vmess_protocol_partial_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.vmess_protocol_true_dataplane_admitted,
        fixture["vmess_protocol_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.vmess_udp_packet_addr_admitted,
        fixture["vmess_udp_packet_addr_admitted"].as_bool().unwrap()
    );
    assert_eq!(
        contract.vmess_mux_admitted,
        fixture["vmess_mux_admitted"].as_bool().unwrap()
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
fn stage66_vmess_aead_udp_over_tcp_gate_blocks_default_admission() {
    let contract = stage66_vmess_aead_udp_over_tcp_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.vmess_aead_tcp_true_dataplane_admitted);
    assert!(contract.vmess_aead_udp_over_tcp_admitted);
    assert!(contract.vmess_protocol_partial_admitted);
    assert!(!contract.vmess_protocol_true_dataplane_admitted);
    assert!(!contract.vmess_udp_packet_addr_admitted);
    assert!(!contract.vmess_mux_admitted);
    assert!(!contract.vmess_tls_underlay_admitted);
    assert!(!contract.vmess_shared_transport_admitted);
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
            "Prior VMess AEAD TCP evidence",
            "VMess AEAD UDP-over-TCP fixed target",
            "VMess packet-addr and mux rows",
            "VMess transport rows",
            "overall outbound/default admission"
        ]
    );
    assert_contains_text(&contract.carried_blockers, "VMess packet-addr");
    assert_contains_text(&contract.carried_blockers, "SS2022");
    assert_contains_text(
        &contract.validation_commands,
        "stage66-vmess-aead-udp-over-tcp-dataplane-admission",
    );
}

#[test]
fn stage67_vmess_packet_addr_udp_gate_matches_golden_fixture() {
    let fixture = load("product/daemon/stage67_vmess_packet_addr_udp_dataplane_gate.json");
    let contract = stage67_vmess_packet_addr_udp_gate_contract();

    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.stage_complete,
        fixture["stage_complete"].as_bool().unwrap()
    );
    assert_eq!(
        contract.vmess_aead_tcp_true_dataplane_admitted,
        fixture["vmess_aead_tcp_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.vmess_aead_udp_over_tcp_admitted,
        fixture["vmess_aead_udp_over_tcp_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.vmess_udp_packet_addr_admitted,
        fixture["vmess_udp_packet_addr_admitted"].as_bool().unwrap()
    );
    assert_eq!(
        contract.vmess_protocol_partial_admitted,
        fixture["vmess_protocol_partial_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.vmess_protocol_true_dataplane_admitted,
        fixture["vmess_protocol_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.vmess_mux_admitted,
        fixture["vmess_mux_admitted"].as_bool().unwrap()
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
fn stage67_vmess_packet_addr_udp_gate_blocks_default_admission() {
    let contract = stage67_vmess_packet_addr_udp_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.vmess_aead_tcp_true_dataplane_admitted);
    assert!(contract.vmess_aead_udp_over_tcp_admitted);
    assert!(contract.vmess_udp_packet_addr_admitted);
    assert!(contract.vmess_protocol_partial_admitted);
    assert!(!contract.vmess_protocol_true_dataplane_admitted);
    assert!(!contract.vmess_mux_admitted);
    assert!(!contract.vmess_tls_underlay_admitted);
    assert!(!contract.vmess_shared_transport_admitted);
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
            "Prior VMess AEAD evidence",
            "VMess packet-addr UDP data plane",
            "VMess mux row",
            "VMess transport rows",
            "overall outbound/default admission"
        ]
    );
    assert_contains_text(&contract.carried_blockers, "VMess mux");
    assert_contains_text(&contract.carried_blockers, "SS2022");
    assert_contains_text(
        &contract.validation_commands,
        "stage67-vmess-packet-addr-udp-dataplane-admission",
    );
}

#[test]
fn stage68_vmess_mux_gate_matches_golden_fixture() {
    let fixture = load("product/daemon/stage68_vmess_mux_dataplane_gate.json");
    let contract = stage68_vmess_mux_gate_contract();

    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.stage_complete,
        fixture["stage_complete"].as_bool().unwrap()
    );
    assert_eq!(
        contract.vmess_aead_tcp_true_dataplane_admitted,
        fixture["vmess_aead_tcp_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.vmess_aead_udp_over_tcp_admitted,
        fixture["vmess_aead_udp_over_tcp_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.vmess_udp_packet_addr_admitted,
        fixture["vmess_udp_packet_addr_admitted"].as_bool().unwrap()
    );
    assert_eq!(
        contract.vmess_mux_admitted,
        fixture["vmess_mux_admitted"].as_bool().unwrap()
    );
    assert_eq!(
        contract.vmess_protocol_partial_admitted,
        fixture["vmess_protocol_partial_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.vmess_protocol_true_dataplane_admitted,
        fixture["vmess_protocol_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.vmess_tls_underlay_admitted,
        fixture["vmess_tls_underlay_admitted"].as_bool().unwrap()
    );
    assert_eq!(
        contract.vmess_shared_transport_admitted,
        fixture["vmess_shared_transport_admitted"]
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
fn stage68_vmess_mux_gate_blocks_default_admission() {
    let contract = stage68_vmess_mux_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.vmess_aead_tcp_true_dataplane_admitted);
    assert!(contract.vmess_aead_udp_over_tcp_admitted);
    assert!(contract.vmess_udp_packet_addr_admitted);
    assert!(contract.vmess_mux_admitted);
    assert!(contract.vmess_protocol_partial_admitted);
    assert!(!contract.vmess_protocol_true_dataplane_admitted);
    assert!(!contract.vmess_tls_underlay_admitted);
    assert!(!contract.vmess_shared_transport_admitted);
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
            "Prior VMess AEAD evidence",
            "VMess mux data plane",
            "VMess default mux exposure",
            "VMess transport rows",
            "overall outbound/default admission"
        ]
    );
    assert_contains_text(&contract.carried_blockers, "VMess TLS");
    assert_contains_text(&contract.carried_blockers, "SS2022");
    assert_contains_text(
        &contract.validation_commands,
        "stage68-vmess-mux-dataplane-admission",
    );
}
