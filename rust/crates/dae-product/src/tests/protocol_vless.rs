use super::*;

#[test]
fn stage62_vless_tcp_gate_matches_golden_fixture() {
    let fixture = load("product/daemon/stage62_vless_tcp_dataplane_gate.json");
    let contract = stage62_vless_tcp_gate_contract();

    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.stage_complete,
        fixture["stage_complete"].as_bool().unwrap()
    );
    assert_eq!(
        contract.vless_tcp_raw_true_dataplane_admitted,
        fixture["vless_tcp_raw_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.vless_protocol_partial_admitted,
        fixture["vless_protocol_partial_admitted"]
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
        contract.vless_tls_underlay_admitted,
        fixture["vless_tls_underlay_admitted"].as_bool().unwrap()
    );
    assert_eq!(
        contract.vless_reality_admitted,
        fixture["vless_reality_admitted"].as_bool().unwrap()
    );
    assert_eq!(
        contract.vless_xtls_vision_admitted,
        fixture["vless_xtls_vision_admitted"].as_bool().unwrap()
    );
    assert_eq!(
        contract.vless_shared_transport_admitted,
        fixture["vless_shared_transport_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.vless_udp_mux_admitted,
        fixture["vless_udp_mux_admitted"].as_bool().unwrap()
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
fn stage62_vless_tcp_gate_blocks_default_admission() {
    let contract = stage62_vless_tcp_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.vless_tcp_raw_true_dataplane_admitted);
    assert!(contract.vless_protocol_partial_admitted);
    assert!(!contract.vless_protocol_true_dataplane_admitted);
    assert!(!contract.vless_tls_underlay_admitted);
    assert!(!contract.vless_reality_admitted);
    assert!(!contract.vless_xtls_vision_admitted);
    assert!(!contract.vless_shared_transport_admitted);
    assert!(!contract.vless_udp_mux_admitted);
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
            "VLESS raw TCP data plane",
            "VLESS TLS, REALITY, and XTLS Vision",
            "VLESS shared transport and UDP/mux",
            "overall outbound/default admission"
        ]
    );
    assert_contains_text(&contract.carried_blockers, "VLESS TLS/REALITY");
    assert_contains_text(&contract.carried_blockers, "VMess");
    assert_contains_text(
        &contract.validation_commands,
        "stage62-vless-tcp-dataplane-admission",
    );
}

#[test]
fn stage63_vless_udp_over_tcp_gate_matches_golden_fixture() {
    let fixture = load("product/daemon/stage63_vless_udp_over_tcp_dataplane_gate.json");
    let contract = stage63_vless_udp_over_tcp_gate_contract();

    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.stage_complete,
        fixture["stage_complete"].as_bool().unwrap()
    );
    assert_eq!(
        contract.vless_tcp_raw_true_dataplane_admitted,
        fixture["vless_tcp_raw_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.vless_udp_over_tcp_admitted,
        fixture["vless_udp_over_tcp_admitted"].as_bool().unwrap()
    );
    assert_eq!(
        contract.vless_protocol_partial_admitted,
        fixture["vless_protocol_partial_admitted"]
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
        contract.vless_tls_underlay_admitted,
        fixture["vless_tls_underlay_admitted"].as_bool().unwrap()
    );
    assert_eq!(
        contract.vless_reality_admitted,
        fixture["vless_reality_admitted"].as_bool().unwrap()
    );
    assert_eq!(
        contract.vless_xtls_vision_admitted,
        fixture["vless_xtls_vision_admitted"].as_bool().unwrap()
    );
    assert_eq!(
        contract.vless_shared_transport_admitted,
        fixture["vless_shared_transport_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.vless_mux_admitted,
        fixture["vless_mux_admitted"].as_bool().unwrap()
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
fn stage63_vless_udp_over_tcp_gate_blocks_default_admission() {
    let contract = stage63_vless_udp_over_tcp_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.vless_tcp_raw_true_dataplane_admitted);
    assert!(contract.vless_udp_over_tcp_admitted);
    assert!(contract.vless_protocol_partial_admitted);
    assert!(!contract.vless_protocol_true_dataplane_admitted);
    assert!(!contract.vless_tls_underlay_admitted);
    assert!(!contract.vless_reality_admitted);
    assert!(!contract.vless_xtls_vision_admitted);
    assert!(!contract.vless_shared_transport_admitted);
    assert!(!contract.vless_mux_admitted);
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
            "VLESS UDP-over-TCP data plane",
            "VLESS TLS, REALITY, and XTLS Vision",
            "VLESS shared transport and mux",
            "overall outbound/default admission"
        ]
    );
    assert_contains_text(&contract.carried_blockers, "VLESS TLS/REALITY");
    assert_contains_text(&contract.carried_blockers, "VMess");
    assert_contains_text(
        &contract.validation_commands,
        "stage63-vless-udp-over-tcp-dataplane-admission",
    );
}

#[test]
fn stage64_vless_mux_gate_matches_golden_fixture() {
    let fixture = load("product/daemon/stage64_vless_mux_dataplane_gate.json");
    let contract = stage64_vless_mux_gate_contract();

    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.stage_complete,
        fixture["stage_complete"].as_bool().unwrap()
    );
    assert_eq!(
        contract.vless_tcp_raw_true_dataplane_admitted,
        fixture["vless_tcp_raw_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.vless_udp_over_tcp_admitted,
        fixture["vless_udp_over_tcp_admitted"].as_bool().unwrap()
    );
    assert_eq!(
        contract.vless_mux_admitted,
        fixture["vless_mux_admitted"].as_bool().unwrap()
    );
    assert_eq!(
        contract.vless_protocol_partial_admitted,
        fixture["vless_protocol_partial_admitted"]
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
        contract.vless_tls_underlay_admitted,
        fixture["vless_tls_underlay_admitted"].as_bool().unwrap()
    );
    assert_eq!(
        contract.vless_reality_admitted,
        fixture["vless_reality_admitted"].as_bool().unwrap()
    );
    assert_eq!(
        contract.vless_xtls_vision_admitted,
        fixture["vless_xtls_vision_admitted"].as_bool().unwrap()
    );
    assert_eq!(
        contract.vless_shared_transport_admitted,
        fixture["vless_shared_transport_admitted"]
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
fn stage64_vless_mux_gate_blocks_default_admission() {
    let contract = stage64_vless_mux_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.vless_tcp_raw_true_dataplane_admitted);
    assert!(contract.vless_udp_over_tcp_admitted);
    assert!(contract.vless_mux_admitted);
    assert!(contract.vless_protocol_partial_admitted);
    assert!(!contract.vless_protocol_true_dataplane_admitted);
    assert!(!contract.vless_tls_underlay_admitted);
    assert!(!contract.vless_reality_admitted);
    assert!(!contract.vless_xtls_vision_admitted);
    assert!(!contract.vless_shared_transport_admitted);
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
            "VLESS mux data plane",
            "VLESS TLS, REALITY, and XTLS Vision",
            "VLESS shared transport and xHTTP xmux",
            "overall outbound/default admission"
        ]
    );
    assert_contains_text(&contract.carried_blockers, "VLESS TLS/REALITY");
    assert_contains_text(&contract.carried_blockers, "VMess");
    assert_contains_text(
        &contract.validation_commands,
        "stage64-vless-mux-dataplane-admission",
    );
}
