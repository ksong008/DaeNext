use super::*;

#[test]
fn stage77_vless_meek_polling_gate_matches_golden_fixture() {
    let fixture = load("product/daemon/stage77_vless_meek_polling_dataplane_gate.json");
    let contract = stage77_vless_meek_polling_gate_contract();

    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.stage_complete,
        fixture["stage_complete"].as_bool().unwrap()
    );
    assert_eq!(
        contract.vless_grpc_hunk_admitted,
        fixture["vless_grpc_hunk_admitted"].as_bool().unwrap()
    );
    assert_eq!(
        contract.vless_meek_polling_admitted,
        fixture["vless_meek_polling_admitted"].as_bool().unwrap()
    );
    assert_eq!(
        contract.vless_meek_full_https_roundtripper_admitted,
        fixture["vless_meek_full_https_roundtripper_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.vless_shared_transport_partial_admitted,
        fixture["vless_shared_transport_partial_admitted"]
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
        contract.vless_xhttp_xmux_admitted,
        fixture["vless_xhttp_xmux_admitted"].as_bool().unwrap()
    );
    assert_eq!(
        contract.vmess_meek_polling_admitted,
        fixture["vmess_meek_polling_admitted"].as_bool().unwrap()
    );
    assert_eq!(
        contract.vmess_http_transport_put_admitted,
        fixture["vmess_http_transport_put_admitted"]
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
fn stage77_vless_meek_polling_gate_blocks_default_admission() {
    let contract = stage77_vless_meek_polling_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.vless_websocket_admitted);
    assert!(contract.vless_httpupgrade_admitted);
    assert!(contract.vless_grpc_hunk_admitted);
    assert!(contract.vless_meek_polling_admitted);
    assert!(!contract.vless_meek_full_https_roundtripper_admitted);
    assert!(contract.vless_shared_transport_partial_admitted);
    assert!(contract.vless_protocol_partial_admitted);
    assert!(!contract.vless_protocol_true_dataplane_admitted);
    assert!(!contract.vless_tls_underlay_admitted);
    assert!(!contract.vless_reality_underlay_admitted);
    assert!(!contract.vless_vision_admitted);
    assert!(!contract.vless_http_transport_put_admitted);
    assert!(!contract.vless_http_h2_full_admitted);
    assert!(!contract.vless_xhttp_admitted);
    assert!(!contract.vless_xhttp_xmux_admitted);
    assert!(!contract.vless_shared_transport_admitted);
    assert!(contract.vmess_meek_polling_admitted);
    assert!(contract.vmess_http_transport_put_admitted);
    assert!(contract.vmess_shared_transport_partial_admitted);
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
            "Prior VLESS shared transport evidence",
            "VLESS Meek polling data plane",
            "VLESS full Meek HTTPS lifecycle",
            "VLESS TLS, REALITY, Vision, and remaining transports",
            "Prior VMess shared transport evidence",
            "overall outbound/default admission"
        ]
    );
    assert_contains_text(&contract.carried_blockers, "full Meek HTTPS");
    assert_contains_text(&contract.carried_blockers, "xHTTP/xmux");
    assert_contains_text(
        &contract.validation_commands,
        "stage77-vless-meek-polling-dataplane-admission",
    );
}

#[test]
fn stage78_vless_http_transport_gate_matches_golden_fixture() {
    let fixture = load("product/daemon/stage78_vless_http_transport_dataplane_gate.json");
    let contract = stage78_vless_http_transport_gate_contract();

    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.stage_complete,
        fixture["stage_complete"].as_bool().unwrap()
    );
    assert_eq!(
        contract.vless_meek_polling_admitted,
        fixture["vless_meek_polling_admitted"].as_bool().unwrap()
    );
    assert_eq!(
        contract.vless_http_transport_put_admitted,
        fixture["vless_http_transport_put_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.vless_http_h2_full_admitted,
        fixture["vless_http_h2_full_admitted"].as_bool().unwrap()
    );
    assert_eq!(
        contract.vless_shared_transport_partial_admitted,
        fixture["vless_shared_transport_partial_admitted"]
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
        contract.vless_xhttp_xmux_admitted,
        fixture["vless_xhttp_xmux_admitted"].as_bool().unwrap()
    );
    assert_eq!(
        contract.vmess_http_transport_put_admitted,
        fixture["vmess_http_transport_put_admitted"]
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
fn stage78_vless_http_transport_gate_blocks_default_admission() {
    let contract = stage78_vless_http_transport_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.vless_websocket_admitted);
    assert!(contract.vless_httpupgrade_admitted);
    assert!(contract.vless_grpc_hunk_admitted);
    assert!(contract.vless_meek_polling_admitted);
    assert!(contract.vless_http_transport_put_admitted);
    assert!(!contract.vless_http_h2_full_admitted);
    assert!(contract.vless_shared_transport_partial_admitted);
    assert!(contract.vless_protocol_partial_admitted);
    assert!(!contract.vless_protocol_true_dataplane_admitted);
    assert!(!contract.vless_tls_underlay_admitted);
    assert!(!contract.vless_reality_underlay_admitted);
    assert!(!contract.vless_vision_admitted);
    assert!(!contract.vless_xhttp_admitted);
    assert!(!contract.vless_xhttp_xmux_admitted);
    assert!(!contract.vless_shared_transport_admitted);
    assert!(contract.vmess_http_transport_put_admitted);
    assert!(contract.vmess_shared_transport_partial_admitted);
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
            "Prior VLESS shared transport evidence",
            "VLESS HTTP transport PUT data plane",
            "VLESS full HTTP/H2 lifecycle",
            "VLESS TLS, REALITY, Vision, and remaining transports",
            "Prior VMess shared transport evidence",
            "overall outbound/default admission"
        ]
    );
    assert_contains_text(&contract.carried_blockers, "full HTTP/H2");
    assert_contains_text(&contract.carried_blockers, "xHTTP/xmux");
    assert_contains_text(
        &contract.validation_commands,
        "stage78-vless-http-transport-dataplane-admission",
    );
}

#[test]
fn stage79_vless_xhttp_packet_gate_matches_golden_fixture() {
    let fixture = load("product/daemon/stage79_vless_xhttp_packet_dataplane_gate.json");
    let contract = stage79_vless_xhttp_packet_gate_contract();

    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.stage_complete,
        fixture["stage_complete"].as_bool().unwrap()
    );
    assert_eq!(
        contract.vless_http_transport_put_admitted,
        fixture["vless_http_transport_put_admitted"]
            .as_bool()
            .unwrap()
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
fn stage79_vless_xhttp_packet_gate_blocks_default_admission() {
    let contract = stage79_vless_xhttp_packet_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.vless_websocket_admitted);
    assert!(contract.vless_httpupgrade_admitted);
    assert!(contract.vless_grpc_hunk_admitted);
    assert!(contract.vless_meek_polling_admitted);
    assert!(contract.vless_http_transport_put_admitted);
    assert!(!contract.vless_http_h2_full_admitted);
    assert!(contract.vless_xhttp_admitted);
    assert!(!contract.vless_xhttp_xmux_admitted);
    assert!(contract.vless_shared_transport_partial_admitted);
    assert!(contract.vless_protocol_partial_admitted);
    assert!(!contract.vless_protocol_true_dataplane_admitted);
    assert!(!contract.vless_tls_underlay_admitted);
    assert!(!contract.vless_reality_underlay_admitted);
    assert!(!contract.vless_vision_admitted);
    assert!(!contract.vless_shared_transport_admitted);
    assert!(contract.vmess_http_transport_put_admitted);
    assert!(contract.vmess_shared_transport_partial_admitted);
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
            "Prior VLESS shared transport evidence",
            "VLESS xHTTP packet-up data plane",
            "VLESS xHTTP xmux and full lifecycle",
            "VLESS TLS, REALITY, Vision, and remaining transports",
            "Prior VMess shared transport evidence",
            "overall outbound/default admission"
        ]
    );
    assert_contains_text(&contract.carried_blockers, "xmux pool");
    assert_contains_text(&contract.carried_blockers, "downloadSettings");
    assert_contains_text(
        &contract.validation_commands,
        "stage79-vless-xhttp-packet-dataplane-admission",
    );
}
