use super::*;

#[test]
fn stage74_vless_websocket_gate_matches_golden_fixture() {
    let fixture = load("product/daemon/stage74_vless_websocket_dataplane_gate.json");
    let contract = stage74_vless_websocket_gate_contract();

    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.stage_complete,
        fixture["stage_complete"].as_bool().unwrap()
    );
    assert_eq!(
        contract.vless_mux_admitted,
        fixture["vless_mux_admitted"].as_bool().unwrap()
    );
    assert_eq!(
        contract.vless_websocket_admitted,
        fixture["vless_websocket_admitted"].as_bool().unwrap()
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
        contract.vless_reality_underlay_admitted,
        fixture["vless_reality_underlay_admitted"]
            .as_bool()
            .unwrap()
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
fn stage74_vless_websocket_gate_blocks_default_admission() {
    let contract = stage74_vless_websocket_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.vless_tcp_raw_true_dataplane_admitted);
    assert!(contract.vless_udp_over_tcp_admitted);
    assert!(contract.vless_mux_admitted);
    assert!(contract.vless_websocket_admitted);
    assert!(contract.vless_shared_transport_partial_admitted);
    assert!(contract.vless_protocol_partial_admitted);
    assert!(!contract.vless_protocol_true_dataplane_admitted);
    assert!(!contract.vless_tls_underlay_admitted);
    assert!(!contract.vless_reality_underlay_admitted);
    assert!(!contract.vless_vision_admitted);
    assert!(!contract.vless_httpupgrade_admitted);
    assert!(!contract.vless_grpc_hunk_admitted);
    assert!(!contract.vless_meek_polling_admitted);
    assert!(!contract.vless_http_transport_put_admitted);
    assert!(!contract.vless_http_h2_full_admitted);
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
            "Prior VLESS raw and mux evidence",
            "VLESS WebSocket data plane",
            "VLESS TLS, WSS, REALITY, and Vision",
            "VLESS remaining shared transports and xHTTP",
            "Prior VMess shared transport evidence",
            "overall outbound/default admission"
        ]
    );
    assert_contains_text(&contract.carried_blockers, "VLESS WSS");
    assert_contains_text(&contract.carried_blockers, "xHTTP/xmux");
    assert_contains_text(
        &contract.validation_commands,
        "stage74-vless-websocket-dataplane-admission",
    );
}

#[test]
fn stage75_vless_httpupgrade_gate_matches_golden_fixture() {
    let fixture = load("product/daemon/stage75_vless_httpupgrade_dataplane_gate.json");
    let contract = stage75_vless_httpupgrade_gate_contract();

    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.stage_complete,
        fixture["stage_complete"].as_bool().unwrap()
    );
    assert_eq!(
        contract.vless_websocket_admitted,
        fixture["vless_websocket_admitted"].as_bool().unwrap()
    );
    assert_eq!(
        contract.vless_httpupgrade_admitted,
        fixture["vless_httpupgrade_admitted"].as_bool().unwrap()
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
        contract.vless_reality_underlay_admitted,
        fixture["vless_reality_underlay_admitted"]
            .as_bool()
            .unwrap()
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
fn stage75_vless_httpupgrade_gate_blocks_default_admission() {
    let contract = stage75_vless_httpupgrade_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.vless_tcp_raw_true_dataplane_admitted);
    assert!(contract.vless_udp_over_tcp_admitted);
    assert!(contract.vless_mux_admitted);
    assert!(contract.vless_websocket_admitted);
    assert!(contract.vless_httpupgrade_admitted);
    assert!(contract.vless_shared_transport_partial_admitted);
    assert!(contract.vless_protocol_partial_admitted);
    assert!(!contract.vless_protocol_true_dataplane_admitted);
    assert!(!contract.vless_tls_underlay_admitted);
    assert!(!contract.vless_reality_underlay_admitted);
    assert!(!contract.vless_vision_admitted);
    assert!(!contract.vless_grpc_hunk_admitted);
    assert!(!contract.vless_meek_polling_admitted);
    assert!(!contract.vless_http_transport_put_admitted);
    assert!(!contract.vless_http_h2_full_admitted);
    assert!(!contract.vless_xhttp_admitted);
    assert!(!contract.vless_xhttp_xmux_admitted);
    assert!(!contract.vless_shared_transport_admitted);
    assert!(contract.vmess_websocket_admitted);
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
            "Prior VLESS raw, mux, and WebSocket evidence",
            "VLESS HTTPUpgrade data plane",
            "VLESS HTTPS HTTPUpgrade, REALITY, and Vision",
            "VLESS remaining shared transports and xHTTP",
            "Prior VMess shared transport evidence",
            "overall outbound/default admission"
        ]
    );
    assert_contains_text(&contract.carried_blockers, "HTTPS HTTPUpgrade");
    assert_contains_text(&contract.carried_blockers, "xHTTP/xmux");
    assert_contains_text(
        &contract.validation_commands,
        "stage75-vless-httpupgrade-dataplane-admission",
    );
}

#[test]
fn stage76_vless_grpc_hunk_gate_matches_golden_fixture() {
    let fixture = load("product/daemon/stage76_vless_grpc_hunk_dataplane_gate.json");
    let contract = stage76_vless_grpc_hunk_gate_contract();

    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.stage_complete,
        fixture["stage_complete"].as_bool().unwrap()
    );
    assert_eq!(
        contract.vless_httpupgrade_admitted,
        fixture["vless_httpupgrade_admitted"].as_bool().unwrap()
    );
    assert_eq!(
        contract.vless_grpc_hunk_admitted,
        fixture["vless_grpc_hunk_admitted"].as_bool().unwrap()
    );
    assert_eq!(
        contract.vless_grpc_full_http2_admitted,
        fixture["vless_grpc_full_http2_admitted"].as_bool().unwrap()
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
        contract.vless_reality_underlay_admitted,
        fixture["vless_reality_underlay_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.vless_xhttp_xmux_admitted,
        fixture["vless_xhttp_xmux_admitted"].as_bool().unwrap()
    );
    assert_eq!(
        contract.vmess_grpc_hunk_admitted,
        fixture["vmess_grpc_hunk_admitted"].as_bool().unwrap()
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
fn stage76_vless_grpc_hunk_gate_blocks_default_admission() {
    let contract = stage76_vless_grpc_hunk_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.vless_tcp_raw_true_dataplane_admitted);
    assert!(contract.vless_udp_over_tcp_admitted);
    assert!(contract.vless_mux_admitted);
    assert!(contract.vless_websocket_admitted);
    assert!(contract.vless_httpupgrade_admitted);
    assert!(contract.vless_grpc_hunk_admitted);
    assert!(!contract.vless_grpc_full_http2_admitted);
    assert!(contract.vless_shared_transport_partial_admitted);
    assert!(contract.vless_protocol_partial_admitted);
    assert!(!contract.vless_protocol_true_dataplane_admitted);
    assert!(!contract.vless_tls_underlay_admitted);
    assert!(!contract.vless_reality_underlay_admitted);
    assert!(!contract.vless_vision_admitted);
    assert!(!contract.vless_meek_polling_admitted);
    assert!(!contract.vless_http_transport_put_admitted);
    assert!(!contract.vless_http_h2_full_admitted);
    assert!(!contract.vless_xhttp_admitted);
    assert!(!contract.vless_xhttp_xmux_admitted);
    assert!(!contract.vless_shared_transport_admitted);
    assert!(contract.vmess_grpc_hunk_admitted);
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
            "VLESS gRPC hunk data plane",
            "VLESS full gRPC HTTP/2",
            "VLESS TLS, REALITY, Vision, and remaining transports",
            "Prior VMess shared transport evidence",
            "overall outbound/default admission"
        ]
    );
    assert_contains_text(&contract.carried_blockers, "full gRPC HTTP2/TLS");
    assert_contains_text(&contract.carried_blockers, "xHTTP/xmux");
    assert_contains_text(
        &contract.validation_commands,
        "stage76-vless-grpc-hunk-dataplane-admission",
    );
}
