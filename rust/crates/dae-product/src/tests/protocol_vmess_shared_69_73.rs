use super::*;

#[test]
fn stage69_vmess_websocket_gate_matches_golden_fixture() {
    let fixture = load("product/daemon/stage69_vmess_websocket_dataplane_gate.json");
    let contract = stage69_vmess_websocket_gate_contract();

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
        contract.vmess_websocket_admitted,
        fixture["vmess_websocket_admitted"].as_bool().unwrap()
    );
    assert_eq!(
        contract.vmess_shared_transport_partial_admitted,
        fixture["vmess_shared_transport_partial_admitted"]
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
fn stage69_vmess_websocket_gate_blocks_default_admission() {
    let contract = stage69_vmess_websocket_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.vmess_aead_tcp_true_dataplane_admitted);
    assert!(contract.vmess_aead_udp_over_tcp_admitted);
    assert!(contract.vmess_udp_packet_addr_admitted);
    assert!(contract.vmess_mux_admitted);
    assert!(contract.vmess_websocket_admitted);
    assert!(contract.vmess_shared_transport_partial_admitted);
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
            "VMess WebSocket data plane",
            "VMess TLS and WSS",
            "VMess remaining shared transports",
            "overall outbound/default admission"
        ]
    );
    assert_contains_text(&contract.carried_blockers, "VMess WSS");
    assert_contains_text(&contract.carried_blockers, "SS2022");
    assert_contains_text(
        &contract.validation_commands,
        "stage69-vmess-websocket-dataplane-admission",
    );
}

#[test]
fn stage70_vmess_httpupgrade_gate_matches_golden_fixture() {
    let fixture = load("product/daemon/stage70_vmess_httpupgrade_dataplane_gate.json");
    let contract = stage70_vmess_httpupgrade_gate_contract();

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
        contract.vmess_websocket_admitted,
        fixture["vmess_websocket_admitted"].as_bool().unwrap()
    );
    assert_eq!(
        contract.vmess_httpupgrade_admitted,
        fixture["vmess_httpupgrade_admitted"].as_bool().unwrap()
    );
    assert_eq!(
        contract.vmess_shared_transport_partial_admitted,
        fixture["vmess_shared_transport_partial_admitted"]
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
fn stage70_vmess_httpupgrade_gate_blocks_default_admission() {
    let contract = stage70_vmess_httpupgrade_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.vmess_aead_tcp_true_dataplane_admitted);
    assert!(contract.vmess_aead_udp_over_tcp_admitted);
    assert!(contract.vmess_udp_packet_addr_admitted);
    assert!(contract.vmess_mux_admitted);
    assert!(contract.vmess_websocket_admitted);
    assert!(contract.vmess_httpupgrade_admitted);
    assert!(contract.vmess_shared_transport_partial_admitted);
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
            "Prior VMess AEAD and WebSocket evidence",
            "VMess HTTPUpgrade data plane",
            "VMess TLS and HTTPS HTTPUpgrade",
            "VMess remaining shared transports",
            "overall outbound/default admission"
        ]
    );
    assert_contains_text(&contract.carried_blockers, "VMess HTTPS HTTPUpgrade");
    assert_contains_text(&contract.carried_blockers, "SS2022");
    assert_contains_text(
        &contract.validation_commands,
        "stage70-vmess-httpupgrade-dataplane-admission",
    );
}

#[test]
fn stage71_vmess_grpc_hunk_gate_matches_golden_fixture() {
    let fixture = load("product/daemon/stage71_vmess_grpc_hunk_dataplane_gate.json");
    let contract = stage71_vmess_grpc_hunk_gate_contract();

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
        contract.vmess_websocket_admitted,
        fixture["vmess_websocket_admitted"].as_bool().unwrap()
    );
    assert_eq!(
        contract.vmess_httpupgrade_admitted,
        fixture["vmess_httpupgrade_admitted"].as_bool().unwrap()
    );
    assert_eq!(
        contract.vmess_grpc_hunk_admitted,
        fixture["vmess_grpc_hunk_admitted"].as_bool().unwrap()
    );
    assert_eq!(
        contract.vmess_grpc_full_http2_admitted,
        fixture["vmess_grpc_full_http2_admitted"].as_bool().unwrap()
    );
    assert_eq!(
        contract.vmess_shared_transport_partial_admitted,
        fixture["vmess_shared_transport_partial_admitted"]
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
fn stage71_vmess_grpc_hunk_gate_blocks_default_admission() {
    let contract = stage71_vmess_grpc_hunk_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.vmess_aead_tcp_true_dataplane_admitted);
    assert!(contract.vmess_aead_udp_over_tcp_admitted);
    assert!(contract.vmess_udp_packet_addr_admitted);
    assert!(contract.vmess_mux_admitted);
    assert!(contract.vmess_websocket_admitted);
    assert!(contract.vmess_httpupgrade_admitted);
    assert!(contract.vmess_grpc_hunk_admitted);
    assert!(!contract.vmess_grpc_full_http2_admitted);
    assert!(contract.vmess_shared_transport_partial_admitted);
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
            "Prior VMess shared transport evidence",
            "VMess gRPC hunk data plane",
            "VMess full gRPC HTTP/2",
            "VMess remaining shared transports",
            "overall outbound/default admission"
        ]
    );
    assert_contains_text(&contract.carried_blockers, "VMess full gRPC HTTP/2");
    assert_contains_text(&contract.carried_blockers, "SS2022");
    assert_contains_text(
        &contract.validation_commands,
        "stage71-vmess-grpc-hunk-dataplane-admission",
    );
}

#[test]
fn stage72_vmess_meek_polling_gate_matches_golden_fixture() {
    let fixture = load("product/daemon/stage72_vmess_meek_polling_dataplane_gate.json");
    let contract = stage72_vmess_meek_polling_gate_contract();

    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.stage_complete,
        fixture["stage_complete"].as_bool().unwrap()
    );
    assert_eq!(
        contract.vmess_grpc_hunk_admitted,
        fixture["vmess_grpc_hunk_admitted"].as_bool().unwrap()
    );
    assert_eq!(
        contract.vmess_meek_polling_admitted,
        fixture["vmess_meek_polling_admitted"].as_bool().unwrap()
    );
    assert_eq!(
        contract.vmess_meek_full_https_roundtripper_admitted,
        fixture["vmess_meek_full_https_roundtripper_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.vmess_shared_transport_partial_admitted,
        fixture["vmess_shared_transport_partial_admitted"]
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
fn stage72_vmess_meek_polling_gate_blocks_default_admission() {
    let contract = stage72_vmess_meek_polling_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.vmess_aead_tcp_true_dataplane_admitted);
    assert!(contract.vmess_aead_udp_over_tcp_admitted);
    assert!(contract.vmess_udp_packet_addr_admitted);
    assert!(contract.vmess_mux_admitted);
    assert!(contract.vmess_websocket_admitted);
    assert!(contract.vmess_httpupgrade_admitted);
    assert!(contract.vmess_grpc_hunk_admitted);
    assert!(!contract.vmess_grpc_full_http2_admitted);
    assert!(contract.vmess_meek_polling_admitted);
    assert!(!contract.vmess_meek_full_https_roundtripper_admitted);
    assert!(contract.vmess_shared_transport_partial_admitted);
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
            "Prior VMess shared transport evidence",
            "VMess Meek polling data plane",
            "VMess full Meek HTTPS lifecycle",
            "VMess remaining shared transports",
            "overall outbound/default admission"
        ]
    );
    assert_contains_text(&contract.carried_blockers, "VMess full Meek HTTPS");
    assert_contains_text(&contract.carried_blockers, "SS2022");
    assert_contains_text(
        &contract.validation_commands,
        "stage72-vmess-meek-polling-dataplane-admission",
    );
}

#[test]
fn stage73_vmess_http_transport_gate_matches_golden_fixture() {
    let fixture = load("product/daemon/stage73_vmess_http_transport_dataplane_gate.json");
    let contract = stage73_vmess_http_transport_gate_contract();

    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.stage_complete,
        fixture["stage_complete"].as_bool().unwrap()
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
        contract.vmess_http_h2_full_admitted,
        fixture["vmess_http_h2_full_admitted"].as_bool().unwrap()
    );
    assert_eq!(
        contract.vmess_shared_transport_partial_admitted,
        fixture["vmess_shared_transport_partial_admitted"]
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
fn stage73_vmess_http_transport_gate_blocks_default_admission() {
    let contract = stage73_vmess_http_transport_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.vmess_aead_tcp_true_dataplane_admitted);
    assert!(contract.vmess_aead_udp_over_tcp_admitted);
    assert!(contract.vmess_udp_packet_addr_admitted);
    assert!(contract.vmess_mux_admitted);
    assert!(contract.vmess_websocket_admitted);
    assert!(contract.vmess_httpupgrade_admitted);
    assert!(contract.vmess_grpc_hunk_admitted);
    assert!(!contract.vmess_grpc_full_http2_admitted);
    assert!(contract.vmess_meek_polling_admitted);
    assert!(!contract.vmess_meek_full_https_roundtripper_admitted);
    assert!(contract.vmess_http_transport_put_admitted);
    assert!(!contract.vmess_http_h2_full_admitted);
    assert!(contract.vmess_shared_transport_partial_admitted);
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
            "Prior VMess shared transport evidence",
            "VMess HTTP transport PUT data plane",
            "VMess full HTTP/H2 lifecycle",
            "VMess remaining shared transports",
            "overall outbound/default admission"
        ]
    );
    assert_contains_text(&contract.carried_blockers, "VMess full HTTP/2");
    assert_contains_text(&contract.carried_blockers, "SS2022");
    assert_contains_text(
        &contract.validation_commands,
        "stage73-vmess-http-transport-dataplane-admission",
    );
}
