use super::*;

#[test]
fn stage55_socks5_outbound_true_dataplane_gate_matches_golden_fixture() {
    let fixture = load("product/daemon/stage55_socks5_outbound_true_dataplane_gate.json");
    let contract = stage55_socks5_outbound_true_dataplane_gate_contract();

    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.stage_complete,
        fixture["stage_complete"].as_bool().unwrap()
    );
    assert_eq!(
        contract.socks5_tcp_true_dataplane_admitted,
        fixture["socks5_tcp_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.socks5_udp_associate_admitted,
        fixture["socks5_udp_associate_admitted"].as_bool().unwrap()
    );
    assert_eq!(
        contract.protocol_outbound_partial_admitted,
        fixture["protocol_outbound_partial_admitted"]
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
        contract.matched_go_rust_default_daemon_benchmark_recorded,
        fixture["matched_go_rust_default_daemon_benchmark_recorded"]
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
fn stage55_socks5_outbound_true_dataplane_gate_blocks_default_admission() {
    let contract = stage55_socks5_outbound_true_dataplane_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.socks5_tcp_true_dataplane_admitted);
    assert!(contract.protocol_outbound_partial_admitted);
    assert!(!contract.socks5_udp_associate_admitted);
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
            "SOCKS5 TCP CONNECT protocol data plane",
            "MagicNetwork underlay socket evidence",
            "SOCKS5 UDP associate",
            "overall outbound/default admission"
        ]
    );
    assert_contains_text(&contract.carried_blockers, "SOCKS5 UDP associate");
    assert_contains_text(&contract.carried_blockers, "matched Go default daemon");
    assert_contains_text(
        &contract.validation_commands,
        "stage55-socks5-outbound-true-dataplane-admission",
    );
}

#[test]
fn stage56_socks5_udp_associate_gate_matches_golden_fixture() {
    let fixture = load("product/daemon/stage56_socks5_udp_associate_dataplane_gate.json");
    let contract = stage56_socks5_udp_associate_gate_contract();

    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.stage_complete,
        fixture["stage_complete"].as_bool().unwrap()
    );
    assert_eq!(
        contract.socks5_tcp_true_dataplane_admitted,
        fixture["socks5_tcp_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.socks5_udp_associate_admitted,
        fixture["socks5_udp_associate_admitted"].as_bool().unwrap()
    );
    assert_eq!(
        contract.socks5_protocol_true_dataplane_admitted,
        fixture["socks5_protocol_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.protocol_outbound_partial_admitted,
        fixture["protocol_outbound_partial_admitted"]
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
        contract.matched_go_rust_default_daemon_benchmark_recorded,
        fixture["matched_go_rust_default_daemon_benchmark_recorded"]
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
fn stage56_socks5_udp_associate_gate_blocks_default_admission() {
    let contract = stage56_socks5_udp_associate_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.socks5_tcp_true_dataplane_admitted);
    assert!(contract.socks5_udp_associate_admitted);
    assert!(contract.socks5_protocol_true_dataplane_admitted);
    assert!(contract.protocol_outbound_partial_admitted);
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
            "SOCKS5 TCP CONNECT carried evidence",
            "SOCKS5 UDP ASSOCIATE control connection",
            "SOCKS5 UDP PacketConn semantics",
            "overall outbound/default admission"
        ]
    );
    assert_contains_text(&contract.carried_blockers, "HTTP/HTTPS");
    assert_contains_text(&contract.carried_blockers, "matched Go default daemon");
    assert_contains_text(
        &contract.validation_commands,
        "stage56-socks5-udp-associate-dataplane-admission",
    );
}

#[test]
fn stage57_http_connect_gate_matches_golden_fixture() {
    let fixture = load("product/daemon/stage57_http_connect_dataplane_gate.json");
    let contract = stage57_http_connect_gate_contract();

    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.stage_complete,
        fixture["stage_complete"].as_bool().unwrap()
    );
    assert_eq!(
        contract.socks5_protocol_true_dataplane_admitted,
        fixture["socks5_protocol_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.http_connect_true_dataplane_admitted,
        fixture["http_connect_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.https_proxy_tls_underlay_admitted,
        fixture["https_proxy_tls_underlay_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.http_proxy_protocol_partial_admitted,
        fixture["http_proxy_protocol_partial_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.protocol_outbound_partial_admitted,
        fixture["protocol_outbound_partial_admitted"]
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
        contract.matched_go_rust_default_daemon_benchmark_recorded,
        fixture["matched_go_rust_default_daemon_benchmark_recorded"]
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
fn stage57_http_connect_gate_blocks_default_admission() {
    let contract = stage57_http_connect_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.socks5_protocol_true_dataplane_admitted);
    assert!(contract.http_connect_true_dataplane_admitted);
    assert!(!contract.https_proxy_tls_underlay_admitted);
    assert!(contract.http_proxy_protocol_partial_admitted);
    assert!(contract.protocol_outbound_partial_admitted);
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
            "HTTP CONNECT protocol data plane",
            "MagicNetwork TCP underlay evidence",
            "HTTPS proxy TLS underlay",
            "overall outbound/default admission"
        ]
    );
    assert_contains_text(&contract.carried_blockers, "HTTPS proxy shared TLS");
    assert_contains_text(&contract.carried_blockers, "matched Go default daemon");
    assert_contains_text(
        &contract.validation_commands,
        "stage57-http-connect-dataplane-admission",
    );
}

#[test]
fn stage58_shadowsocks_aead_tcp_gate_matches_golden_fixture() {
    let fixture = load("product/daemon/stage58_shadowsocks_aead_tcp_dataplane_gate.json");
    let contract = stage58_shadowsocks_aead_tcp_gate_contract();

    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.stage_complete,
        fixture["stage_complete"].as_bool().unwrap()
    );
    assert_eq!(
        contract.socks5_protocol_true_dataplane_admitted,
        fixture["socks5_protocol_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.http_connect_true_dataplane_admitted,
        fixture["http_connect_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.shadowsocks_aead_tcp_true_dataplane_admitted,
        fixture["shadowsocks_aead_tcp_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.shadowsocks_protocol_partial_admitted,
        fixture["shadowsocks_protocol_partial_admitted"]
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
        contract.ss2022_true_dataplane_admitted,
        fixture["ss2022_true_dataplane_admitted"].as_bool().unwrap()
    );
    assert_eq!(
        contract.shadowsocks_udp_true_dataplane_admitted,
        fixture["shadowsocks_udp_true_dataplane_admitted"]
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
        contract.shadowsocksr_true_dataplane_admitted,
        fixture["shadowsocksr_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.protocol_outbound_partial_admitted,
        fixture["protocol_outbound_partial_admitted"]
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
fn stage58_shadowsocks_aead_tcp_gate_blocks_default_admission() {
    let contract = stage58_shadowsocks_aead_tcp_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.socks5_protocol_true_dataplane_admitted);
    assert!(contract.http_connect_true_dataplane_admitted);
    assert!(contract.shadowsocks_aead_tcp_true_dataplane_admitted);
    assert!(contract.shadowsocks_protocol_partial_admitted);
    assert!(!contract.shadowsocks_protocol_true_dataplane_admitted);
    assert!(!contract.ss2022_true_dataplane_admitted);
    assert!(!contract.shadowsocks_udp_true_dataplane_admitted);
    assert!(!contract.sip003_plugin_transport_admitted);
    assert!(!contract.shadowsocksr_true_dataplane_admitted);
    assert!(contract.protocol_outbound_partial_admitted);
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
            "Shadowsocks AEAD TCP protocol data plane",
            "MagicNetwork TCP underlay evidence",
            "SS2022 and Shadowsocks UDP",
            "SIP003 plugin and ShadowsocksR",
            "overall outbound/default admission"
        ]
    );
    assert_contains_text(&contract.carried_blockers, "SS2022 TCP/UDP");
    assert_contains_text(&contract.carried_blockers, "matched Go default daemon");
    assert_contains_text(
        &contract.validation_commands,
        "stage58-shadowsocks-aead-tcp-dataplane-admission",
    );
}

#[test]
fn stage59_shadowsocks_aead_udp_gate_matches_golden_fixture() {
    let fixture = load("product/daemon/stage59_shadowsocks_aead_udp_dataplane_gate.json");
    let contract = stage59_shadowsocks_aead_udp_gate_contract();

    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.stage_complete,
        fixture["stage_complete"].as_bool().unwrap()
    );
    assert_eq!(
        contract.shadowsocks_aead_tcp_true_dataplane_admitted,
        fixture["shadowsocks_aead_tcp_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.shadowsocks_aead_udp_true_dataplane_admitted,
        fixture["shadowsocks_aead_udp_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.shadowsocks_aead_protocol_true_dataplane_admitted,
        fixture["shadowsocks_aead_protocol_true_dataplane_admitted"]
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
        contract.ss2022_true_dataplane_admitted,
        fixture["ss2022_true_dataplane_admitted"].as_bool().unwrap()
    );
    assert_eq!(
        contract.sip003_plugin_transport_admitted,
        fixture["sip003_plugin_transport_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.shadowsocksr_true_dataplane_admitted,
        fixture["shadowsocksr_true_dataplane_admitted"]
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
fn stage59_shadowsocks_aead_udp_gate_blocks_default_admission() {
    let contract = stage59_shadowsocks_aead_udp_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.shadowsocks_aead_tcp_true_dataplane_admitted);
    assert!(contract.shadowsocks_aead_udp_true_dataplane_admitted);
    assert!(contract.shadowsocks_aead_protocol_true_dataplane_admitted);
    assert!(contract.shadowsocks_protocol_partial_admitted);
    assert!(!contract.shadowsocks_protocol_true_dataplane_admitted);
    assert!(!contract.ss2022_true_dataplane_admitted);
    assert!(!contract.sip003_plugin_transport_admitted);
    assert!(!contract.shadowsocksr_true_dataplane_admitted);
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
            "Shadowsocks AEAD TCP carried evidence",
            "Shadowsocks AEAD UDP PacketConn data plane",
            "UDP underlay evidence",
            "SS2022, SIP003, and ShadowsocksR",
            "overall outbound/default admission"
        ]
    );
    assert_contains_text(&contract.carried_blockers, "SS2022 TCP/UDP");
    assert_contains_text(&contract.carried_blockers, "matched Go default daemon");
    assert_contains_text(
        &contract.validation_commands,
        "stage59-shadowsocks-aead-udp-dataplane-admission",
    );
}
