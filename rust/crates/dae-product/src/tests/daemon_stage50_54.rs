use super::*;

#[test]
fn stage50_active_tcp_ingress_gate_contract_matches_golden_fixture() {
    let fixture = load("product/daemon/stage50_active_tcp_ingress_gate.json");
    let contract = stage50_active_tcp_ingress_gate_contract();
    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.stage_complete,
        fixture["stage_complete"].as_bool().unwrap()
    );
    assert_eq!(
        contract.active_tcp_tproxy_ingress_recorded,
        fixture["active_tcp_tproxy_ingress_recorded"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.active_tcp_syn_reached_transparent_listener_recorded,
        fixture["active_tcp_syn_reached_transparent_listener_recorded"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.original_destination_recorded,
        fixture["original_destination_recorded"].as_bool().unwrap()
    );
    assert_eq!(
        contract.tcp_reply_path_recorded,
        fixture["tcp_reply_path_recorded"].as_bool().unwrap()
    );
    assert_eq!(
        contract.route_dial_tcp_rust_control_plane_recorded,
        fixture["route_dial_tcp_rust_control_plane_recorded"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.outbound_relay_recorded,
        fixture["outbound_relay_recorded"].as_bool().unwrap()
    );
    assert_eq!(
        contract.so_mark_mptcp_real_outbound_socket_recorded,
        fixture["so_mark_mptcp_real_outbound_socket_recorded"]
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
fn stage50_active_tcp_ingress_gate_blocks_default_admission() {
    let contract = stage50_active_tcp_ingress_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.active_tcp_tproxy_ingress_recorded);
    assert!(contract.active_tcp_syn_reached_transparent_listener_recorded);
    assert!(contract.original_destination_recorded);
    assert!(contract.tcp_reply_path_recorded);
    assert!(!contract.route_dial_tcp_rust_control_plane_recorded);
    assert!(!contract.outbound_relay_recorded);
    assert!(!contract.so_mark_mptcp_real_outbound_socket_recorded);
    assert!(!contract.active_udp_tproxy_admitted);
    assert!(!contract.active_dns_tproxy_admitted);
    assert!(!contract.outbound_true_dataplane_admitted);
    assert!(!contract.default_switch_allowed);
    assert!(!contract.product_chain_switch_allowed);
    assert!(!contract.true_rust_default_daemon_admitted);
    assert!(contract.go_default_path_preserved);
    assert!(contract.go_fallback_required);

    assert_contains_text(
        &contract.carried_blockers,
        "RouteDialTcp Rust control-plane",
    );
    assert_contains_text(&contract.carried_blockers, "SO_MARK and MPTCP");
    assert_contains_text(&contract.carried_blockers, "matched Go default daemon");
}

#[test]
fn stage50_active_tcp_ingress_gate_covers_rows() {
    let contract = stage50_active_tcp_ingress_gate_contract();
    let areas = contract.rows.iter().map(|row| row.area).collect::<Vec<_>>();
    assert_eq!(
        areas,
        vec![
            "LAN ingress to transparent TCP listener",
            "original destination and reply smoke"
        ]
    );
    assert_contains_text(&contract.source, "runtime_stage50_tcp_gate.rs");
    assert_contains_text(&contract.source, "runtime_maps.rs");
    assert_contains_text(
        &contract.validation_commands,
        "stage50-active-tcp-tproxy-ingress-admission",
    );
}

#[test]
fn stage51_active_tcp_relay_gate_contract_matches_golden_fixture() {
    let fixture = load("product/daemon/stage51_active_tcp_relay_gate.json");
    let contract = stage51_active_tcp_relay_gate_contract();
    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.stage_complete,
        fixture["stage_complete"].as_bool().unwrap()
    );
    assert_eq!(
        contract.active_tcp_tproxy_ingress_recorded,
        fixture["active_tcp_tproxy_ingress_recorded"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.original_destination_recorded,
        fixture["original_destination_recorded"].as_bool().unwrap()
    );
    assert_eq!(
        contract.route_dial_tcp_direct_path_recorded,
        fixture["route_dial_tcp_direct_path_recorded"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.route_dial_tcp_rust_control_plane_recorded,
        fixture["route_dial_tcp_rust_control_plane_recorded"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.outbound_relay_recorded,
        fixture["outbound_relay_recorded"].as_bool().unwrap()
    );
    assert_eq!(
        contract.so_mark_mptcp_real_outbound_socket_recorded,
        fixture["so_mark_mptcp_real_outbound_socket_recorded"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.active_tcp_relay_benchmark_recorded,
        fixture["active_tcp_relay_benchmark_recorded"]
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
fn stage51_active_tcp_relay_gate_blocks_default_admission() {
    let contract = stage51_active_tcp_relay_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.active_tcp_tproxy_ingress_recorded);
    assert!(contract.original_destination_recorded);
    assert!(contract.route_dial_tcp_direct_path_recorded);
    assert!(!contract.route_dial_tcp_rust_control_plane_recorded);
    assert!(contract.outbound_relay_recorded);
    assert!(contract.so_mark_mptcp_real_outbound_socket_recorded);
    assert!(contract.active_tcp_relay_benchmark_recorded);
    assert!(!contract.active_udp_tproxy_admitted);
    assert!(!contract.active_dns_tproxy_admitted);
    assert!(!contract.outbound_true_dataplane_admitted);
    assert!(!contract.default_switch_allowed);
    assert!(!contract.product_chain_switch_allowed);
    assert!(!contract.true_rust_default_daemon_admitted);
    assert!(contract.go_default_path_preserved);
    assert!(contract.go_fallback_required);

    assert_contains_text(&contract.carried_blockers, "Full RouteDialTcp");
    assert_contains_text(&contract.carried_blockers, "active UDP");
    assert_contains_text(&contract.carried_blockers, "matched Go default daemon");
}

#[test]
fn stage51_active_tcp_relay_gate_covers_rows() {
    let contract = stage51_active_tcp_relay_gate_contract();
    let areas = contract.rows.iter().map(|row| row.area).collect::<Vec<_>>();
    assert_eq!(
        areas,
        vec![
            "transparent accept to Rust direct outbound relay",
            "SO_MARK and MPTCP outbound socket",
            "active TCP relay benchmark"
        ]
    );
    assert_contains_text(&contract.source, "runtime_stage50_tcp_gate.rs");
    assert_contains_text(&contract.source, "tcp_direct.rs");
    assert_contains_text(
        &contract.validation_commands,
        "stage51-active-tcp-route-dial-relay-admission",
    );
}

#[test]
fn stage52_active_tcp_route_table_group_gate_contract_matches_golden_fixture() {
    let fixture = load("product/daemon/stage52_active_tcp_route_table_group_gate.json");
    let contract = stage52_active_tcp_route_table_group_gate_contract();
    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.stage_complete,
        fixture["stage_complete"].as_bool().unwrap()
    );
    assert_eq!(
        contract.active_tcp_tproxy_ingress_recorded,
        fixture["active_tcp_tproxy_ingress_recorded"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.original_destination_recorded,
        fixture["original_destination_recorded"].as_bool().unwrap()
    );
    assert_eq!(
        contract.route_dial_tcp_route_table_recorded,
        fixture["route_dial_tcp_route_table_recorded"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.choose_dial_target_recorded,
        fixture["choose_dial_target_recorded"].as_bool().unwrap()
    );
    assert_eq!(
        contract.outbound_group_selection_recorded,
        fixture["outbound_group_selection_recorded"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.route_dial_tcp_rust_control_plane_recorded,
        fixture["route_dial_tcp_rust_control_plane_recorded"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.outbound_relay_recorded,
        fixture["outbound_relay_recorded"].as_bool().unwrap()
    );
    assert_eq!(
        contract.so_mark_mptcp_real_outbound_socket_recorded,
        fixture["so_mark_mptcp_real_outbound_socket_recorded"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.active_tcp_route_table_group_benchmark_recorded,
        fixture["active_tcp_route_table_group_benchmark_recorded"]
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
fn stage52_active_tcp_route_table_group_gate_blocks_default_admission() {
    let contract = stage52_active_tcp_route_table_group_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.active_tcp_tproxy_ingress_recorded);
    assert!(contract.original_destination_recorded);
    assert!(contract.route_dial_tcp_route_table_recorded);
    assert!(contract.choose_dial_target_recorded);
    assert!(contract.outbound_group_selection_recorded);
    assert!(contract.route_dial_tcp_rust_control_plane_recorded);
    assert!(contract.outbound_relay_recorded);
    assert!(contract.so_mark_mptcp_real_outbound_socket_recorded);
    assert!(contract.active_tcp_route_table_group_benchmark_recorded);
    assert!(!contract.active_udp_tproxy_admitted);
    assert!(!contract.active_dns_tproxy_admitted);
    assert!(!contract.outbound_true_dataplane_admitted);
    assert!(!contract.default_switch_allowed);
    assert!(!contract.product_chain_switch_allowed);
    assert!(!contract.true_rust_default_daemon_admitted);
    assert!(contract.go_default_path_preserved);
    assert!(contract.go_fallback_required);

    assert_contains_text(&contract.carried_blockers, "active UDP");
    assert_contains_text(&contract.carried_blockers, "bounded direct loopback");
    assert_contains_text(&contract.carried_blockers, "matched Go default daemon");
}

#[test]
fn stage52_active_tcp_route_table_group_gate_covers_rows() {
    let contract = stage52_active_tcp_route_table_group_gate_contract();
    let areas = contract.rows.iter().map(|row| row.area).collect::<Vec<_>>();
    assert_eq!(
        areas,
        vec![
            "RouteDialTcp userspace reroute",
            "outbound group min selection",
            "route-aware active TCP relay benchmark"
        ]
    );
    assert_contains_text(&contract.source, "runtime_stage50_tcp_gate.rs");
    assert_contains_text(&contract.source, "tcp_route_dial.rs");
    assert_contains_text(
        &contract.validation_commands,
        "stage52-active-tcp-route-table-group-relay-admission",
    );
}

#[test]
fn stage53_active_udp_tproxy_endpoint_gate_contract_matches_golden_fixture() {
    let fixture = load("product/daemon/stage53_active_udp_tproxy_endpoint_gate.json");
    let contract = stage53_active_udp_tproxy_endpoint_gate_contract();
    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.stage_complete,
        fixture["stage_complete"].as_bool().unwrap()
    );
    assert_eq!(
        contract.active_tcp_tproxy_ingress_recorded,
        fixture["active_tcp_tproxy_ingress_recorded"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.original_destination_recorded,
        fixture["original_destination_recorded"].as_bool().unwrap()
    );
    assert_eq!(
        contract.route_dial_tcp_route_table_recorded,
        fixture["route_dial_tcp_route_table_recorded"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.choose_dial_target_recorded,
        fixture["choose_dial_target_recorded"].as_bool().unwrap()
    );
    assert_eq!(
        contract.outbound_group_selection_recorded,
        fixture["outbound_group_selection_recorded"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.route_dial_tcp_rust_control_plane_recorded,
        fixture["route_dial_tcp_rust_control_plane_recorded"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.outbound_relay_recorded,
        fixture["outbound_relay_recorded"].as_bool().unwrap()
    );
    assert_eq!(
        contract.so_mark_mptcp_real_outbound_socket_recorded,
        fixture["so_mark_mptcp_real_outbound_socket_recorded"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.active_tcp_route_table_group_benchmark_recorded,
        fixture["active_tcp_route_table_group_benchmark_recorded"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.active_udp_tproxy_admitted,
        fixture["active_udp_tproxy_admitted"].as_bool().unwrap()
    );
    assert_eq!(
        contract.active_udp_original_destination_recorded,
        fixture["active_udp_original_destination_recorded"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.udp_endpoint_pool_live_recorded,
        fixture["udp_endpoint_pool_live_recorded"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.udp_packetconn_write_read_recorded,
        fixture["udp_packetconn_write_read_recorded"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.udp_sendpkt_reply_recorded,
        fixture["udp_sendpkt_reply_recorded"].as_bool().unwrap()
    );
    assert_eq!(
        contract.udp_so_mark_real_outbound_socket_recorded,
        fixture["udp_so_mark_real_outbound_socket_recorded"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.active_udp_tproxy_benchmark_recorded,
        fixture["active_udp_tproxy_benchmark_recorded"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.active_dns_tproxy_admitted,
        fixture["active_dns_tproxy_admitted"].as_bool().unwrap()
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
fn stage53_active_udp_tproxy_endpoint_gate_blocks_default_admission() {
    let contract = stage53_active_udp_tproxy_endpoint_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.active_tcp_tproxy_ingress_recorded);
    assert!(contract.original_destination_recorded);
    assert!(contract.route_dial_tcp_route_table_recorded);
    assert!(contract.choose_dial_target_recorded);
    assert!(contract.outbound_group_selection_recorded);
    assert!(contract.route_dial_tcp_rust_control_plane_recorded);
    assert!(contract.outbound_relay_recorded);
    assert!(contract.so_mark_mptcp_real_outbound_socket_recorded);
    assert!(contract.active_tcp_route_table_group_benchmark_recorded);
    assert!(contract.active_udp_tproxy_admitted);
    assert!(contract.active_udp_original_destination_recorded);
    assert!(contract.udp_endpoint_pool_live_recorded);
    assert!(contract.udp_packetconn_write_read_recorded);
    assert!(contract.udp_sendpkt_reply_recorded);
    assert!(contract.udp_so_mark_real_outbound_socket_recorded);
    assert!(contract.active_udp_tproxy_benchmark_recorded);
    assert!(!contract.active_dns_tproxy_admitted);
    assert!(!contract.outbound_true_dataplane_admitted);
    assert!(!contract.default_switch_allowed);
    assert!(!contract.product_chain_switch_allowed);
    assert!(!contract.true_rust_default_daemon_admitted);
    assert!(contract.go_default_path_preserved);
    assert!(contract.go_fallback_required);

    assert_contains_text(&contract.carried_blockers, "active DNS UDP/53");
    assert_contains_text(&contract.carried_blockers, "protocol true dataplane");
    assert_contains_text(&contract.carried_blockers, "matched Go default daemon");
}

#[test]
fn stage53_active_udp_tproxy_endpoint_gate_covers_rows() {
    let contract = stage53_active_udp_tproxy_endpoint_gate_contract();
    let areas = contract.rows.iter().map(|row| row.area).collect::<Vec<_>>();
    assert_eq!(
        areas,
        vec![
            "active UDP transparent receive",
            "UDP endpoint pool full-cone key",
            "UDP PacketConn outbound socket",
            "sendPkt-style reply and benchmark"
        ]
    );
    assert_contains_text(&contract.source, "runtime_stage50_tcp_gate.rs");
    assert_contains_text(&contract.source, "udp_direct.rs");
    assert_contains_text(&contract.source, "tproxy_listener.rs");
    assert_contains_text(
        &contract.validation_commands,
        "stage53-active-udp-tproxy-endpoint-admission",
    );
}

#[test]
fn stage54_active_dns_tproxy_cache_gate_contract_matches_golden_fixture() {
    let fixture = load("product/daemon/stage54_active_dns_tproxy_cache_gate.json");
    let contract = stage54_active_dns_tproxy_cache_gate_contract();
    assert_eq!(contract.name, fixture["name"].as_str().unwrap());
    assert_eq!(contract.stage, fixture["stage"].as_str().unwrap());
    assert_eq!(contract.prior_gate, fixture["prior_gate"].as_str().unwrap());
    assert_eq!(
        contract.stage_complete,
        fixture["stage_complete"].as_bool().unwrap()
    );
    assert_eq!(
        contract.active_udp_tproxy_admitted,
        fixture["active_udp_tproxy_admitted"].as_bool().unwrap()
    );
    assert_eq!(
        contract.active_dns_tproxy_admitted,
        fixture["active_dns_tproxy_admitted"].as_bool().unwrap()
    );
    assert_eq!(
        contract.active_dns_original_destination_recorded,
        fixture["active_dns_original_destination_recorded"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.dns_controller_path_recorded,
        fixture["dns_controller_path_recorded"].as_bool().unwrap()
    );
    assert_eq!(
        contract.dns_upstream_query_recorded,
        fixture["dns_upstream_query_recorded"].as_bool().unwrap()
    );
    assert_eq!(
        contract.dns_response_validation_recorded,
        fixture["dns_response_validation_recorded"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.dns_cache_restore_recorded,
        fixture["dns_cache_restore_recorded"].as_bool().unwrap()
    );
    assert_eq!(
        contract.domain_routing_owner_migration_recorded,
        fixture["domain_routing_owner_migration_recorded"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.dns_sendpkt_reply_recorded,
        fixture["dns_sendpkt_reply_recorded"].as_bool().unwrap()
    );
    assert_eq!(
        contract.dns_so_mark_upstream_socket_recorded,
        fixture["dns_so_mark_upstream_socket_recorded"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        contract.active_dns_tproxy_benchmark_recorded,
        fixture["active_dns_tproxy_benchmark_recorded"]
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
fn stage54_active_dns_tproxy_cache_gate_blocks_default_admission() {
    let contract = stage54_active_dns_tproxy_cache_gate_contract();
    assert!(contract.stage_complete);
    assert!(contract.active_udp_tproxy_admitted);
    assert!(contract.active_dns_tproxy_admitted);
    assert!(contract.active_dns_original_destination_recorded);
    assert!(contract.dns_controller_path_recorded);
    assert!(contract.dns_upstream_query_recorded);
    assert!(contract.dns_response_validation_recorded);
    assert!(contract.dns_cache_restore_recorded);
    assert!(contract.domain_routing_owner_migration_recorded);
    assert!(contract.dns_sendpkt_reply_recorded);
    assert!(contract.dns_so_mark_upstream_socket_recorded);
    assert!(contract.active_dns_tproxy_benchmark_recorded);
    assert!(!contract.outbound_true_dataplane_admitted);
    assert!(!contract.default_switch_allowed);
    assert!(!contract.product_chain_switch_allowed);
    assert!(!contract.true_rust_default_daemon_admitted);
    assert!(contract.go_default_path_preserved);
    assert!(contract.go_fallback_required);

    assert_contains_text(&contract.carried_blockers, "protocol true dataplane");
    assert_contains_text(&contract.carried_blockers, "matched Go default daemon");
}

#[test]
fn stage54_active_dns_tproxy_cache_gate_covers_rows() {
    let contract = stage54_active_dns_tproxy_cache_gate_contract();
    let areas = contract.rows.iter().map(|row| row.area).collect::<Vec<_>>();
    assert_eq!(
        areas,
        vec![
            "transparent DNS UDP/53 receive",
            "DNS upstream and response validation",
            "reload DNS cache and domain routing owner",
            "DNS sendPkt reply and benchmark"
        ]
    );
    assert_contains_text(&contract.source, "runtime_stage50_tcp_gate.rs");
    assert_contains_text(&contract.source, "cache.rs");
    assert_contains_text(&contract.source, "domain_routing.rs");
    assert_contains_text(
        &contract.validation_commands,
        "stage54-active-dns-tproxy-cache-admission",
    );
}
