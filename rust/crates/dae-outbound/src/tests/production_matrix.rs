use super::*;

#[test]
fn outbound_production_matrix_contract_covers_current_native_handlers() {
    let contract = outbound_production_matrix_contract();
    assert_eq!(contract.schema, "outbound-production-matrix");
    assert!(contract.matrix_ready);
    assert!(contract.parser_export_metadata_ready);
    assert!(contract.tcp_udp_dataplane_ready);
    assert!(contract.transport_underlay_ready);
    assert!(contract.route_group_connectivity_ready);
    assert!(contract.reload_behavior_ready);
    assert!(contract.live_smoke_ready);
    assert!(contract.go_fallback_retirement_ready);

    let handlers: Vec<_> = contract.entries.iter().map(|entry| entry.handler).collect();
    for expected in [
        "shadowsocks",
        "trojan",
        "vmess",
        "vless",
        "hysteria2",
        "tuic",
        "juicity",
        "anytls",
        "http-proxy",
        "socks5",
    ] {
        assert!(
            handlers.contains(&expected),
            "missing matrix entry: {expected}"
        );
    }

    for entry in contract.entries {
        assert!(entry.parser_export_metadata, "{}", entry.handler);
        assert!(entry.tcp_dataplane, "{}", entry.handler);
        assert!(entry.udp_dataplane, "{}", entry.handler);
        assert!(entry.transport_underlay, "{}", entry.handler);
        assert!(entry.route_group_connectivity, "{}", entry.handler);
        assert!(entry.reload_behavior, "{}", entry.handler);
        assert!(entry.live_smoke, "{}", entry.handler);
        assert!(entry.go_fallback_retired, "{}", entry.handler);
        assert!(!entry.evidence.is_empty(), "{}", entry.handler);
    }
}
