use super::*;
use dae_outbound::{
    FLOW_STREAM_PACKET_OWNERSHIP, FLOW_STREAM_POLICY_CLOSED_OWNERSHIP, MaterializedChainUdp,
    RuntimeOwnershipProfile, ShadowsocksLink, Sip003,
};

#[test]
fn every_nested_chain_selector_has_exact_disposition_and_ownership() {
    let primary = fixture_host(FixtureEndpoint::Primary);
    let authority = fixture_host(FixtureEndpoint::Authority);
    let policy_closed = vec![
        ("socks5", socks5_fixture_url(&primary, fixture_port(10))),
        ("http", http_proxy_fixture_url(&primary, fixture_port(10))),
        (
            "http-transport",
            http_transport_fixture_url(&primary, fixture_port(10)),
        ),
        (
            "shadowsocks-aead",
            shadowsocks_fixture_url("", &primary, fixture_port(10)),
        ),
        ("shadowsocks-2022", shadowsocks_2022_source()),
        (
            "simple-obfs-http",
            shadowsocks_plugin_fixture_url("", &primary, fixture_port(10)),
        ),
        (
            "simple-obfs-tls",
            shadowsocks_simple_obfs_tls_fixture_url("", &primary, fixture_port(10)),
        ),
        (
            "v2ray-plugin-tls-websocket",
            shadowsocks_v2ray_plugin_tls_fixture_url("", &primary, fixture_port(10)),
        ),
        (
            "shadowsocks-2022-simple-obfs-http",
            shadowsocks_2022_simple_obfs_http_fixture_url("", &primary, fixture_port(10)),
        ),
        (
            "shadowsocksr-http-simple",
            shadowsocksr_http_simple_fixture_url(
                shadowsocksr_stream_cipher_specs()
                    .first()
                    .expect("fixture cipher table must not be empty")
                    .cipher,
            ),
        ),
    ];
    for (label, child) in policy_closed {
        assert_chain_case(label, child, false);
    }

    for (label, child) in [
        (
            "vmess-tcp",
            vmess_fixture_url("", &primary, fixture_port(10), "tcp", "", "", ""),
        ),
        (
            "vmess-websocket",
            vmess_fixture_url("", &primary, fixture_port(10), "ws", &authority, "/ws", ""),
        ),
        (
            "vmess-httpupgrade",
            vmess_fixture_url(
                "",
                &primary,
                fixture_port(10),
                "httpupgrade",
                &authority,
                "/upgrade",
                "",
            ),
        ),
    ] {
        assert_chain_case(label, child, true);
    }
}

fn assert_chain_case(label: &str, child: String, parent_stream: bool) {
    let parent = socks5_fixture_url(&fixture_host(FixtureEndpoint::Secondary), fixture_port(9));
    let source = format!("{parent} -> {child}");
    let proxy = build(&source).unwrap_or_else(|error| panic!("build {label} chain: {error}"));
    let shape = materialized_source_shape(&proxy, &source);
    assert_eq!(
        production_match_ids(&source, &proxy),
        ["nested-chain-shape"],
        "{label}: {shape:?}"
    );
    assert_eq!(
        shape.chain_udp,
        if parent_stream {
            MaterializedChainUdp::ParentStream
        } else {
            MaterializedChainUdp::PolicyClosed
        },
        "{label}"
    );

    let expected_ownership = if parent_stream {
        FLOW_STREAM_PACKET_OWNERSHIP
    } else {
        FLOW_STREAM_POLICY_CLOSED_OWNERSHIP
    };
    let wrong_ownership = if parent_stream {
        FLOW_STREAM_POLICY_CLOSED_OWNERSHIP
    } else {
        FLOW_STREAM_PACKET_OWNERSHIP
    };
    assert_exact_chain_ownership(&source, &proxy, expected_ownership, wrong_ownership, label);

    let graph = proxy.executable_graph_value();
    let components = &graph["runtimeComponents"];
    let expected_status = if parent_stream {
        "admitted"
    } else {
        "fail-closed"
    };
    let expected_disposition = if parent_stream {
        "packet-relay"
    } else {
        "policy-closed-negative-path"
    };
    let expected_carrier = if parent_stream {
        "parent-connect-stream"
    } else {
        "unsupported"
    };
    assert_eq!(
        components["udpExecutionAgreement"]["disposition"], expected_disposition,
        "{label}"
    );
    assert_eq!(
        graph["packetSemantics"], components["udpExecutionAgreement"]["packetSemantics"],
        "{label}"
    );
    assert_eq!(
        graph["rawChildPacketSemantics"],
        proxy.execution_plan().udp.packet_semantics().as_str(),
        "{label}"
    );
    assert_eq!(
        components["packetSessionManager"]["status"], expected_status,
        "{label}"
    );
    assert_eq!(
        components["packetSessionManager"]["chainCarrier"], expected_carrier,
        "{label}"
    );
    assert_eq!(
        components["probeExecutor"]["udp"]["status"], expected_status,
        "{label}"
    );
}

fn assert_exact_chain_ownership(
    source: &str,
    proxy: &ResidentProxyPlan,
    expected: RuntimeOwnershipProfile,
    wrong: RuntimeOwnershipProfile,
    label: &str,
) {
    let nested = dae_outbound::source_shape_registry_rows()
        .iter()
        .find(|row| row.shape_id == "nested-chain-shape")
        .unwrap();
    let expected_row = dae_outbound::SourceShapeRegistryRow {
        runtime_ownership: expected,
        ..*nested
    };
    let wrong_row = dae_outbound::SourceShapeRegistryRow {
        runtime_ownership: wrong,
        ..*nested
    };
    assert!(
        source_shape_matches_materialization(&expected_row, proxy, source),
        "{label} must use the expected effective ownership"
    );
    assert!(
        !source_shape_matches_materialization(&wrong_row, proxy, source),
        "{label} must reject the neighbouring ownership model"
    );
}

fn shadowsocks_2022_source() -> String {
    let conf = default_shadowsocks_2022_conf();
    ShadowsocksLink {
        name: String::new(),
        server: fixture_host(FixtureEndpoint::Primary),
        port: fixture_port(10),
        password: psk_for_conf(conf),
        cipher: conf.cipher.to_owned(),
        plugin: Sip003::default(),
        udp: true,
        protocol: "shadowsocks".to_owned(),
    }
    .export_url()
}
