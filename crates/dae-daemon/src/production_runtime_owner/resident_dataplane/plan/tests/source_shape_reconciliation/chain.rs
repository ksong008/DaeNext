use super::*;
use dae_outbound::{
    MaterializedChain, MaterializedChainUdp, MaterializedProtocol,
    MaterializedStreamPacketTransport, MaterializedUdp, MaterializedWrapper,
};

fn parent_source() -> String {
    socks5_fixture_url(
        &fixture_host(FixtureEndpoint::Primary),
        fixture_port(FixtureEndpoint::Primary.slot()),
    )
}

fn chained_source(child: String) -> String {
    format!("{} -> {child}", parent_source())
}

fn node_shape(source: &str) -> ResidentNodeLinkShape {
    let parsed = dae_outbound::parse_link_chain(source).unwrap();
    ResidentNodeLinkShape {
        tag: "chain-shape".to_owned(),
        scheme: parsed.nodes.first().unwrap().scheme.clone(),
        link: source.to_owned(),
    }
}

#[test]
fn builder_projects_raw_child_udp_and_effective_chain_disposition_separately() {
    let primary = fixture_host(FixtureEndpoint::Secondary);
    let authority = fixture_host(FixtureEndpoint::Authority);
    let cases = [
        (
            vmess_fixture_url("", &primary, fixture_port(4), "tcp", "", "", ""),
            MaterializedChainUdp::ParentStream,
            MaterializedProtocol::VmessAead,
            MaterializedWrapper::None,
            MaterializedUdp::Vmess(MaterializedStreamPacketTransport::PlainTcp),
        ),
        (
            vmess_fixture_url("", &primary, fixture_port(4), "ws", &authority, "/ws", ""),
            MaterializedChainUdp::ParentStream,
            MaterializedProtocol::VmessAead,
            MaterializedWrapper::WebSocket,
            MaterializedUdp::Vmess(MaterializedStreamPacketTransport::WebSocketPlain),
        ),
        (
            socks5_fixture_url(&primary, fixture_port(4)),
            MaterializedChainUdp::PolicyClosed,
            MaterializedProtocol::Socks5,
            MaterializedWrapper::None,
            MaterializedUdp::Socks5Associate,
        ),
        (
            shadowsocks_fixture_url("", &primary, fixture_port(4)),
            MaterializedChainUdp::PolicyClosed,
            MaterializedProtocol::ShadowsocksAead,
            MaterializedWrapper::None,
            MaterializedUdp::ShadowsocksAead,
        ),
        (
            http_transport_fixture_url(&primary, fixture_port(4)),
            MaterializedChainUdp::PolicyClosed,
            MaterializedProtocol::HttpProxy,
            MaterializedWrapper::HttpTransport,
            MaterializedUdp::PolicyClosed(
                dae_outbound::MaterializedPolicyClosedReason::HttpConnect,
            ),
        ),
    ];

    let nested_row = dae_outbound::source_shape_registry_rows()
        .iter()
        .find(|row| row.shape_id == "nested-chain-shape")
        .unwrap();
    for (child, expected_chain_udp, protocol, wrapper, udp) in cases {
        let source = chained_source(child);
        let proxy = build(&source).unwrap_or_else(|error| panic!("build chain: {error}"));
        let shape = materialized_source_shape(&proxy, &source);
        assert_eq!(shape.chain, MaterializedChain::ParentConnect);
        assert_eq!(shape.chain_udp, expected_chain_udp);
        assert_eq!(shape.protocol, protocol);
        assert_eq!(shape.wrapper, wrapper);
        assert_eq!(shape.udp, udp);
        assert!(source_shape_matches_materialization(
            nested_row, &proxy, &source
        ));
    }
}

#[test]
fn source_candidate_prefilter_separates_valid_chain_and_standalone_topologies() {
    let rows = dae_outbound::source_shape_registry_rows();
    let nested = rows
        .iter()
        .find(|row| row.shape_id == "nested-chain-shape")
        .unwrap();
    let socks = rows
        .iter()
        .find(|row| row.shape_id == "baseline-socks-endpoint")
        .unwrap();
    let standalone = parent_source();
    let chain = chained_source(http_proxy_fixture_url(
        &fixture_host(FixtureEndpoint::Secondary),
        fixture_port(FixtureEndpoint::Secondary.slot()),
    ));

    assert!(source_shape_candidate_is_relevant(
        nested,
        &node_shape(&chain)
    ));
    assert!(!source_shape_candidate_is_relevant(
        socks,
        &node_shape(&chain)
    ));
    assert!(source_shape_candidate_is_relevant(
        socks,
        &node_shape(&standalone)
    ));
    assert!(!source_shape_candidate_is_relevant(
        nested,
        &node_shape(&standalone)
    ));

    let malformed = ResidentNodeLinkShape {
        tag: "malformed-chain".to_owned(),
        scheme: "socks5".to_owned(),
        link: "socks5://[".to_owned(),
    };
    assert!(source_shape_candidate_is_relevant(socks, &malformed));
}
