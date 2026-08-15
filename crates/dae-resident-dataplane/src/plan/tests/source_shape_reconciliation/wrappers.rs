use super::*;

#[test]
fn builder_witnesses_protocol_specific_meek_and_h2_rows() {
    let primary = fixture_host(FixtureEndpoint::Primary);
    let authority = fixture_host(FixtureEndpoint::Authority);
    assert_witness(
        "vless-meek-tls-stream-wrapper",
        vless_fixture_url(
            "",
            &primary,
            fixture_port(5),
            "meek",
            "",
            "https://meek.fixture.invalid/resource",
            &authority,
            "",
            "",
        ),
    );

    let mut reality_meek = VLESSLink::parse(&vless_reality_fixture_url()).unwrap();
    reality_meek.net = "meek".to_owned();
    reality_meek.flow.clear();
    reality_meek.host.clear();
    reality_meek.path = "https://meek.fixture.invalid/resource".to_owned();
    reality_meek.alpn = dae_outbound::shared_transport::UTLS_ALPN_HTTP_1_1.to_owned();
    assert_witness(
        "vless-meek-reality-stream-wrapper",
        reality_meek.export_url(),
    );

    assert_witness(
        "vless-h2-stream-wrapper",
        vless_fixture_url(
            "",
            &primary,
            fixture_port(5),
            "h2",
            &authority,
            "/h2",
            &authority,
            "",
            "",
        ),
    );
    assert_witness(
        "vmess-h2-stream-wrapper",
        vmess_fixture_url_with_sni(
            &primary,
            fixture_port(4),
            "h2",
            &authority,
            "/h2",
            "tls",
            &authority,
        ),
    );
}

#[test]
fn builder_witnesses_chain_and_trojan_inner_without_protocol_aliases() {
    let chain = two_node_chain_fixture_url();
    assert_witness("nested-chain-shape", chain.clone());
    let chain_row = dae_outbound::source_shape_registry_rows()
        .iter()
        .find(|row| row.shape_id == "nested-chain-shape")
        .unwrap();
    assert!(source_shape_candidate_is_relevant(
        chain_row,
        &ResidentNodeLinkShape {
            tag: "chain-source-prefilter".to_owned(),
            scheme: "socks5".to_owned(),
            link: chain,
        }
    ));
    let standalone_socks =
        socks5_fixture_url(&fixture_host(FixtureEndpoint::Primary), fixture_port(2));
    assert!(!source_shape_candidate_is_relevant(
        chain_row,
        &ResidentNodeLinkShape {
            tag: "standalone-source-prefilter".to_owned(),
            scheme: "socks5".to_owned(),
            link: standalone_socks,
        }
    ));
    assert_witness(
        "inner-encryption-stream-wrapper",
        trojan_inner_shadowsocks_fixture_url("aes-128-gcm"),
    );

    let ordinary =
        trojan_websocket_fixture_url("", &fixture_host(FixtureEndpoint::Primary), fixture_port(3));
    let ordinary_proxy = build(&ordinary).unwrap();
    let ordinary_shape = materialized_source_shape(&ordinary_proxy, &ordinary);
    assert!(
        !source_shape_reconciliation("inner-encryption-stream-wrapper")
            .unwrap()
            .matches(ordinary_shape)
    );
}
