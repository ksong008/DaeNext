use super::*;
use dae_outbound::{ShadowsocksLink, Sip003};

#[test]
fn plain_stream_and_datagram_sources_have_exact_production_rows() {
    let config = fixture_config();
    let primary = fixture_host(FixtureEndpoint::Primary);
    let authority = fixture_host(FixtureEndpoint::Authority);
    for (source, expected) in [
        (
            vless_plain_tcp_none_fixture_url(),
            "vless-native-tcp-endpoint",
        ),
        (
            vmess_fixture_url("", &primary, fixture_port(3), "tcp", "", "", ""),
            "baseline-aead-framed-endpoint",
        ),
        (
            vmess_tcp_http_header_fixture_url(
                &primary,
                fixture_port(3),
                &authority,
                "/vmess-header",
                "",
                "",
            ),
            "baseline-aead-framed-endpoint",
        ),
        (
            vmess_fixture_url(
                "",
                &primary,
                fixture_port(3),
                "grpc",
                &authority,
                "/grpc",
                "",
            ),
            "plain-grpc-framed-endpoint",
        ),
        (
            vmess_fixture_url("", &primary, fixture_port(3), "ws", &authority, "/ws", ""),
            "plain-websocket-framed-endpoint",
        ),
        (
            vmess_fixture_url(
                "",
                &primary,
                fixture_port(3),
                "httpupgrade",
                &authority,
                "/upgrade",
                "",
            ),
            "plain-httpupgrade-framed-endpoint",
        ),
        (
            socks5_fixture_url(&primary, fixture_port(3)),
            "baseline-socks-endpoint",
        ),
        (
            http_proxy_fixture_url(&primary, fixture_port(3)),
            "baseline-connect-endpoint",
        ),
        (
            shadowsocks_fixture_url("", &primary, fixture_port(3)),
            "baseline-aead-cipher-endpoint",
        ),
        (
            shadowsocks_plugin_fixture_url("", &primary, fixture_port(3)),
            "plugin-wrapper-layer",
        ),
        (
            shadowsocks_simple_obfs_tls_fixture_url("", &primary, fixture_port(3)),
            "obfs-tls-plugin-wrapper",
        ),
        (
            shadowsocks_2022_source(&primary, fixture_port(3)),
            "baseline-aead-2022-cipher-endpoint",
        ),
        (
            shadowsocks_2022_simple_obfs_http_fixture_url("", &primary, fixture_port(3)),
            "aead-2022-plugin-wrapper",
        ),
        (
            shadowsocksr_http_simple_fixture_url(
                shadowsocksr_stream_cipher_specs().first().unwrap().cipher,
            ),
            "legacy-cipher-protocol-shape",
        ),
    ] {
        assert_exact_source(&source, &config, &[expected]);
    }
}

#[test]
fn quic_qualifiers_produce_exact_match_sets() {
    let config = fixture_config();
    let primary = fixture_host(FixtureEndpoint::Primary);

    assert_exact_source(
        &hysteria2_fixture_url("", &primary, fixture_port(5)),
        &config,
        &["baseline-quic-auth-endpoint"],
    );
    assert_exact_source(
        &hysteria2_fixture_url_with_pin(
            "",
            &fixture_hop_server(
                fixture_port(5),
                &format!(",{}-{}", fixture_port(6), fixture_port(7)),
            ),
            &fixture_pin_sha256(),
        ),
        &config,
        &["quic-port-hopping-surface"],
    );
    assert_exact_source(
        &tuic_fixture_url("", &primary, fixture_port(6), false),
        &config,
        &[
            "baseline-quic-uuid-endpoint",
            "verified-quic-security-underlay",
        ],
    );
    assert_exact_source(
        &tuic_fixture_url("", &primary, fixture_port(6), true),
        &config,
        &["baseline-quic-uuid-endpoint"],
    );
    assert_exact_source(
        &juicity_fixture_url("", &primary, fixture_port(7), true),
        &config,
        &["baseline-quic-password-endpoint"],
    );
}

#[test]
fn nested_chain_sources_have_only_the_effective_chain_row() {
    let primary = fixture_host(FixtureEndpoint::Primary);
    let authority = fixture_host(FixtureEndpoint::Authority);
    let parent = socks5_fixture_url(&primary, fixture_port(8));
    for child in [
        socks5_fixture_url(&primary, fixture_port(9)),
        shadowsocks_fixture_url("", &primary, fixture_port(9)),
        http_transport_fixture_url(&primary, fixture_port(9)),
        vmess_fixture_url("", &primary, fixture_port(9), "tcp", "", "", ""),
        vmess_fixture_url("", &primary, fixture_port(9), "ws", &authority, "/ws", ""),
        vmess_fixture_url(
            "",
            &primary,
            fixture_port(9),
            "httpupgrade",
            &authority,
            "/upgrade",
            "",
        ),
    ] {
        assert_exact_source(
            &format!("{parent} -> {child}"),
            &fixture_config(),
            &["nested-chain-shape"],
        );
    }
}

fn shadowsocks_2022_source(host: &str, port: u16) -> String {
    let conf = default_shadowsocks_2022_conf();
    ShadowsocksLink {
        name: String::new(),
        server: host.to_owned(),
        port,
        password: psk_for_conf(conf),
        cipher: conf.cipher.to_owned(),
        plugin: Sip003::default(),
        udp: true,
        protocol: "shadowsocks".to_owned(),
    }
    .export_url()
}
