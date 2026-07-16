use super::source_fixtures::shadowsocks_2022_source;
use super::*;

pub(super) fn chained_builder_sources() -> Vec<String> {
    let primary = fixture_host(FixtureEndpoint::Primary);
    let authority = fixture_host(FixtureEndpoint::Authority);
    let parent = socks5_fixture_url(&primary, fixture_port(9));
    [
        socks5_fixture_url(&primary, fixture_port(10)),
        http_proxy_fixture_url(&primary, fixture_port(10)),
        http_transport_fixture_url(&primary, fixture_port(10)),
        shadowsocks_fixture_url("", &primary, fixture_port(10)),
        shadowsocks_2022_source(&primary, fixture_port(10)),
        shadowsocks_plugin_fixture_url("", &primary, fixture_port(10)),
        shadowsocks_simple_obfs_tls_fixture_url("", &primary, fixture_port(10)),
        shadowsocks_v2ray_plugin_tls_fixture_url("", &primary, fixture_port(10)),
        shadowsocks_2022_simple_obfs_http_fixture_url("", &primary, fixture_port(10)),
        shadowsocksr_http_simple_fixture_url(
            shadowsocksr_stream_cipher_specs()
                .first()
                .expect("ShadowsocksR stream cipher table must not be empty")
                .cipher,
        ),
        vmess_fixture_url("", &primary, fixture_port(10), "tcp", "", "", ""),
        vmess_fixture_url("", &primary, fixture_port(10), "ws", &authority, "/ws", ""),
        vmess_fixture_url(
            "",
            &primary,
            fixture_port(10),
            "httpupgrade",
            &authority,
            "/up",
            "",
        ),
    ]
    .into_iter()
    .map(|source| format!("{parent} -> {source}"))
    .collect()
}
