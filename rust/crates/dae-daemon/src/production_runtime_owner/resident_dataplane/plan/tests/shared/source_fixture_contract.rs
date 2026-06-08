use super::*;
pub(crate) fn resident_admitted_source_fixture_links() -> Vec<String> {
    let primary_host = fixture_host(FixtureEndpoint::Primary);
    let authority_host = fixture_host(FixtureEndpoint::Authority);
    vec![
        socks5_fixture_url(&primary_host, fixture_port(1)),
        http_proxy_fixture_url(&primary_host, fixture_port(1)),
        https_proxy_fixture_url(&primary_host, fixture_port(1)),
        shadowsocks_fixture_url("", &primary_host, fixture_port(1)),
        shadowsocks_plugin_fixture_url("", &primary_host, fixture_port(2)),
        shadowsocksr_http_simple_fixture_url(
            shadowsocksr_stream_cipher_specs()
                .first()
                .expect("ShadowsocksR stream cipher table must not be empty")
                .cipher,
        ),
        trojan_fixture_url("", &primary_host, fixture_port(1)),
        trojan_websocket_fixture_url("", &primary_host, fixture_port(2)),
        anytls_fixture_url(&primary_host, fixture_port(1)),
        vmess_fixture_url("", &primary_host, fixture_port(2), "tcp", "", "", ""),
        vmess_fixture_url(
            "",
            &primary_host,
            fixture_port(3),
            "ws",
            &authority_host,
            "/vmess",
            "",
        ),
        vmess_fixture_url_with_sni(
            &primary_host,
            fixture_port(3),
            "ws",
            &authority_host,
            "/vmess",
            "tls",
            &authority_host,
        ),
        vmess_fixture_url_with_sni(
            &primary_host,
            fixture_port(4),
            "httpupgrade",
            &authority_host,
            "/vmess-upgrade",
            "tls",
            &authority_host,
        ),
        vless_fixture_url(
            "",
            &primary_host,
            fixture_port(5),
            "ws",
            &authority_host,
            "/ws",
            &authority_host,
            "",
            "",
        ),
        vless_reality_fixture_url(),
        vless_mux_fixture_url(),
        hysteria2_fixture_url("", &primary_host, fixture_port(6)),
        hysteria2_fixture_url_with_pin(
            "",
            &fixture_hop_server(
                fixture_port(6),
                &format!(",{}-{}", fixture_port(7), fixture_port(8)),
            ),
            &fixture_pin_sha256(),
        ),
        tuic_fixture_url("", &primary_host, fixture_port(7), true),
        tuic_fixture_url("", &primary_host, fixture_port(7), false),
        juicity_fixture_url("", &primary_host, fixture_port(8), true),
    ]
}

pub(crate) fn assert_common_source_import_round_trips(link: &str) {
    let scheme = link
        .split_once("://")
        .map(|(scheme, _)| scheme)
        .unwrap_or_default();
    match scheme {
        "socks" | "socks5" => {
            let parsed = Url::parse(link).unwrap();
            assert!(parsed.has_host(), "{link}");
            assert!(parsed.port().is_some(), "{link}");
            assert!(!parsed.username().is_empty(), "{link}");
        }
        "http" | "https" => {
            assert_eq!(HttpProxyLink::parse(link).unwrap().export_url(), link);
        }
        "ss" => {
            assert_eq!(ShadowsocksLink::parse(link).unwrap().export_url(), link);
        }
        "ssr" => {
            let parsed = ShadowsocksRLink::parse(link).unwrap();
            assert_eq!(parsed.protocol, "shadowsocksr");
            assert!(!parsed.server.is_empty(), "{link}");
            assert!(parsed.port > 0, "{link}");
            assert!(!parsed.password.is_empty(), "{link}");
            assert!(!parsed.cipher.is_empty(), "{link}");
            assert_eq!(parsed.proto, "origin");
            assert_eq!(parsed.obfs, "http_simple");
        }
        "trojan" | "trojan-go" => {
            assert_eq!(TrojanLink::parse(link).unwrap().export_url(), link);
        }
        "anytls" => {
            assert_eq!(AnyTLSLink::parse(link).unwrap().export_url(), link);
        }
        "vmess" => {
            assert_eq!(VMessLink::parse(link).unwrap().export_url(), link);
        }
        "vless" => {
            assert_eq!(VLESSLink::parse(link).unwrap().export_url(), link);
        }
        "hysteria2" | "hy2" => {
            assert_eq!(Hysteria2Link::parse(link).unwrap().export_url(), link);
        }
        "tuic" => {
            assert_eq!(TuicLink::parse(link).unwrap().export_url(), link);
        }
        "juicity" => {
            assert_eq!(JuicityLink::parse(link).unwrap().export_url(), link);
        }
        other => panic!("unexpected resident source fixture scheme {other}: {link}"),
    }
}

#[test]
pub(crate) fn resident_admitted_source_fixtures_use_common_canonical_formats() {
    let links = resident_admitted_source_fixture_links();
    assert!(links.len() >= 10);
    for link in links {
        assert_resident_source_fixture_uses_generic_semantics(&link);
        assert_common_source_import_round_trips(&link);
    }
}

#[test]
pub(crate) fn resident_legacy_import_normalizes_to_current_executor() {
    let config = parse_config(
        r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        }
        routing {
        fallback: direct
        }
        "#,
    );
    let legacy = vmess_legacy_fixture_url();
    assert_resident_source_fixture_uses_generic_semantics(&legacy);
    let normalized = VMessLink::parse(&legacy).unwrap().export_url();
    assert_ne!(normalized, legacy);
    let proxy = build_resident_proxy_plan_for_node(
        &config,
        "proxy".to_owned(),
        "legacy_import".to_owned(),
        legacy,
    )
    .unwrap();
    assert_eq!(proxy.protocol, "vmess");
    assert_eq!(proxy.net, "tcp");
    assert!(matches!(
        proxy.handler,
        ResidentProxyProtocolPlan::VmessAeadTcp { .. }
    ));
}
