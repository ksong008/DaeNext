use super::*;
pub(crate) fn resident_admitted_source_fixture_links() -> Vec<String> {
    vec![
        "socks5://user:password@proxy.example.net:1080".to_owned(),
        "http://user:password@proxy.example.net:80".to_owned(),
        "https://user:password@secure-proxy.example.net:443".to_owned(),
        shadowsocks_fixture_url("ss", "203.0.113.10", 28446),
        shadowsocks_plugin_fixture_url("ss-plugin", "203.0.113.10", 28447),
        trojan_fixture_url("trojan", "203.0.113.10", 28444),
        trojan_websocket_fixture_url("trojan-ws", "203.0.113.10", 28456),
        "anytls://password@secure-stream.example.net:443?sni=secure-stream.example.net".to_owned(),
        vmess_fixture_url("vmess", "203.0.113.10", 28452, "tcp", "", "", ""),
        vmess_fixture_url(
            "vmess-ws",
            "203.0.113.10",
            28454,
            "ws",
            "front.example",
            "/vmess",
            "",
        ),
        vmess_fixture_url_with_sni(
            "203.0.113.10",
            28454,
            "ws",
            "front.example",
            "/vmess",
            "tls",
            "office.example",
        ),
        vmess_fixture_url_with_sni(
            "203.0.113.10",
            28460,
            "httpupgrade",
            "front.example",
            "/vmess-upgrade",
            "tls",
            "office.example",
        ),
        vless_fixture_url(
            "vless-ws",
            "203.0.113.10",
            28443,
            "ws",
            "front.example",
            "/ws",
            "office.example",
            "",
            "",
        ),
        hysteria2_fixture_url("hy2", "203.0.113.10", 28453),
        hysteria2_fixture_url_with_pin("hy2-hop", "203.0.113.10:28453,28454-28455", "AA-BB-CC"),
        tuic_fixture_url("tuic", "203.0.113.10", 28454, true),
        tuic_fixture_url("tuic-verified", "203.0.113.10", 28454, false),
        juicity_fixture_url("juicity", "203.0.113.10", 28455, true),
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
