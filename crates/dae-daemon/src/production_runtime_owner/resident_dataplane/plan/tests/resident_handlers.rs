use super::*;
mod basic_shadowsocks;
use self::basic_shadowsocks::*;
mod trojan;
use self::trojan::*;
mod vmess_vless;
use self::vmess_vless::*;
mod quic;
use self::quic::*;
mod graph_contract;
use self::graph_contract::*;

#[test]
pub(super) fn resident_dataplane_plan_admits_shadowsocks_2022_cipher_family() {
    for conf in cipher_confs() {
        let psk = base64::engine::general_purpose::STANDARD.encode(vec![0_u8; conf.key_len]);
        let link = ShadowsocksLink {
            name: String::new(),
            server: fixture_host(FixtureEndpoint::Primary),
            port: fixture_port(1),
            password: psk,
            cipher: conf.cipher.to_owned(),
            plugin: Sip003::default(),
            udp: true,
            protocol: "shadowsocks".to_owned(),
        }
        .export_url();
        let config_source = r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        }
        node {
        ss_live: '{link}'
        }
        group {
        proxy {
            filter: name(ss_live)
            policy: fixed(0)
        }
        }
        routing {
        l4proto(tcp) && dport(443) -> proxy
        fallback: direct
        }
        "#;
        let config_source = config_source.replace("{link}", &link);
        let config = parse_config(&config_source);
        let plan = build_resident_dataplane_plan(&config).unwrap();
        let proxy = plan
            .default_proxy_group()
            .unwrap()
            .select_proxy_for_tcp()
            .unwrap();
        assert_eq!(proxy.node_tag, "ss_live");
        assert_eq!(proxy.protocol, "shadowsocks");
        assert_eq!(proxy.tls, "aead-2022");
        assert_eq!(
            proxy.executable_graph_value()["packetSemantics"],
            "datagram-aead-2022"
        );
        assert!(matches!(
            proxy.handler,
            ResidentProxyProtocolPlan::Shadowsocks2022Tcp {
                salt_len,
                packet_nonce_len,
                ..
            } if salt_len == conf.salt_len && packet_nonce_len == conf.packet_nonce_len
        ));
    }
}

#[test]
pub(super) fn resident_dataplane_plan_admits_shadowsocks_aead_cipher_family() {
    let config = resident_tcp_handler_config();
    for spec in aead_cipher_specs() {
        for cipher in std::iter::once(spec.cipher).chain(spec.aliases.iter().copied()) {
            let link = ShadowsocksLink {
                name: String::new(),
                server: fixture_host(FixtureEndpoint::Primary),
                port: fixture_port(1),
                password: fixture_secret(),
                cipher: cipher.to_owned(),
                plugin: Sip003::default(),
                udp: true,
                protocol: "shadowsocks".to_owned(),
            }
            .export_url();
            let proxy = build_resident_proxy_plan_for_node(
                &config,
                "proxy".to_owned(),
                format!("ss_{cipher}"),
                link,
            )
            .unwrap();
            assert_eq!(proxy.protocol, "shadowsocks");
            assert_eq!(proxy.tls, "aead");
            assert!(matches!(
                proxy.handler,
                ResidentProxyProtocolPlan::ShadowsocksAeadTcp {
                    ref cipher,
                    salt_len,
                    ..
                } if cipher == spec.cipher && salt_len == spec.salt_len
            ));
        }
    }
}

#[test]
pub(super) fn resident_dataplane_plan_admits_trojan_inner_shadowsocks_aead_family() {
    let config = resident_tcp_handler_config();
    for spec in aead_cipher_specs() {
        for cipher in std::iter::once(spec.cipher).chain(spec.aliases.iter().copied()) {
            let proxy = build_resident_proxy_plan_for_node(
                &config,
                "proxy".to_owned(),
                format!("trojan_inner_{cipher}"),
                trojan_inner_shadowsocks_fixture_url(cipher),
            )
            .unwrap();
            assert_eq!(proxy.protocol, "trojan");
            assert_eq!(proxy.net, "websocket");
            assert!(matches!(
                proxy.handler,
                ResidentProxyProtocolPlan::TrojanInnerShadowsocksTcpTls {
                    ref inner_cipher,
                    ..
                } if inner_cipher == spec.cipher
            ));
        }
    }
}

#[test]
pub(super) fn resident_dataplane_plan_admits_supported_legacy_stream_cipher_family() {
    let config = resident_tcp_handler_config();
    for spec in shadowsocksr_stream_cipher_specs() {
        let link = shadowsocksr_http_simple_fixture_url(spec.cipher);
        let proxy = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            format!("legacy_{}", spec.cipher),
            link,
        )
        .unwrap();
        assert_eq!(proxy.protocol, "shadowsocksr");
        assert_eq!(proxy.tls, "legacy-cipher");
        assert_eq!(proxy.net, "legacy-obfs");
        assert!(matches!(
            proxy.handler,
            ResidentProxyProtocolPlan::ShadowsocksRHttpSimpleTcp {
                ref cipher,
                ..
            } if cipher == spec.cipher
        ));
    }
}

pub(super) fn resident_tcp_handler_config() -> Config {
    parse_config(
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
    )
}

#[test]
pub(super) fn resident_dataplane_plan_admits_basic_and_shadowsocks_handlers() {
    let config = resident_tcp_handler_config();
    let proxies = assert_basic_and_shadowsocks_handlers(&config);
    assert_common_resident_graph_contracts(&proxies);
}

#[test]
pub(super) fn resident_dataplane_plan_admits_trojan_handlers() {
    let config = resident_tcp_handler_config();
    let proxies = assert_trojan_handlers(&config);
    assert_common_resident_graph_contracts(&proxies);
}

#[test]
pub(super) fn resident_dataplane_plan_admits_vmess_vless_handlers() {
    let config = resident_tcp_handler_config();
    let proxies = assert_vmess_vless_handlers(&config);
    assert_common_resident_graph_contracts(&proxies);
}

#[test]
pub(super) fn resident_dataplane_plan_admits_quic_handlers() {
    let config = resident_tcp_handler_config();
    let proxies = assert_quic_handlers(&config);
    assert_common_resident_graph_contracts(&proxies);
}
