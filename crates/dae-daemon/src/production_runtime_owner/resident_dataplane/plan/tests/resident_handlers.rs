use super::*;
mod basic_shadowsocks;
use self::basic_shadowsocks::*;
mod trojan;
use self::trojan::*;
mod vmess_vless;
use self::vmess_vless::*;
mod quic;
mod xhttp_h3_admission;
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

#[test]
fn hysteria2_port_hopping_rejects_an_interval_below_the_official_minimum() {
    let config = parse_config(
        r#"
        global {
        udphop_interval: 4s
        }
        routing {
        fallback: direct
        }
        "#,
    );
    let error = build_resident_proxy_plan_for_node(
        &config,
        "proxy".to_owned(),
        "hy2_short_hop".to_owned(),
        hysteria2_fixture_url_with_pin(
            "hy2",
            &fixture_hop_server(fixture_port(1), &format!(",{}", fixture_port(2))),
            &fixture_pin_sha256(),
        ),
    )
    .unwrap_err();
    assert!(error.contains("must be at least 5000 ms"));
    assert!(!error.contains(&fixture_secret()));
}

#[test]
fn hysteria2_bandwidth_uses_independent_node_and_global_directions() {
    let config = parse_config(
        r#"
        global {
        bandwidth_max_tx: '200 mbps'
        bandwidth_max_rx: '1 gbps'
        }
        routing {
        fallback: direct
        }
        "#,
    );
    let mut link = Hysteria2Link::parse(&hysteria2_fixture_url(
        "hy2",
        &fixture_host(FixtureEndpoint::Primary),
        fixture_port(1),
    ))
    .unwrap();
    link.max_rx = 30_000_000;
    link.max_rx_configured = true;
    link.congestion = Hysteria2CongestionConfig {
        controller: dae_outbound::hysteria2::Hysteria2CongestionController::Reno,
        ..Default::default()
    };
    let proxy = build_resident_proxy_plan_for_node(
        &config,
        "proxy".to_owned(),
        "hy2_independent_bandwidth".to_owned(),
        link.export_url(),
    )
    .unwrap();
    assert!(matches!(
        proxy.handler,
        ResidentProxyProtocolPlan::Hysteria2QuicTcp {
            max_tx: 25_000_000,
            max_rx: 30_000_000,
            congestion: Hysteria2CongestionConfig {
                controller: dae_outbound::hysteria2::Hysteria2CongestionController::Reno,
                ..
            },
            ..
        }
    ));
}

#[test]
fn hysteria2_unavailable_bbr_profile_fails_before_socket_construction() {
    let config = resident_tcp_handler_config();
    let mut link = Hysteria2Link::parse(&hysteria2_fixture_url(
        "hy2",
        &fixture_host(FixtureEndpoint::Primary),
        fixture_port(1),
    ))
    .unwrap();
    link.congestion.bbr_profile = dae_outbound::hysteria2::Hysteria2BbrProfile::Aggressive;
    let error = build_resident_proxy_plan_for_node(
        &config,
        "proxy".to_owned(),
        "hy2_unavailable_profile".to_owned(),
        link.export_url(),
    )
    .unwrap_err();
    assert!(error.contains("only the standard BBR profile"));
}

#[test]
pub(super) fn resident_protocol_executor_contract_covers_all_plan_variants() {
    let variants = [
        ResidentProxyProtocolPlan::VlessVisionTcpTls { key: [1; 16] },
        ResidentProxyProtocolPlan::VlessMuxTcpTls { key: [2; 16] },
        ResidentProxyProtocolPlan::Socks5Tcp {
            username: fixture_secret(),
            password: fixture_secret(),
        },
        ResidentProxyProtocolPlan::HttpProxyTcp {
            username: fixture_secret(),
            password: fixture_secret(),
            transport: false,
            transport_host: String::new(),
            transport_path: String::new(),
        },
        ResidentProxyProtocolPlan::ShadowsocksAeadTcp {
            cipher: "aes-128-gcm".to_owned(),
            password: fixture_secret(),
            salt_len: 16,
        },
        ResidentProxyProtocolPlan::Shadowsocks2022Tcp {
            cipher: "2022-blake3-aes-128-gcm".to_owned(),
            password: fixture_secret(),
            salt_len: 16,
            packet_nonce_len: 16,
        },
        ResidentProxyProtocolPlan::ShadowsocksSimpleObfsHttpTcp {
            cipher: "aes-128-gcm".to_owned(),
            password: fixture_secret(),
            salt_len: 16,
            host: fixture_host(FixtureEndpoint::Primary),
            path: "/obfs".to_owned(),
        },
        ResidentProxyProtocolPlan::ShadowsocksSimpleObfsTlsTcp {
            cipher: "aes-128-gcm".to_owned(),
            password: fixture_secret(),
            salt_len: 16,
            host: fixture_host(FixtureEndpoint::Primary),
        },
        ResidentProxyProtocolPlan::ShadowsocksV2rayPluginTlsWsTcp {
            cipher: "aes-128-gcm".to_owned(),
            password: fixture_secret(),
            salt_len: 16,
            host: fixture_host(FixtureEndpoint::Primary),
            path: "/plugin".to_owned(),
        },
        ResidentProxyProtocolPlan::Shadowsocks2022SimpleObfsHttpTcp {
            cipher: "2022-blake3-aes-128-gcm".to_owned(),
            password: fixture_secret(),
            salt_len: 16,
            host: fixture_host(FixtureEndpoint::Primary),
            path: "/obfs".to_owned(),
        },
        ResidentProxyProtocolPlan::ShadowsocksRHttpSimpleTcp {
            cipher: "aes-128-cfb".to_owned(),
            password: fixture_secret(),
            obfs_host: fixture_host(FixtureEndpoint::Primary),
            obfs_port: fixture_port(1),
        },
        ResidentProxyProtocolPlan::TrojanTcpTls {
            password: fixture_secret(),
        },
        ResidentProxyProtocolPlan::TrojanInnerShadowsocksTcpTls {
            password: fixture_secret(),
            inner_cipher: "aes-128-gcm".to_owned(),
            inner_password: fixture_secret(),
        },
        ResidentProxyProtocolPlan::AnyTlsTcpTls {
            auth: fixture_secret(),
        },
        ResidentProxyProtocolPlan::VmessAeadTcp {
            id: fixture_client_id(),
        },
        ResidentProxyProtocolPlan::Hysteria2QuicTcp {
            auth: fixture_secret(),
            tls_identity: dae_outbound::hysteria2::Hysteria2TlsIdentity::from_node_and_global(
                fixture_host(FixtureEndpoint::Authority),
                false,
                false,
                &fixture_pin_sha256(),
            )
            .unwrap(),
            max_tx: 0,
            max_rx: 0,
            congestion: Default::default(),
            obfs: ResidentHysteria2ObfsPlan::none(),
            port_hop_ports: vec![fixture_port(1)],
            port_hop_interval: Duration::from_secs(30),
        },
        ResidentProxyProtocolPlan::TuicQuicTcp {
            uuid: fixture_client_id(),
            password: fixture_secret(),
            alpn: vec!["h3".to_owned()],
            allow_insecure: false,
            congestion: dae_outbound::tuic::TuicCongestionController::Bbr,
            udp_relay_mode: dae_outbound::tuic::TuicUdpRelayMode::Native,
        },
        ResidentProxyProtocolPlan::JuicityQuicTcp {
            uuid: fixture_client_id(),
            password: fixture_secret(),
            allow_insecure: false,
            pinned_certchain_sha256: "sha256:fixture".to_owned(),
        },
    ];

    for variant in variants {
        let contract = variant.executor_contract();
        assert!(!contract.tcp_executor.is_empty());
        assert!(!contract.udp_executor.is_empty());
        assert!(!contract.packet_semantics.is_empty());
        assert!(!contract.tcp_executor.contains("fallback"));
        assert!(!contract.udp_executor.contains("fallback"));
        if contract.udp_policy_closed {
            assert!(
                contract.udp_executor.contains("closed"),
                "{} must explain its UDP policy closure",
                contract.udp_executor
            );
        }
    }
}
