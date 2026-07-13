use super::*;
pub(super) fn assert_basic_and_shadowsocks_handlers(config: &Config) -> Vec<ResidentProxyPlan> {
    let primary_host = fixture_host(FixtureEndpoint::Primary);
    let authority_host = fixture_host(FixtureEndpoint::Authority);
    let primary_port = fixture_port(1);
    let socks = build_resident_proxy_plan_for_node(
        config,
        "proxy".to_owned(),
        "socks_live".to_owned(),
        socks5_fixture_url(&primary_host, primary_port),
    )
    .unwrap();
    assert_eq!(socks.protocol, "socks5");
    assert_eq!(socks.server_host, primary_host);
    assert_eq!(socks.server_port, primary_port);
    assert!(matches!(
        socks.handler,
        ResidentProxyProtocolPlan::Socks5Tcp { .. }
    ));

    let http = build_resident_proxy_plan_for_node(
        config,
        "proxy".to_owned(),
        "http_live".to_owned(),
        http_proxy_fixture_url(&primary_host, primary_port),
    )
    .unwrap();
    assert_eq!(http.protocol, "http-proxy");
    assert_eq!(http.server_host, primary_host);
    assert_eq!(http.server_port, primary_port);
    assert_eq!(http.tls, "none");
    assert!(matches!(
        http.handler,
        ResidentProxyProtocolPlan::HttpProxyTcp { .. }
    ));

    let https = build_resident_proxy_plan_for_node(
        config,
        "proxy".to_owned(),
        "https_live".to_owned(),
        https_proxy_fixture_url(&primary_host, primary_port),
    )
    .unwrap();
    assert_eq!(https.protocol, "http-proxy");
    assert_eq!(https.server_host, primary_host);
    assert_eq!(https.server_port, primary_port);
    assert_eq!(https.server_name, primary_host);
    assert_eq!(https.tls, "tls");
    assert_eq!(https.alpn, vec!["http/1.1".to_owned()]);
    assert!(matches!(
        https.handler,
        ResidentProxyProtocolPlan::HttpProxyTcp { .. }
    ));
    let https_graph = https.executable_graph_value();
    assert_eq!(https_graph["protocolFraming"], "http-proxy");
    assert_eq!(https_graph["securityUnderlay"], "standard-tls");
    assert_eq!(https_graph["packetSemantics"], "protocol-closed");
    assert_eq!(
        https_graph["runtimeComponents"]["underlayFactory"]["provider"],
        "rustls"
    );

    let http_transport = build_resident_proxy_plan_for_node(
        config,
        "proxy".to_owned(),
        "http_transport_live".to_owned(),
        http_transport_fixture_url(&primary_host, primary_port),
    )
    .unwrap();
    assert_eq!(http_transport.protocol, "http-proxy");
    assert_eq!(http_transport.net, "http-transport");
    assert_eq!(http_transport.stream_host, authority_host);
    assert_eq!(http_transport.stream_path, "/resource");
    assert!(matches!(
        http_transport.handler,
        ResidentProxyProtocolPlan::HttpProxyTcp {
            transport: true,
            ref transport_host,
            ref transport_path,
            ..
        } if transport_host == &authority_host && transport_path == "/resource"
    ));

    let shadowsocks = build_resident_proxy_plan_for_node(
        config,
        "proxy".to_owned(),
        "ss_live".to_owned(),
        shadowsocks_fixture_url("ss", &primary_host, primary_port),
    )
    .unwrap();
    assert_eq!(shadowsocks.protocol, "shadowsocks");
    assert_eq!(shadowsocks.tls, "aead");
    assert!(matches!(
        shadowsocks.handler,
        ResidentProxyProtocolPlan::ShadowsocksAeadTcp { salt_len: 16, .. }
    ));

    let shadowsocks_2022 = build_resident_proxy_plan_for_node(
        config,
        "proxy".to_owned(),
        "ss2022_live".to_owned(),
        ShadowsocksLink {
            name: String::new(),
            server: primary_host.clone(),
            port: primary_port,
            password: psk_for_conf(default_shadowsocks_2022_conf()),
            cipher: default_shadowsocks_2022_conf().cipher.to_owned(),
            plugin: Sip003::default(),
            udp: true,
            protocol: "shadowsocks".to_owned(),
        }
        .export_url(),
    )
    .unwrap();
    assert_eq!(shadowsocks_2022.protocol, "shadowsocks");
    assert_eq!(shadowsocks_2022.tls, "aead-2022");
    assert_eq!(
        shadowsocks_2022.executable_graph_value()["packetSemantics"],
        "datagram-aead-2022"
    );
    assert!(matches!(
        shadowsocks_2022.handler,
        ResidentProxyProtocolPlan::Shadowsocks2022Tcp {
            salt_len: 16,
            packet_nonce_len: 0,
            ..
        }
    ));

    let shadowsocks_plugin = build_resident_proxy_plan_for_node(
        config,
        "proxy".to_owned(),
        "ss_plugin_live".to_owned(),
        shadowsocks_plugin_fixture_url("ss-plugin", &primary_host, primary_port),
    )
    .unwrap();
    assert_eq!(shadowsocks_plugin.protocol, "shadowsocks");
    assert_eq!(shadowsocks_plugin.net, "simple-obfs-http");
    assert!(matches!(
        shadowsocks_plugin.handler,
        ResidentProxyProtocolPlan::ShadowsocksSimpleObfsHttpTcp { .. }
    ));

    let shadowsocks_obfs_tls = build_resident_proxy_plan_for_node(
        config,
        "proxy".to_owned(),
        "ss_obfs_tls_live".to_owned(),
        shadowsocks_simple_obfs_tls_fixture_url("ss-plugin-tls", &primary_host, primary_port),
    )
    .unwrap();
    assert_eq!(shadowsocks_obfs_tls.protocol, "shadowsocks");
    assert_eq!(shadowsocks_obfs_tls.net, "simple-obfs-tls");
    assert_eq!(
        shadowsocks_obfs_tls.executable_graph_value()["streamWrapper"],
        "simple-obfs-tls"
    );
    assert!(matches!(
        shadowsocks_obfs_tls.handler,
        ResidentProxyProtocolPlan::ShadowsocksSimpleObfsTlsTcp { .. }
    ));

    let shadowsocks_v2ray_plugin = build_resident_proxy_plan_for_node(
        config,
        "proxy".to_owned(),
        "ss_v2ray_plugin_live".to_owned(),
        shadowsocks_v2ray_plugin_tls_fixture_url("ss-plugin-v2ray", &primary_host, primary_port),
    )
    .unwrap();
    assert_eq!(shadowsocks_v2ray_plugin.protocol, "shadowsocks");
    assert_eq!(shadowsocks_v2ray_plugin.net, "v2ray-plugin-tls-websocket");
    assert_eq!(shadowsocks_v2ray_plugin.tls, "tls");
    assert_eq!(shadowsocks_v2ray_plugin.server_name, authority_host);
    assert_eq!(shadowsocks_v2ray_plugin.alpn, vec!["http/1.1".to_owned()]);
    assert!(matches!(
        shadowsocks_v2ray_plugin.handler,
        ResidentProxyProtocolPlan::ShadowsocksV2rayPluginTlsWsTcp { .. }
    ));

    let shadowsocks_2022_plugin = build_resident_proxy_plan_for_node(
        config,
        "proxy".to_owned(),
        "ss2022_plugin_live".to_owned(),
        shadowsocks_2022_simple_obfs_http_fixture_url("ss2022-plugin", &primary_host, primary_port),
    )
    .unwrap();
    assert_eq!(shadowsocks_2022_plugin.protocol, "shadowsocks");
    assert_eq!(shadowsocks_2022_plugin.net, "simple-obfs-http");
    assert_eq!(shadowsocks_2022_plugin.tls, "aead-2022");
    assert!(matches!(
        shadowsocks_2022_plugin.handler,
        ResidentProxyProtocolPlan::Shadowsocks2022SimpleObfsHttpTcp { .. }
    ));

    vec![
        socks,
        http,
        http_transport,
        https,
        shadowsocks,
        shadowsocks_2022,
        shadowsocks_plugin,
        shadowsocks_obfs_tls,
        shadowsocks_v2ray_plugin,
        shadowsocks_2022_plugin,
    ]
}
