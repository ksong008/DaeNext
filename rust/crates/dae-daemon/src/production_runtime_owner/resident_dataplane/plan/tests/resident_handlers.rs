#[test]
    fn resident_dataplane_plan_admits_shadowsocks_2022_cipher_family() {
        let config = parse_config(
            r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        }
        node {
        ss_live: 'ss://2022-blake3-aes-128-gcm:MTIzNDU2Nzg5MDEyMzQ1Ng==@217.116.171.227:25868'
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
        "#,
        );
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
                salt_len: 16,
                packet_nonce_len: 0,
                ..
            }
        ));
    }

    #[test]
    fn resident_dataplane_plan_admits_resident_tcp_handlers() {
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
        let socks = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "socks_live".to_owned(),
            "socks5://user:password@proxy.example.net:1080".to_owned(),
        )
        .unwrap();
        assert_eq!(socks.protocol, "socks5");
        assert_eq!(socks.server_host, "proxy.example.net");
        assert_eq!(socks.server_port, 1080);
        assert!(matches!(
            socks.handler,
            ResidentProxyProtocolPlan::Socks5Tcp { .. }
        ));

        let http = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "http_live".to_owned(),
            "http://user:password@proxy.example.net:80".to_owned(),
        )
        .unwrap();
        assert_eq!(http.protocol, "http-proxy");
        assert_eq!(http.server_host, "proxy.example.net");
        assert_eq!(http.server_port, 80);
        assert_eq!(http.tls, "none");
        assert!(matches!(
            http.handler,
            ResidentProxyProtocolPlan::HttpProxyTcp { .. }
        ));

        let https = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "https_live".to_owned(),
            "https://user:password@secure-proxy.example.net:443".to_owned(),
        )
        .unwrap();
        assert_eq!(https.protocol, "http-proxy");
        assert_eq!(https.server_host, "secure-proxy.example.net");
        assert_eq!(https.server_port, 443);
        assert_eq!(https.server_name, "secure-proxy.example.net");
        assert_eq!(https.tls, "tls");
        assert_eq!(https.alpn, vec!["h2".to_owned(), "http/1.1".to_owned()]);
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
            &config,
            "proxy".to_owned(),
            "http_transport_live".to_owned(),
            "http://user:password@proxy.example.net:80/relay?transport=1&host=front.example"
                .to_owned(),
        )
        .unwrap();
        assert_eq!(http_transport.protocol, "http-proxy");
        assert_eq!(http_transport.net, "http-transport");
        assert_eq!(http_transport.stream_host, "front.example");
        assert_eq!(http_transport.stream_path, "/relay");
        assert!(matches!(
            http_transport.handler,
            ResidentProxyProtocolPlan::HttpProxyTcp {
                transport: true,
                ref transport_host,
                ref transport_path,
                ..
            } if transport_host == "front.example" && transport_path == "/relay"
        ));

        let shadowsocks = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "ss_live".to_owned(),
            shadowsocks_fixture_url("ss", "203.0.113.10", 28446),
        )
        .unwrap();
        assert_eq!(shadowsocks.protocol, "shadowsocks");
        assert_eq!(shadowsocks.tls, "aead");
        assert!(matches!(
            shadowsocks.handler,
            ResidentProxyProtocolPlan::ShadowsocksAeadTcp { salt_len: 16, .. }
        ));

        let shadowsocks_2022 = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "ss2022_live".to_owned(),
            "ss://2022-blake3-aes-128-gcm:MTIzNDU2Nzg5MDEyMzQ1Ng==@203.0.113.10:28448".to_owned(),
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
            &config,
            "proxy".to_owned(),
            "ss_plugin_live".to_owned(),
            shadowsocks_plugin_fixture_url("ss-plugin", "203.0.113.10", 28447),
        )
        .unwrap();
        assert_eq!(shadowsocks_plugin.protocol, "shadowsocks");
        assert_eq!(shadowsocks_plugin.net, "simple-obfs-http");
        assert!(matches!(
            shadowsocks_plugin.handler,
            ResidentProxyProtocolPlan::ShadowsocksSimpleObfsHttpTcp { .. }
        ));

        let shadowsocks_obfs_tls = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "ss_obfs_tls_live".to_owned(),
            shadowsocks_simple_obfs_tls_fixture_url("ss-plugin-tls", "203.0.113.10", 28448),
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
            &config,
            "proxy".to_owned(),
            "ss_v2ray_plugin_live".to_owned(),
            shadowsocks_v2ray_plugin_tls_fixture_url("ss-plugin-v2ray", "203.0.113.10", 28449),
        )
        .unwrap();
        assert_eq!(shadowsocks_v2ray_plugin.protocol, "shadowsocks");
        assert_eq!(shadowsocks_v2ray_plugin.net, "v2ray-plugin-tls-websocket");
        assert_eq!(shadowsocks_v2ray_plugin.tls, "tls");
        assert_eq!(shadowsocks_v2ray_plugin.server_name, "front.example");
        assert_eq!(shadowsocks_v2ray_plugin.alpn, vec!["http/1.1".to_owned()]);
        assert!(matches!(
            shadowsocks_v2ray_plugin.handler,
            ResidentProxyProtocolPlan::ShadowsocksV2rayPluginTlsWsTcp { .. }
        ));

        let shadowsocks_2022_plugin = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "ss2022_plugin_live".to_owned(),
            shadowsocks_2022_simple_obfs_http_fixture_url("ss2022-plugin", "203.0.113.10", 28450),
        )
        .unwrap();
        assert_eq!(shadowsocks_2022_plugin.protocol, "shadowsocks");
        assert_eq!(shadowsocks_2022_plugin.net, "simple-obfs-http");
        assert_eq!(shadowsocks_2022_plugin.tls, "aead-2022");
        assert!(matches!(
            shadowsocks_2022_plugin.handler,
            ResidentProxyProtocolPlan::Shadowsocks2022SimpleObfsHttpTcp { .. }
        ));

        let trojan = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "trojan_live".to_owned(),
            trojan_fixture_url("trojan", "203.0.113.10", 28444),
        )
        .unwrap();
        assert_eq!(trojan.protocol, "trojan");
        assert_eq!(trojan.server_host, "203.0.113.10");
        assert_eq!(trojan.server_port, 28444);
        assert_eq!(trojan.server_name, "office.example");
        assert_eq!(trojan.tls, "tls");
        assert!(matches!(
            trojan.handler,
            ResidentProxyProtocolPlan::TrojanTcpTls { .. }
        ));

        let trojan_websocket = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "trojan_ws_live".to_owned(),
            trojan_websocket_fixture_url("trojan-ws", "203.0.113.10", 28456),
        )
        .unwrap();
        assert_eq!(trojan_websocket.protocol, "trojan");
        assert_eq!(trojan_websocket.server_host, "203.0.113.10");
        assert_eq!(trojan_websocket.server_port, 28456);
        assert_eq!(trojan_websocket.server_name, "office.example");
        assert_eq!(trojan_websocket.net, "websocket");
        assert_eq!(trojan_websocket.stream_host, "front.example");
        assert_eq!(trojan_websocket.stream_path, "/trojan");
        assert_eq!(trojan_websocket.tls, "tls");
        assert!(matches!(
            trojan_websocket.handler,
            ResidentProxyProtocolPlan::TrojanTcpTls { .. }
        ));
        let trojan_websocket_graph = trojan_websocket.executable_graph_value();
        assert_eq!(trojan_websocket_graph["protocolFraming"], "trojan");
        assert_eq!(trojan_websocket_graph["streamWrapper"], "websocket");
        assert_eq!(
            trojan_websocket_graph["runtimeComponents"]["streamWrapperFactory"]["provider"],
            "resident-websocket-binary-frame"
        );
        assert!(
            trojan_websocket_graph["streamWrapperEndpoint"]["hostHash"]
                .as_str()
                .unwrap()
                .starts_with("sha256:")
        );
        assert_eq!(
            trojan_websocket_graph["streamWrapperEndpoint"]["path"],
            "/trojan"
        );
        assert!(!trojan_websocket_graph.to_string().contains("front.example"));

        let trojan_httpupgrade = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "trojan_httpupgrade_live".to_owned(),
            trojan_httpupgrade_fixture_url("trojan-httpupgrade", "203.0.113.10", 28459),
        )
        .unwrap();
        assert_eq!(trojan_httpupgrade.protocol, "trojan");
        assert_eq!(trojan_httpupgrade.server_host, "203.0.113.10");
        assert_eq!(trojan_httpupgrade.server_port, 28459);
        assert_eq!(trojan_httpupgrade.server_name, "office.example");
        assert_eq!(trojan_httpupgrade.net, "httpupgrade");
        assert_eq!(trojan_httpupgrade.stream_host, "front.example");
        assert_eq!(trojan_httpupgrade.stream_path, "/trojan-upgrade");
        assert_eq!(trojan_httpupgrade.tls, "tls");
        assert!(matches!(
            trojan_httpupgrade.handler,
            ResidentProxyProtocolPlan::TrojanTcpTls { .. }
        ));
        let trojan_httpupgrade_graph = trojan_httpupgrade.executable_graph_value();
        assert_eq!(trojan_httpupgrade_graph["protocolFraming"], "trojan");
        assert_eq!(trojan_httpupgrade_graph["streamWrapper"], "httpupgrade");
        assert_eq!(
            trojan_httpupgrade_graph["runtimeComponents"]["streamWrapperFactory"]["provider"],
            "resident-http-upgrade-stream"
        );
        assert!(
            trojan_httpupgrade_graph["streamWrapperEndpoint"]["hostHash"]
                .as_str()
                .unwrap()
                .starts_with("sha256:")
        );
        assert_eq!(
            trojan_httpupgrade_graph["streamWrapperEndpoint"]["path"],
            "/trojan-upgrade"
        );
        assert!(
            !trojan_httpupgrade_graph
                .to_string()
                .contains("front.example")
        );

        let trojan_grpc = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "trojan_grpc_live".to_owned(),
            trojan_grpc_fixture_url("trojan-grpc", "203.0.113.10", 28461),
        )
        .unwrap();
        assert_eq!(trojan_grpc.protocol, "trojan");
        assert_eq!(trojan_grpc.server_host, "203.0.113.10");
        assert_eq!(trojan_grpc.server_port, 28461);
        assert_eq!(trojan_grpc.server_name, "office.example");
        assert_eq!(trojan_grpc.net, "grpc");
        assert_eq!(trojan_grpc.stream_host, "front.example");
        assert_eq!(trojan_grpc.stream_path, "TrojanGunService");
        assert_eq!(trojan_grpc.alpn, vec!["h2".to_owned()]);
        assert!(matches!(
            trojan_grpc.handler,
            ResidentProxyProtocolPlan::TrojanTcpTls { .. }
        ));
        let trojan_grpc_graph = trojan_grpc.executable_graph_value();
        assert_eq!(trojan_grpc_graph["protocolFraming"], "trojan");
        assert_eq!(trojan_grpc_graph["streamWrapper"], "grpc");
        assert_eq!(
            trojan_grpc_graph["runtimeComponents"]["streamWrapperFactory"]["provider"],
            "resident-grpc-h2-stream"
        );
        assert!(
            trojan_grpc_graph["streamWrapperEndpoint"]["hostHash"]
                .as_str()
                .unwrap()
                .starts_with("sha256:")
        );
        assert_eq!(
            trojan_grpc_graph["streamWrapperEndpoint"]["path"],
            "TrojanGunService"
        );
        assert!(!trojan_grpc_graph.to_string().contains("front.example"));

        let anytls = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "anytls_live".to_owned(),
            "anytls://password@secure-stream.example.net:443?sni=secure-stream.example.net"
                .to_owned(),
        )
        .unwrap();
        assert_eq!(anytls.protocol, "anytls");
        assert_eq!(anytls.server_host, "secure-stream.example.net");
        assert_eq!(anytls.server_port, 443);
        assert_eq!(anytls.server_name, "secure-stream.example.net");
        assert_eq!(anytls.tls, "tls");
        assert!(matches!(
            anytls.handler,
            ResidentProxyProtocolPlan::AnyTlsTcpTls { .. }
        ));

        let vmess = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "vmess_live".to_owned(),
            vmess_fixture_url("vmess", "203.0.113.10", 28452, "tcp", "", "", ""),
        )
        .unwrap();
        assert_eq!(vmess.protocol, "vmess");
        assert_eq!(vmess.server_host, "203.0.113.10");
        assert_eq!(vmess.server_port, 28452);
        assert_eq!(vmess.tls, "none");
        assert!(matches!(
            vmess.handler,
            ResidentProxyProtocolPlan::VmessAeadTcp { .. }
        ));

        let vmess_websocket = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "vmess_ws_live".to_owned(),
            vmess_fixture_url(
                "vmess-ws",
                "203.0.113.10",
                28454,
                "ws",
                "front.example",
                "/vmess",
                "",
            ),
        )
        .unwrap();
        assert_eq!(vmess_websocket.protocol, "vmess");
        assert_eq!(vmess_websocket.net, "websocket");
        assert_eq!(vmess_websocket.stream_host, "front.example");
        assert_eq!(vmess_websocket.stream_path, "/vmess");
        assert_eq!(vmess_websocket.tls, "none");
        assert!(matches!(
            vmess_websocket.handler,
            ResidentProxyProtocolPlan::VmessAeadTcp { .. }
        ));
        let vmess_websocket_graph = vmess_websocket.executable_graph_value();
        assert_eq!(vmess_websocket_graph["streamWrapper"], "websocket");
        assert_eq!(vmess_websocket_graph["securityUnderlay"], "none");
        assert_eq!(
            vmess_websocket_graph["runtimeComponents"]["streamWrapperFactory"]["provider"],
            "resident-websocket-binary-frame"
        );
        assert!(
            vmess_websocket_graph["streamWrapperEndpoint"]["hostHash"]
                .as_str()
                .unwrap()
                .starts_with("sha256:")
        );
        assert!(!vmess_websocket_graph.to_string().contains("front.example"));

        let vmess_websocket_tls = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "vmess_ws_tls_live".to_owned(),
            vmess_fixture_url_with_sni(
                "203.0.113.10",
                28454,
                "ws",
                "front.example",
                "/vmess",
                "tls",
                "office.example",
            ),
        )
        .unwrap();
        assert_eq!(vmess_websocket_tls.protocol, "vmess");
        assert_eq!(vmess_websocket_tls.net, "websocket");
        assert_eq!(vmess_websocket_tls.server_name, "office.example");
        assert_eq!(vmess_websocket_tls.stream_host, "front.example");
        assert_eq!(vmess_websocket_tls.stream_path, "/vmess");
        assert_eq!(vmess_websocket_tls.tls, "tls");
        assert!(matches!(
            vmess_websocket_tls.handler,
            ResidentProxyProtocolPlan::VmessAeadTcp { .. }
        ));
        let vmess_websocket_tls_graph = vmess_websocket_tls.executable_graph_value();
        assert_eq!(vmess_websocket_tls_graph["streamWrapper"], "websocket");
        assert_eq!(
            vmess_websocket_tls_graph["securityUnderlay"],
            "standard-tls"
        );
        assert_eq!(
            vmess_websocket_tls_graph["runtimeComponents"]["streamWrapperFactory"]["provider"],
            "resident-websocket-binary-frame"
        );
        assert_eq!(
            vmess_websocket_tls_graph["runtimeComponents"]["underlayFactory"]["provider"],
            "rustls"
        );

        let vmess_httpupgrade = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "vmess_httpupgrade_live".to_owned(),
            vmess_fixture_url(
                "vmess-httpupgrade",
                "203.0.113.10",
                28460,
                "httpupgrade",
                "front.example",
                "/vmess-upgrade",
                "",
            ),
        )
        .unwrap();
        assert_eq!(vmess_httpupgrade.protocol, "vmess");
        assert_eq!(vmess_httpupgrade.net, "httpupgrade");
        assert_eq!(vmess_httpupgrade.stream_host, "front.example");
        assert_eq!(vmess_httpupgrade.stream_path, "/vmess-upgrade");
        assert_eq!(vmess_httpupgrade.tls, "none");
        assert!(matches!(
            vmess_httpupgrade.handler,
            ResidentProxyProtocolPlan::VmessAeadTcp { .. }
        ));
        let vmess_httpupgrade_graph = vmess_httpupgrade.executable_graph_value();
        assert_eq!(vmess_httpupgrade_graph["streamWrapper"], "httpupgrade");
        assert_eq!(vmess_httpupgrade_graph["securityUnderlay"], "none");
        assert_eq!(
            vmess_httpupgrade_graph["runtimeComponents"]["streamWrapperFactory"]["provider"],
            "resident-http-upgrade-stream"
        );
        assert!(
            vmess_httpupgrade_graph["streamWrapperEndpoint"]["hostHash"]
                .as_str()
                .unwrap()
                .starts_with("sha256:")
        );
        assert!(
            !vmess_httpupgrade_graph
                .to_string()
                .contains("front.example")
        );

        let vmess_httpupgrade_tls = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "vmess_httpupgrade_tls_live".to_owned(),
            vmess_fixture_url_with_sni(
                "203.0.113.10",
                28460,
                "httpupgrade",
                "front.example",
                "/vmess-upgrade",
                "tls",
                "office.example",
            ),
        )
        .unwrap();
        assert_eq!(vmess_httpupgrade_tls.protocol, "vmess");
        assert_eq!(vmess_httpupgrade_tls.net, "httpupgrade");
        assert_eq!(vmess_httpupgrade_tls.server_name, "office.example");
        assert_eq!(vmess_httpupgrade_tls.stream_host, "front.example");
        assert_eq!(vmess_httpupgrade_tls.stream_path, "/vmess-upgrade");
        assert_eq!(vmess_httpupgrade_tls.tls, "tls");
        assert!(matches!(
            vmess_httpupgrade_tls.handler,
            ResidentProxyProtocolPlan::VmessAeadTcp { .. }
        ));
        let vmess_httpupgrade_tls_graph = vmess_httpupgrade_tls.executable_graph_value();
        assert_eq!(vmess_httpupgrade_tls_graph["streamWrapper"], "httpupgrade");
        assert_eq!(
            vmess_httpupgrade_tls_graph["securityUnderlay"],
            "standard-tls"
        );
        assert_eq!(
            vmess_httpupgrade_tls_graph["runtimeComponents"]["streamWrapperFactory"]["provider"],
            "resident-http-upgrade-stream"
        );
        assert_eq!(
            vmess_httpupgrade_tls_graph["runtimeComponents"]["underlayFactory"]["provider"],
            "rustls"
        );

        let vmess_grpc = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "vmess_grpc_live".to_owned(),
            vmess_fixture_url(
                "vmess-grpc",
                "203.0.113.10",
                28462,
                "grpc",
                "front.example",
                "GunService",
                "tls",
            ),
        )
        .unwrap();
        assert_eq!(vmess_grpc.protocol, "vmess");
        assert_eq!(vmess_grpc.net, "grpc");
        assert_eq!(vmess_grpc.server_host, "203.0.113.10");
        assert_eq!(vmess_grpc.server_port, 28462);
        assert_eq!(vmess_grpc.server_name, "203.0.113.10");
        assert_eq!(vmess_grpc.stream_host, "front.example");
        assert_eq!(vmess_grpc.stream_path, "GunService");
        assert_eq!(vmess_grpc.tls, "tls");
        assert_eq!(vmess_grpc.alpn, vec!["h2".to_owned()]);
        assert!(matches!(
            vmess_grpc.handler,
            ResidentProxyProtocolPlan::VmessAeadTcp { .. }
        ));
        let vmess_grpc_graph = vmess_grpc.executable_graph_value();
        assert_eq!(vmess_grpc_graph["streamWrapper"], "grpc");
        assert_eq!(vmess_grpc_graph["securityUnderlay"], "standard-tls");
        assert_eq!(
            vmess_grpc_graph["runtimeComponents"]["streamWrapperFactory"]["provider"],
            "resident-grpc-h2-stream"
        );
        assert!(
            vmess_grpc_graph["streamWrapperEndpoint"]["hostHash"]
                .as_str()
                .unwrap()
                .starts_with("sha256:")
        );
        assert!(!vmess_grpc_graph.to_string().contains("front.example"));

        let vless_websocket = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "vless_ws_live".to_owned(),
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
        )
        .unwrap();
        assert_eq!(vless_websocket.protocol, "vless");
        assert_eq!(vless_websocket.server_host, "203.0.113.10");
        assert_eq!(vless_websocket.server_port, 28443);
        assert_eq!(vless_websocket.server_name, "office.example");
        assert_eq!(vless_websocket.net, "websocket");
        assert_eq!(vless_websocket.stream_host, "front.example");
        assert_eq!(vless_websocket.stream_path, "/ws");
        assert_eq!(vless_websocket.flow, "");
        assert!(matches!(
            vless_websocket.handler,
            ResidentProxyProtocolPlan::VlessVisionTcpTls { .. }
        ));
        let vless_websocket_graph = vless_websocket.executable_graph_value();
        assert_eq!(vless_websocket_graph["streamWrapper"], "websocket");
        assert_eq!(
            vless_websocket_graph["runtimeComponents"]["streamWrapperFactory"]["provider"],
            "resident-websocket-binary-frame"
        );
        assert!(
            vless_websocket_graph["streamWrapperEndpoint"]["hostHash"]
                .as_str()
                .unwrap()
                .starts_with("sha256:")
        );
        assert_eq!(
            vless_websocket_graph["streamWrapperEndpoint"]["path"],
            "/ws"
        );
        assert!(!vless_websocket_graph.to_string().contains("front.example"));

        let vless_httpupgrade = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "vless_httpupgrade_live".to_owned(),
            vless_fixture_url(
                "vless-httpupgrade",
                "203.0.113.10",
                28461,
                "httpupgrade",
                "front.example",
                "/vless-upgrade",
                "office.example",
                "",
                "",
            ),
        )
        .unwrap();
        assert_eq!(vless_httpupgrade.protocol, "vless");
        assert_eq!(vless_httpupgrade.server_host, "203.0.113.10");
        assert_eq!(vless_httpupgrade.server_port, 28461);
        assert_eq!(vless_httpupgrade.server_name, "office.example");
        assert_eq!(vless_httpupgrade.net, "httpupgrade");
        assert_eq!(vless_httpupgrade.stream_host, "front.example");
        assert_eq!(vless_httpupgrade.stream_path, "/vless-upgrade");
        assert_eq!(vless_httpupgrade.flow, "");
        assert!(matches!(
            vless_httpupgrade.handler,
            ResidentProxyProtocolPlan::VlessVisionTcpTls { .. }
        ));
        let vless_httpupgrade_graph = vless_httpupgrade.executable_graph_value();
        assert_eq!(vless_httpupgrade_graph["streamWrapper"], "httpupgrade");
        assert_eq!(
            vless_httpupgrade_graph["runtimeComponents"]["streamWrapperFactory"]["provider"],
            "resident-http-upgrade-stream"
        );
        assert!(
            vless_httpupgrade_graph["streamWrapperEndpoint"]["hostHash"]
                .as_str()
                .unwrap()
                .starts_with("sha256:")
        );
        assert_eq!(
            vless_httpupgrade_graph["streamWrapperEndpoint"]["path"],
            "/vless-upgrade"
        );
        assert!(
            !vless_httpupgrade_graph
                .to_string()
                .contains("front.example")
        );

        let hysteria2 = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "hy2_live".to_owned(),
            hysteria2_fixture_url("hy2", "203.0.113.10", 28453),
        )
        .unwrap();
        assert_eq!(hysteria2.protocol, "hysteria2");
        assert_eq!(hysteria2.server_host, "203.0.113.10");
        assert_eq!(hysteria2.server_port, 28453);
        assert_eq!(hysteria2.server_name, "office.example");
        assert_eq!(hysteria2.net, "udp");
        assert_eq!(hysteria2.tls, "quic");
        assert!(matches!(
            hysteria2.handler,
            ResidentProxyProtocolPlan::Hysteria2QuicTcp { .. }
        ));

        let hysteria2_hopping = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "hy2_hopping_live".to_owned(),
            hysteria2_fixture_url_with_pin("hy2", "203.0.113.10:28453,28454-28455", "AA-BB-CC"),
        )
        .unwrap();
        assert_eq!(hysteria2_hopping.protocol, "hysteria2");
        assert_eq!(hysteria2_hopping.server_host, "203.0.113.10");
        assert_eq!(hysteria2_hopping.server_port, 28453);
        assert!(matches!(
            hysteria2_hopping.handler,
            ResidentProxyProtocolPlan::Hysteria2QuicTcp {
                ref port_hop_ports,
                ..
            } if port_hop_ports == &vec![28453, 28454, 28455]
        ));

        let tuic = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "tuic_live".to_owned(),
            tuic_fixture_url("tuic", "203.0.113.10", 28454, true),
        )
        .unwrap();
        assert_eq!(tuic.protocol, "tuic");
        assert_eq!(tuic.server_host, "203.0.113.10");
        assert_eq!(tuic.server_port, 28454);
        assert_eq!(tuic.server_name, "office.example");
        assert_eq!(tuic.net, "udp");
        assert_eq!(tuic.tls, "quic");
        assert!(tuic.allow_insecure);
        assert!(matches!(
            tuic.handler,
            ResidentProxyProtocolPlan::TuicQuicTcp {
                allow_insecure: true,
                ..
            }
        ));

        let tuic_verified = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "tuic_verified_live".to_owned(),
            tuic_fixture_url("tuic", "203.0.113.10", 28454, false),
        )
        .unwrap();
        assert_eq!(tuic_verified.protocol, "tuic");
        assert_eq!(tuic_verified.server_name, "office.example");
        assert_eq!(tuic_verified.tls, "quic");
        assert!(!tuic_verified.allow_insecure);
        assert!(matches!(
            tuic_verified.handler,
            ResidentProxyProtocolPlan::TuicQuicTcp {
                allow_insecure: false,
                ..
            }
        ));
        assert_eq!(
            tuic_verified.executable_graph_value()["runtimeComponents"]["underlayFactory"]["verificationPolicy"],
            "system-roots"
        );

        let juicity = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "juicity_live".to_owned(),
            juicity_fixture_url("juicity", "203.0.113.10", 28455, true),
        )
        .unwrap();
        assert_eq!(juicity.protocol, "juicity");
        assert_eq!(juicity.server_host, "203.0.113.10");
        assert_eq!(juicity.server_port, 28455);
        assert_eq!(juicity.server_name, "office.example");
        assert_eq!(juicity.net, "udp");
        assert_eq!(juicity.tls, "quic");
        assert!(matches!(
            juicity.handler,
            ResidentProxyProtocolPlan::JuicityQuicTcp { .. }
        ));

        for proxy in [
            &socks,
            &http,
            &https,
            &shadowsocks,
            &shadowsocks_plugin,
            &trojan,
            &trojan_websocket,
            &trojan_httpupgrade,
            &anytls,
            &vmess,
            &vmess_websocket,
            &vmess_httpupgrade,
            &vless_websocket,
            &vless_httpupgrade,
            &hysteria2,
            &tuic,
            &juicity,
        ] {
            let graph = proxy.executable_graph_value();
            assert_eq!(graph["schemaVersion"], 1);
            assert!(
                graph["graphId"]
                    .as_str()
                    .unwrap()
                    .starts_with("resident-graph:")
            );
            assert_eq!(graph["admission"]["status"], "admitted");
            assert_eq!(graph["chain"]["flattened"], false);
            assert_eq!(
                graph["runtimeComponents"]["underlayFactory"]["status"],
                "admitted"
            );
            assert_eq!(
                graph["runtimeComponents"]["streamWrapperFactory"]["status"],
                "admitted"
            );
            assert_eq!(
                graph["runtimeComponents"]["chainExecutor"]["executor"],
                "single-resident-graph"
            );
            assert_eq!(
                graph["runtimeComponents"]["generationCache"]["cacheScope"],
                "graph-and-reload-generation"
            );
            assert_eq!(
                graph["runtimeComponents"]["generationCache"]["materialized"],
                false
            );
            assert!(graph["runtimeComponents"]["generationCache"]["reloadGeneration"].is_null());
            let materialized = proxy.executable_graph_value_for_reload_generation(42);
            assert_eq!(
                materialized["runtimeComponents"]["generationCache"]["reloadGeneration"],
                42
            );
            assert_eq!(
                materialized["runtimeComponents"]["generationCache"]["materialized"],
                true
            );
            assert_eq!(
                materialized["runtimeComponents"]["probeExecutor"]["reloadGeneration"],
                42
            );
            assert_eq!(
                graph["runtimeComponents"]["packetSessionManager"]["manager"],
                "bounded-resident-packet-session"
            );
            assert_eq!(
                graph["runtimeComponents"]["probeExecutor"]["executor"],
                "resident-executable-graph"
            );
            assert!(
                graph["linkIdentity"]["linkHash"]
                    .as_str()
                    .unwrap()
                    .starts_with("sha256:")
            );
            let graph_text = graph.to_string();
            for secret in ["user:password", ":password@", "auth-token"] {
                assert!(
                    !graph_text.contains(secret),
                    "graph leaked raw credential-bearing link: {graph}"
                );
            }
        }
    }
