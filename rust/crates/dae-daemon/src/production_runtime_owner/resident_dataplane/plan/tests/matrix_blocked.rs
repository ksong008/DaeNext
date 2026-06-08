#[test]
    fn resident_dataplane_plan_admits_nested_chain_without_flattening() {
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
        let proxy = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "chained_live".to_owned(),
            "socks5://user:password@proxy-a.example.net:1080 -> http://user:password@proxy-b.example.net:80"
                .to_owned(),
        )
        .unwrap();
        assert!(proxy.chain_parent.is_some());
        assert_eq!(proxy.server_host, "proxy-b.example.net");
        let graph = proxy.executable_graph_value();
        assert_eq!(graph["chain"]["mode"], "parent-proxy");
        assert_eq!(graph["chain"]["parentCount"], 1);
        assert_eq!(graph["chain"]["flattened"], false);
        assert_eq!(
            graph["runtimeComponents"]["chainExecutor"]["executor"],
            "resident-parent-connect-chain"
        );

        let err = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "too_deep".to_owned(),
            "socks5://user:password@proxy-a.example.net:1080 -> http://user:password@proxy-b.example.net:80 -> http://user:password@proxy-c.example.net:80"
                .to_owned(),
        )
        .unwrap_err();
        assert!(err.contains("admits two-node chains only"));
    }

    #[test]
    fn resident_dataplane_plan_keeps_deferred_unsupported_shapes_blocked() {
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
        let https_insecure = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "https_insecure".to_owned(),
            "https://user:password@secure-proxy.example.net:443?allowInsecure=1".to_owned(),
        )
        .unwrap_err();
        assert!(https_insecure.contains("does not admit allow_insecure"));

        let https_utls = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "https_utls".to_owned(),
            "https://user:password@secure-proxy.example.net:443?utlsImitate=chrome".to_owned(),
        )
        .unwrap_err();
        assert!(https_utls.contains("does not admit fingerprint/utls imitation"));

        let plugin = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "ss_plugin".to_owned(),
            shadowsocks_unsupported_plugin_fixture_url("ss-plugin", "203.0.113.10", 28446),
        )
        .unwrap_err();
        assert!(plugin.contains("admits simple-obfs http/tls and v2ray-plugin tls websocket only"));

        let vmess_grpc = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "vmess_grpc".to_owned(),
            vmess_fixture_url(
                "vmess-grpc",
                "203.0.113.10",
                28458,
                "grpc",
                "",
                "grpc-service",
                "",
            ),
        )
        .unwrap_err();
        assert!(vmess_grpc.contains(
            "VMess grpc handler admits TLS HTTP/2 endpoints only for node vmess_grpc; got tls=none"
        ));

        let trojan_go_inner_encryption = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "trojan_go_inner_encryption".to_owned(),
            "trojan-go://password@secure-stream.example.net:443?type=ws&sni=secure-stream.example.net&encryption=ss%3Baes-128-gcm%3Apass".to_owned(),
        )
        .unwrap();
        assert_eq!(trojan_go_inner_encryption.protocol, "trojan");
        assert_eq!(trojan_go_inner_encryption.net, "websocket");
        assert!(matches!(
            trojan_go_inner_encryption.handler,
            ResidentProxyProtocolPlan::TrojanInnerShadowsocksTcpTls { .. }
        ));

        let anytls_insecure = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "anytls_insecure".to_owned(),
            "anytls://password@secure-stream.example.net:443?insecure=1&sni=secure-stream.example.net"
                .to_owned(),
        )
        .unwrap_err();
        assert!(anytls_insecure.contains("does not admit AnyTLS insecure mode"));

        let vmess_tls = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "vmess_tls".to_owned(),
            vmess_fixture_url("vmess-tls", "203.0.113.10", 28452, "tcp", "", "", "tls"),
        )
        .unwrap_err();
        assert!(vmess_tls.contains("admits only plain VMess TCP endpoints"));

        let hy2_no_pin = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "hy2_no_pin".to_owned(),
            hysteria2_fixture_url_with_pin("hy2", "203.0.113.10:28453", ""),
        )
        .unwrap_err();
        assert!(hy2_no_pin.contains("requires Hysteria2 pinSHA256"));

        let hy2_hopping = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "hy2_hopping".to_owned(),
            hysteria2_fixture_url_with_pin("hy2", "example.com:443,8443-8445", "AA-BB-CC"),
        )
        .unwrap();
        assert_eq!(hy2_hopping.server_port, 443);
        assert!(matches!(
            hy2_hopping.handler,
            ResidentProxyProtocolPlan::Hysteria2QuicTcp {
                ref port_hop_ports,
                ..
            } if port_hop_ports == &vec![443, 8443, 8444, 8445]
        ));

        let tuic_verified = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "tuic_verified".to_owned(),
            tuic_fixture_url("tuic", "203.0.113.10", 28454, false),
        )
        .unwrap();
        assert!(!tuic_verified.allow_insecure);

        let juicity_without_verification = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "juicity_without_verification".to_owned(),
            juicity_fixture_url("juicity", "203.0.113.10", 28455, false),
        )
        .unwrap_err();
        assert!(
            juicity_without_verification
                .contains("requires Juicity allow_insecure or pinned_certchain_sha256")
        );
    }

    #[test]
    fn resident_dataplane_plan_builds_proxy_by_outbound_index() {
        let config = parse_config(
            r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        dial_mode: domain++
        }
        node {
        hk: 'vless://01234567-89ab-cdef-0123-456789abcdef@156.246.90.2:443?security=tls&type=tcp&sni=hk.example&flow=xtls-rprx-vision&alpn=h2,http/1.1'
        us: 'vless://01234567-89ab-cdef-0123-456789abcdef@203.0.113.2:443?security=tls&type=tcp&sni=us.example&flow=xtls-rprx-vision&alpn=h2,http/1.1'
        }
        group {
        proxy {
            filter: name(hk)
            policy: fixed(0)
        }
        openai {
            filter: name(us)
            policy: fixed(0)
        }
        }
        routing {
        domain(suffix: googleapis.com) -> openai
        fallback: proxy
        }
        "#,
        );
        let plan = build_resident_dataplane_plan(&config).unwrap();
        assert!(plan.enabled);
        assert_eq!(plan.tcp_dial_mode, TcpDialMode::DomainPlusPlus);
        let proxy = plan
            .proxies
            .get(&2)
            .unwrap()
            .default_proxy_snapshot()
            .unwrap();
        let openai = plan
            .proxies
            .get(&3)
            .unwrap()
            .default_proxy_snapshot()
            .unwrap();
        assert_eq!(proxy.group_name, "proxy");
        assert_eq!(proxy.node_tag, "hk");
        assert_eq!(openai.group_name, "openai");
        assert_eq!(openai.node_tag, "us");
    }

    #[test]
    fn resident_dataplane_plan_rejects_vless_without_vision_flow() {
        let config = parse_config(
            r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        }
        node {
        vless_live: 'vless://01234567-89ab-cdef-0123-456789abcdef@156.246.90.2:443?security=tls&type=tcp&sni=office.example&alpn=h2,http/1.1'
        }
        group {
        proxy {
            filter: name(vless_live)
            policy: fixed(0)
        }
        }
        routing {
        l4proto(tcp) && dport(443) -> proxy
        fallback: direct
        }
        "#,
        );
        let err = build_resident_dataplane_plan(&config).unwrap_err();
        assert!(err.contains("admits tcp flow=xtls-rprx-vision"));
        assert!(err.contains("resident shape remains fail-closed"));
    }

    #[test]
    fn resident_dataplane_plan_admits_vless_xhttp_h2_packet_up() {
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
        let proxy = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "standard_import".to_owned(),
            vless_xhttp_parser_fixture_url("auto", "h2", ""),
        )
        .unwrap();

        assert_eq!(proxy.protocol, "vless");
        assert_eq!(proxy.net, "xhttp");
        assert_eq!(proxy.alpn, vec!["h2".to_owned()]);
        assert_eq!(proxy.stream_host, "edge.transport.invalid");
        assert_eq!(proxy.stream_path, "/resource/?ed=2048");
        let graph = proxy.executable_graph_value();
        assert_eq!(graph["streamWrapper"], "xhttp");
        assert_eq!(
            graph["runtimeComponents"]["streamWrapperFactory"]["provider"],
            "resident-xhttp-h2-packet-up"
        );
    }

    #[test]
    fn resident_dataplane_plan_rejects_unimplemented_vless_xhttp_shapes() {
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
        for (tag, link, expected) in [
            (
                "xhttp_h3",
                vless_xhttp_parser_fixture_url("packet-up", "h3", ""),
                "admits HTTP/2 packet-up only",
            ),
            (
                "xhttp_stream_up",
                vless_xhttp_parser_fixture_url("stream-up", "h2", ""),
                "admits packet-up mode only",
            ),
            (
                "xhttp_extra",
                vless_xhttp_parser_fixture_url(
                    "packet-up",
                    "h2",
                    r#"{"xmux":{"maxConnections":2}}"#,
                ),
                "admits default extra settings only",
            ),
        ] {
            let err = build_resident_proxy_plan_for_node(
                &config,
                "proxy".to_owned(),
                tag.to_owned(),
                link,
            )
            .unwrap_err();
            assert!(
                err.contains(expected),
                "{tag} rejected with unexpected error: {err}"
            );
        }
    }
