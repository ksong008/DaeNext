use super::*;
#[test]
pub(super) fn resident_dataplane_plan_admits_nested_chain_without_flattening() {
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
        two_node_chain_fixture_url(),
    )
    .unwrap();
    assert!(proxy.chain_parent.is_some());
    assert_eq!(proxy.server_host, fixture_host(FixtureEndpoint::Secondary));
    let graph = proxy.executable_graph_value();
    assert_eq!(graph["chain"]["mode"], "parent-proxy");
    assert_eq!(graph["chain"]["parentCount"], 1);
    assert_eq!(graph["chain"]["flattened"], false);
    assert_eq!(
        graph["runtimeComponents"]["chainExecutor"]["executor"],
        "resident-parent-connect-chain"
    );

    let deep = build_resident_proxy_plan_for_node(
        &config,
        "proxy".to_owned(),
        "too_deep".to_owned(),
        too_deep_chain_fixture_url(),
    )
    .unwrap();
    assert_eq!(deep.server_host, fixture_host(FixtureEndpoint::Tertiary));
    let first_parent = deep.chain_parent.as_ref().unwrap();
    assert_eq!(
        first_parent.server_host,
        fixture_host(FixtureEndpoint::Primary)
    );
    let second_parent = first_parent.chain_parent.as_ref().unwrap();
    assert_eq!(
        second_parent.server_host,
        fixture_host(FixtureEndpoint::Secondary)
    );
    let graph = deep.executable_graph_value();
    assert_eq!(graph["chain"]["mode"], "parent-proxy");
    assert_eq!(graph["chain"]["parentCount"], 2);
    assert_eq!(graph["chain"]["flattened"], false);

    let ssr_cipher = shadowsocksr_stream_cipher_specs()
        .first()
        .expect("ShadowsocksR stream cipher table must not be empty")
        .cipher;
    let ssr_chain = format!(
        "{} -> {}",
        socks5_fixture_url(
            &fixture_host(FixtureEndpoint::Primary),
            fixture_port(FixtureEndpoint::Primary.slot())
        ),
        shadowsocksr_http_simple_fixture_url(ssr_cipher)
    );
    let ssr_child = build_resident_proxy_plan_for_node(
        &config,
        "proxy".to_owned(),
        "ssr_child_chain".to_owned(),
        ssr_chain,
    )
    .unwrap();
    assert_eq!(ssr_child.protocol, "shadowsocksr");
    assert!(ssr_child.chain_parent.is_some());
}

#[test]
pub(super) fn resident_dataplane_plan_keeps_deferred_unsupported_shapes_blocked() {
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
    let primary_host = fixture_host(FixtureEndpoint::Primary);
    let admitted_secure_underlays = vec![
        (
            "https_insecure",
            https_proxy_insecure_fixture_url(&primary_host, fixture_port(1)),
            "insecure-tls",
            "rustls",
            true,
        ),
        (
            "https_utls",
            https_proxy_utls_fixture_url(&primary_host, fixture_port(1)),
            "fingerprint-aware-tls",
            "boringssl",
            false,
        ),
        (
            "anytls_insecure",
            anytls_insecure_fixture_url(&primary_host, fixture_port(1)),
            "insecure-tls",
            "rustls",
            true,
        ),
        (
            "trojan_insecure",
            trojan_insecure_fixture_url("trojan-insecure", &primary_host, fixture_port(1)),
            "insecure-tls",
            "rustls",
            true,
        ),
        (
            "trojan_type_tcp",
            trojan_tcp_type_fixture_url("trojan-tcp", &primary_host, fixture_port(1)),
            "standard-tls",
            "rustls",
            false,
        ),
        (
            "vless_insecure",
            vless_vision_insecure_fixture_url(""),
            "insecure-tls",
            "rustls",
            true,
        ),
        (
            "vless_reality",
            vless_reality_fixture_url(),
            "reality",
            "rustls-reality",
            false,
        ),
        (
            "vless_reality_insecure",
            vless_reality_insecure_fixture_url(),
            "reality",
            "rustls-reality",
            true,
        ),
    ];
    for (tag, link, security_underlay, provider, allow_insecure) in admitted_secure_underlays {
        let proxy = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            tag.to_owned(),
            link.to_owned(),
        )
        .unwrap();
        let graph = proxy.executable_graph_value();
        assert_eq!(graph["securityUnderlay"], security_underlay, "{tag}");
        assert_eq!(
            graph["runtimeComponents"]["underlayFactory"]["provider"], provider,
            "{tag}"
        );
        assert_eq!(
            graph["runtimeComponents"]["underlayFactory"]["verificationPolicy"],
            if allow_insecure {
                "explicit-insecure"
            } else {
                "system-roots"
            },
            "{tag}"
        );
        assert_eq!(
            graph["runtimeComponents"]["underlayFactory"]["allowInsecure"], allow_insecure,
            "{tag}"
        );
        assert_eq!(proxy.allow_insecure, allow_insecure, "{tag}");
    }

    let trojan_type_tcp = build_resident_proxy_plan_for_node(
        &config,
        "proxy".to_owned(),
        "trojan_type_tcp_alpn".to_owned(),
        trojan_tcp_type_fixture_url("trojan-tcp", &primary_host, fixture_port(1)),
    )
    .unwrap();
    assert_eq!(
        trojan_type_tcp.alpn,
        vec!["h3".to_owned(), "h2".to_owned(), "http/1.1".to_owned()]
    );
    assert_eq!(
        trojan_type_tcp.executable_graph_value()["runtimeComponents"]["underlayFactory"]["alpn"],
        serde_json::json!(["h3", "h2", "http/1.1"])
    );

    let mux_proxy = build_resident_proxy_plan_for_node(
        &config,
        "proxy".to_owned(),
        "shared_transport_mux".to_owned(),
        vless_mux_fixture_url(),
    )
    .unwrap();
    assert!(matches!(
        mux_proxy.handler,
        ResidentProxyProtocolPlan::VlessMuxTcpTls { .. }
    ));
    let mux_graph = mux_proxy.executable_graph_value();
    assert_eq!(mux_graph["streamWrapper"], "mux");
    assert_eq!(mux_graph["packetSemantics"], "multiplexed-stream");
    assert_eq!(
        mux_graph["runtimeComponents"]["streamWrapperFactory"]["provider"],
        "resident-shared-mux-stream"
    );

    let tls_fragment_config = parse_config(
        r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        tls_fragment: true
        tls_fragment_length: 1-4
        tls_fragment_interval: 1-1
        }
        routing {
        fallback: direct
        }
        "#,
    );
    let tls_fragment_proxy = build_resident_proxy_plan_for_node(
        &tls_fragment_config,
        "proxy".to_owned(),
        "tls_fragment".to_owned(),
        https_proxy_fixture_url(&primary_host, fixture_port(1)),
    )
    .unwrap();
    assert!(tls_fragment_proxy.tls_fragment.is_some());
    let graph = tls_fragment_proxy.executable_graph_value();
    assert_eq!(graph["securityUnderlay"], "tls-fragment");
    assert_eq!(
        graph["runtimeComponents"]["underlayFactory"]["provider"],
        "rustls"
    );

    let plugin = build_resident_proxy_plan_for_node(
        &config,
        "proxy".to_owned(),
        "ss_plugin".to_owned(),
        shadowsocks_unsupported_plugin_fixture_url("ss-plugin", &primary_host, fixture_port(1)),
    )
    .unwrap_err();
    assert!(plugin.contains("admits simple-obfs http/tls and v2ray-plugin tls websocket only"));

    let vmess_grpc = build_resident_proxy_plan_for_node(
        &config,
        "proxy".to_owned(),
        "vmess_grpc".to_owned(),
        vmess_fixture_url(
            "vmess-grpc",
            &primary_host,
            fixture_port(2),
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

    let inner_cipher = aead_cipher_specs()
        .first()
        .expect("AEAD cipher table must not be empty")
        .cipher;
    let trojan_inner_encryption = build_resident_proxy_plan_for_node(
        &config,
        "proxy".to_owned(),
        "trojan_inner_encryption".to_owned(),
        trojan_inner_shadowsocks_fixture_url(inner_cipher),
    )
    .unwrap();
    assert_eq!(trojan_inner_encryption.protocol, "trojan");
    assert_eq!(trojan_inner_encryption.net, "websocket");
    assert!(matches!(
        trojan_inner_encryption.handler,
        ResidentProxyProtocolPlan::TrojanInnerShadowsocksTcpTls { .. }
    ));

    let vmess_tls = build_resident_proxy_plan_for_node(
        &config,
        "proxy".to_owned(),
        "vmess_tls".to_owned(),
        vmess_fixture_url(
            "vmess-tls",
            &primary_host,
            fixture_port(3),
            "tcp",
            "",
            "",
            "tls",
        ),
    )
    .unwrap();
    assert_eq!(vmess_tls.protocol, "vmess");
    assert_eq!(vmess_tls.net, "tcp");
    assert_eq!(vmess_tls.tls, "tls");
    assert_eq!(
        vmess_tls.executable_graph_value()["runtimeComponents"]["underlayFactory"]["verificationPolicy"],
        "system-roots"
    );

    let hy2_no_pin = build_resident_proxy_plan_for_node(
        &config,
        "proxy".to_owned(),
        "hy2_no_pin".to_owned(),
        hysteria2_fixture_url_with_pin("hy2", &fixture_hop_server(fixture_port(4), ""), ""),
    )
    .unwrap_err();
    assert!(hy2_no_pin.contains("requires Hysteria2 pinSHA256"));

    let hy2_hopping = build_resident_proxy_plan_for_node(
        &config,
        "proxy".to_owned(),
        "hy2_hopping".to_owned(),
        hysteria2_fixture_url_with_pin(
            "hy2",
            &fixture_hop_server(
                fixture_port(4),
                &format!(",{}-{}", fixture_port(5), fixture_port(7)),
            ),
            &fixture_pin_sha256(),
        ),
    )
    .unwrap();
    assert_eq!(hy2_hopping.server_port, fixture_port(4));
    assert!(matches!(
        hy2_hopping.handler,
        ResidentProxyProtocolPlan::Hysteria2QuicTcp {
            ref port_hop_ports,
            ..
        } if port_hop_ports == &vec![
            fixture_port(4),
            fixture_port(5),
            fixture_port(6),
            fixture_port(7),
        ]
    ));

    let tuic_verified = build_resident_proxy_plan_for_node(
        &config,
        "proxy".to_owned(),
        "tuic_verified".to_owned(),
        tuic_fixture_url("tuic", &primary_host, fixture_port(8), false),
    )
    .unwrap();
    assert!(!tuic_verified.allow_insecure);

    let juicity_system_roots = build_resident_proxy_plan_for_node(
        &config,
        "proxy".to_owned(),
        "juicity_system_roots".to_owned(),
        juicity_fixture_url("juicity", &primary_host, fixture_port(9), false),
    )
    .unwrap();
    assert_eq!(juicity_system_roots.protocol, "juicity");
    assert!(!juicity_system_roots.allow_insecure);
    assert!(matches!(
        juicity_system_roots.handler,
        ResidentProxyProtocolPlan::JuicityQuicTcp {
            allow_insecure: false,
            ref pinned_certchain_sha256,
            ..
        } if pinned_certchain_sha256.is_empty()
    ));
    assert_eq!(
        juicity_system_roots.executable_graph_value()["runtimeComponents"]["underlayFactory"]["verificationPolicy"],
        "system-roots"
    );

    let juicity_pinned = JuicityLink {
        name: String::new(),
        user: fixture_client_id(),
        password: fixture_secret(),
        server: primary_host.clone(),
        port: fixture_port(10),
        sni: fixture_host(FixtureEndpoint::Authority),
        allow_insecure: false,
        congestion_control: String::new(),
        pinned_certchain_sha256: fixture_pin_sha256(),
        protocol: "juicity".to_owned(),
    }
    .export_url();
    let juicity_pinned = build_resident_proxy_plan_for_node(
        &config,
        "proxy".to_owned(),
        "juicity_pinned".to_owned(),
        juicity_pinned,
    )
    .unwrap();
    assert_eq!(
        juicity_pinned.executable_graph_value()["runtimeComponents"]["underlayFactory"]["verificationPolicy"],
        "pinned-certchain-sha256"
    );
}

#[test]
pub(super) fn resident_dataplane_plan_propagates_global_allow_insecure_to_tls_handlers() {
    let config = parse_config(
        r#"
        global {
        lan_interface: daerust0
        allow_insecure: true
        so_mark_from_dae: 1234
        mptcp: false
        }
        routing {
        fallback: direct
        }
        "#,
    );
    let primary_host = fixture_host(FixtureEndpoint::Primary);
    let links = [
        (
            "trojan_global_insecure",
            trojan_fixture_url("trojan-global-insecure", &primary_host, fixture_port(1)),
        ),
        ("vless_global_insecure", vless_vision_fixture_url("")),
        (
            "vmess_tls_global_insecure",
            vmess_fixture_url(
                "vmess-tls",
                &primary_host,
                fixture_port(3),
                "tcp",
                "",
                "",
                "tls",
            ),
        ),
    ];

    for (tag, link) in links {
        let proxy =
            build_resident_proxy_plan_for_node(&config, "proxy".to_owned(), tag.to_owned(), link)
                .unwrap();
        let graph = proxy.executable_graph_value();
        assert!(proxy.allow_insecure, "{tag}");
        assert_eq!(graph["securityUnderlay"], "insecure-tls", "{tag}");
        assert_eq!(
            graph["runtimeComponents"]["underlayFactory"]["allowInsecure"], true,
            "{tag}"
        );
        assert_eq!(
            graph["runtimeComponents"]["underlayFactory"]["verificationPolicy"],
            "explicit-insecure",
            "{tag}"
        );
    }
}

#[test]
pub(super) fn resident_dataplane_plan_builds_proxy_by_outbound_index() {
    let first_link = vless_vision_fixture_url("");
    let second_link = vless_fixture_url(
        "",
        &fixture_host(FixtureEndpoint::Secondary),
        fixture_authority_port(),
        "tcp",
        "",
        "",
        &fixture_host(FixtureEndpoint::Authority),
        "xtls-rprx-vision",
        "",
    );
    let config_source = r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        dial_mode: domain++
        }
        node {
        first_node: '__FIRST_SOURCE__'
        second_node: '__SECOND_SOURCE__'
        }
        group {
        proxy {
            filter: name(first_node)
            policy: fixed(0)
        }
        secondary {
            filter: name(second_node)
            policy: fixed(0)
        }
        }
        routing {
        domain(suffix: target.fixture.invalid) -> secondary
        fallback: proxy
        }
        "#
    .replace("__FIRST_SOURCE__", &first_link)
    .replace("__SECOND_SOURCE__", &second_link);
    let config = parse_config(&config_source);
    let plan = build_resident_dataplane_plan(&config).unwrap();
    assert!(plan.enabled);
    assert_eq!(plan.tcp_dial_mode, TcpDialMode::DomainPlusPlus);
    let proxy = plan
        .proxies
        .get(&2)
        .unwrap()
        .default_proxy_snapshot()
        .unwrap();
    let secondary = plan
        .proxies
        .get(&3)
        .unwrap()
        .default_proxy_snapshot()
        .unwrap();
    assert_eq!(proxy.group_name, "proxy");
    assert_eq!(proxy.node_tag, "first_node");
    assert_eq!(secondary.group_name, "secondary");
    assert_eq!(secondary.node_tag, "second_node");
}

#[test]
pub(super) fn resident_dataplane_plan_admits_vless_plain_tcp_tls_without_vision_flow() {
    let source = vless_vision_without_flow_fixture_url("");
    let config_source = r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        }
        node {
        vless_live: '__SOURCE__'
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
        "#
    .replace("__SOURCE__", &source);
    let config = parse_config(&config_source);
    let plan = build_resident_dataplane_plan(&config).unwrap();
    let proxy = plan
        .default_proxy_group()
        .unwrap()
        .select_proxy_for_tcp()
        .unwrap();
    assert_eq!(proxy.protocol, "vless");
    assert_eq!(proxy.net, "tcp");
    assert_eq!(proxy.flow, "");
    assert!(matches!(
        proxy.handler,
        ResidentProxyProtocolPlan::VlessVisionTcpTls { .. }
    ));
}

#[test]
pub(super) fn resident_dataplane_plan_admits_vless_plain_tcp_without_tls() {
    let source = vless_plain_tcp_none_fixture_url();
    let config_source = r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        }
        node {
        vless_live: '__SOURCE__'
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
        "#
    .replace("__SOURCE__", &source);
    let config = parse_config(&config_source);
    let plan = build_resident_dataplane_plan(&config).unwrap();
    let proxy = plan
        .default_proxy_group()
        .unwrap()
        .select_proxy_for_tcp()
        .unwrap();
    assert_eq!(proxy.protocol, "vless");
    assert_eq!(proxy.net, "tcp");
    assert_eq!(proxy.tls, "none");
    assert_eq!(proxy.flow, "");
    assert!(matches!(
        proxy.handler,
        ResidentProxyProtocolPlan::VlessVisionTcpTls { .. }
    ));
    let graph = proxy.executable_graph_value();
    assert_eq!(graph["securityUnderlay"], "none");
    assert_eq!(
        graph["runtimeComponents"]["underlayFactory"]["verificationPolicy"],
        "none"
    );
}

#[test]
pub(super) fn resident_dataplane_plan_admits_vless_vision_udp443_flow() {
    let source = vless_fixture_url(
        "",
        &fixture_host(FixtureEndpoint::Primary),
        fixture_authority_port(),
        "tcp",
        "",
        "",
        &fixture_host(FixtureEndpoint::Authority),
        "xtls-rprx-vision-udp443",
        "",
    );
    let config_source = r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        }
        node {
        vless_live: '__SOURCE__'
        }
        group {
        proxy {
            filter: name(vless_live)
            policy: fixed(0)
        }
        }
        routing {
        fallback: proxy
        }
        "#
    .replace("__SOURCE__", &source);
    let config = parse_config(&config_source);
    let plan = build_resident_dataplane_plan(&config).unwrap();
    let proxy = plan
        .default_proxy_group()
        .unwrap()
        .select_proxy_for_tcp()
        .unwrap();
    assert_eq!(proxy.protocol, "vless");
    assert_eq!(proxy.net, "tcp");
    assert_eq!(proxy.flow, "xtls-rprx-vision-udp443");
    assert!(matches!(
        proxy.handler,
        ResidentProxyProtocolPlan::VlessVisionTcpTls { .. }
    ));
}

#[test]
pub(super) fn resident_dataplane_plan_admits_vless_xhttp_h2_packet_up() {
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
    assert_eq!(proxy.stream_host, fixture_host(FixtureEndpoint::Authority));
    assert_eq!(proxy.stream_path, "/resource/?ed=2048");
    let graph = proxy.executable_graph_value();
    assert_eq!(graph["streamWrapper"], "xhttp");
    assert_eq!(
        graph["runtimeComponents"]["streamWrapperFactory"]["provider"],
        "resident-xhttp-h2-packet-up"
    );

    let proxy = build_resident_proxy_plan_for_node(
        &config,
        "proxy".to_owned(),
        "standard_import".to_owned(),
        vless_xhttp_parser_fixture_url("packet-up", "h2,http/1.1", ""),
    )
    .unwrap();
    let graph = proxy.executable_graph_value();
    assert_eq!(proxy.alpn, vec!["h2".to_owned(), "http/1.1".to_owned()]);
    assert_eq!(
        graph["runtimeComponents"]["streamWrapperFactory"]["provider"],
        "resident-xhttp-h2-packet-up"
    );
}

#[test]
pub(super) fn resident_dataplane_plan_admits_vless_xhttp_h1_packet_up() {
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
        vless_xhttp_parser_fixture_url("packet-up", "http/1.1", ""),
    )
    .unwrap();

    assert_eq!(proxy.protocol, "vless");
    assert_eq!(proxy.net, "xhttp");
    assert_eq!(proxy.alpn, vec!["http/1.1".to_owned()]);
    assert_eq!(proxy.stream_host, fixture_host(FixtureEndpoint::Authority));
    assert_eq!(proxy.stream_path, "/resource/?ed=2048");
    let graph = proxy.executable_graph_value();
    assert_eq!(graph["streamWrapper"], "xhttp");
    assert_eq!(graph["packetSemantics"], "udp-over-stream");
    assert_eq!(
        graph["runtimeComponents"]["streamWrapperFactory"]["provider"],
        "resident-xhttp-h1-packet-up"
    );
}

#[test]
pub(super) fn resident_dataplane_plan_admits_vless_xhttp_h3_packet_up() {
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
        vless_xhttp_parser_fixture_url("packet-up", "h3", ""),
    )
    .unwrap();

    assert_eq!(proxy.protocol, "vless");
    assert_eq!(proxy.net, "xhttp");
    assert_eq!(proxy.alpn, vec!["h3".to_owned()]);
    assert_eq!(proxy.stream_host, fixture_host(FixtureEndpoint::Authority));
    assert_eq!(proxy.stream_path, "/resource/?ed=2048");
    let graph = proxy.executable_graph_value();
    assert_eq!(graph["streamWrapper"], "xhttp");
    assert_eq!(graph["packetSemantics"], "udp-over-stream");
    assert_eq!(
        graph["runtimeComponents"]["streamWrapperFactory"]["provider"],
        "resident-xhttp-h3-packet-up"
    );
}

#[test]
pub(super) fn resident_dataplane_plan_admits_vless_xhttp_download_settings() {
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
        vless_xhttp_parser_fixture_url(
            "packet-up",
            "h2",
            r#"{"downloadSettings":{"address":"download.transport.invalid","port":18444,"network":"xhttp","security":"tls","tlsSettings":{"serverName":"download.sni.invalid","alpn":["h3"],"allowInsecure":true},"xhttpSettings":{"host":"download.host.invalid","path":"/down?ed=4096","mode":"packet-up"}}}"#,
        ),
    )
    .unwrap();

    let download = proxy.xhttp_download.as_ref().unwrap();
    assert_eq!(download.server_host, "download.transport.invalid");
    assert_eq!(download.server_port, 18444);
    assert_eq!(download.server_name, "download.sni.invalid");
    assert_eq!(download.alpn, vec!["h3".to_owned()]);
    assert_eq!(download.stream_host, "download.host.invalid");
    assert_eq!(download.stream_path, "/down/?ed=4096");
    assert!(download.allow_insecure);

    let proxy = build_resident_proxy_plan_for_node(
        &config,
        "proxy".to_owned(),
        "standard_import".to_owned(),
        vless_xhttp_parser_fixture_url(
            "packet-up",
            "h2",
            r#"{"downloadSettings":{"address":"download.transport.invalid","port":18444,"network":"xhttp","security":"tls","tlsSettings":{"serverName":"download.sni.invalid","alpn":["http/1.1"],"allowInsecure":false},"xhttpSettings":{"host":"download.host.invalid","path":"/down?ed=4096","mode":"packet-up"}}}"#,
        ),
    )
    .unwrap();
    let download = proxy.xhttp_download.as_ref().unwrap();
    assert_eq!(download.alpn, vec!["http/1.1".to_owned()]);
    assert!(!download.allow_insecure);

    let proxy = build_resident_proxy_plan_for_node(
        &config,
        "proxy".to_owned(),
        "standard_import".to_owned(),
        vless_xhttp_parser_fixture_url(
            "packet-up",
            "h2",
            r#"{"downloadSettings":{"address":"download.transport.invalid","port":18444,"network":"xhttp","security":"tls","xhttpSettings":{"host":"download.xhttp.invalid","path":"/xhttp?ed=4096"},"splithttpSettings":{"host":"download.splithttp.invalid","path":"/splithttp?ed=4096"}}}"#,
        ),
    )
    .unwrap();
    let download = proxy.xhttp_download.as_ref().unwrap();
    assert_eq!(download.stream_host, "download.xhttp.invalid");
    assert_eq!(download.stream_path, "/xhttp/?ed=4096");
}

#[test]
pub(super) fn resident_dataplane_plan_admits_vless_xhttp_reality_download_settings() {
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
    let primary_public_key = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode([FixtureEndpoint::Primary.slot() as u8; 32]);
    let download_public_key = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode([FixtureEndpoint::Secondary.slot() as u8; 32]);
    let link = VLESSLink {
        ps: String::new(),
        add: fixture_host(FixtureEndpoint::Primary),
        port: fixture_authority_port().to_string(),
        id: fixture_client_id(),
        net: "xhttp".to_owned(),
        r#type: "none".to_owned(),
        host: fixture_host(FixtureEndpoint::Authority),
        sni: fixture_host(FixtureEndpoint::Authority),
        path: "/resource?ed=2048".to_owned(),
        xhttp_mode: "packet-up".to_owned(),
        xhttp_extra: format!(
            r#"{{"downloadSettings":{{"address":"download.transport.invalid","port":18444,"network":"xhttp","security":"reality","realitySettings":{{"serverName":"download.sni.invalid","alpn":["h2"],"allowInsecure":true,"publicKey":"{download_public_key}","shortId":"01020304","spiderX":"/download"}},"xhttpSettings":{{"host":"download.host.invalid","path":"/down?ed=4096","mode":"packet-up"}}}}}}"#
        ),
        tls: "reality".to_owned(),
        flow: String::new(),
        alpn: "h2".to_owned(),
        allow_insecure: false,
        fingerprint: String::new(),
        public_key: primary_public_key,
        short_id: "05060708".to_owned(),
        spider_x: "/primary".to_owned(),
        mux: false,
        protocol: "vless".to_owned(),
    }
    .export_url();

    let proxy = build_resident_proxy_plan_for_node(
        &config,
        "proxy".to_owned(),
        "xhttp_reality_download".to_owned(),
        link,
    )
    .unwrap();

    assert_eq!(proxy.tls, "reality");
    assert!(proxy.reality.is_some());
    let download = proxy.xhttp_download.as_ref().unwrap();
    assert_eq!(download.server_host, "download.transport.invalid");
    assert_eq!(download.server_name, "download.sni.invalid");
    assert_eq!(download.alpn, vec!["h2".to_owned()]);
    assert_eq!(download.stream_host, "download.host.invalid");
    assert_eq!(download.stream_path, "/down/?ed=4096");
    assert!(download.allow_insecure);
    let reality = download.reality.as_ref().unwrap();
    assert_eq!(
        reality.public_key,
        [FixtureEndpoint::Secondary.slot() as u8; 32]
    );
    assert_eq!(reality.short_id, vec![1, 2, 3, 4]);
    assert_eq!(reality.spider_x, "/download");
}

#[test]
pub(super) fn resident_dataplane_plan_admits_vless_xhttp_stream_modes_and_xmux() {
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
    let stream_up = build_resident_proxy_plan_for_node(
        &config,
        "proxy".to_owned(),
        "xhttp_stream_up".to_owned(),
        vless_xhttp_parser_fixture_url("stream-up", "h2", ""),
    )
    .unwrap();
    assert_eq!(stream_up.xhttp_mode, ResidentXhttpMode::StreamUp);
    let default_xmux = stream_up.xhttp_xmux.as_ref().unwrap();
    assert_eq!(default_xmux.max_concurrency, Some((1, 1)));
    assert_eq!(default_xmux.max_connections, None);
    assert_eq!(default_xmux.c_max_reuse_times, None);
    assert_eq!(default_xmux.h_max_request_times, Some((600, 900)));
    assert_eq!(default_xmux.h_max_reusable_secs, Some((1800, 3000)));

    let stream_one = build_resident_proxy_plan_for_node(
        &config,
        "proxy".to_owned(),
        "xhttp_stream_one".to_owned(),
        vless_xhttp_parser_fixture_url("stream-one", "h2", ""),
    )
    .unwrap();
    assert_eq!(stream_one.xhttp_mode, ResidentXhttpMode::StreamOne);

    let xmux = build_resident_proxy_plan_for_node(
        &config,
        "proxy".to_owned(),
        "xhttp_xmux".to_owned(),
        vless_xhttp_parser_fixture_url(
            "packet-up",
            "h2",
            r#"{"xmux":{"maxConcurrency":{"from":8,"to":0},"cMaxReuseTimes":"9-3","hMaxRequestTimes":"4","hMaxReusableSecs":{"from":5,"to":10},"hKeepAlivePeriod":15}}"#,
        ),
    )
    .unwrap();
    let xmux = xmux.xhttp_xmux.as_ref().unwrap();
    assert_eq!(xmux.max_concurrency, Some((0, 8)));
    assert_eq!(xmux.max_connections, None);
    assert_eq!(xmux.c_max_reuse_times, Some((3, 9)));
    assert_eq!(xmux.h_max_request_times, Some((4, 4)));
    assert_eq!(xmux.h_max_reusable_secs, Some((5, 10)));
    assert_eq!(xmux.h_keep_alive_period, 15);

    let zero_xmux = build_resident_proxy_plan_for_node(
        &config,
        "proxy".to_owned(),
        "xhttp_xmux_zero".to_owned(),
        vless_xhttp_parser_fixture_url("packet-up", "h2", r#"{"xmux":{"maxConnections":0}}"#),
    )
    .unwrap();
    let zero_xmux = zero_xmux.xhttp_xmux.as_ref().unwrap();
    assert_eq!(zero_xmux.max_concurrency, Some((1, 1)));
    assert_eq!(zero_xmux.max_connections, None);
    assert_eq!(zero_xmux.h_max_request_times, Some((600, 900)));
    assert_eq!(zero_xmux.h_max_reusable_secs, Some((1800, 3000)));

    let signed_xmux = build_resident_proxy_plan_for_node(
        &config,
        "proxy".to_owned(),
        "xhttp_xmux_signed".to_owned(),
        vless_xhttp_parser_fixture_url(
            "packet-up",
            "h2",
            r#"{"xmux":{"maxConcurrency":"-1","cMaxReuseTimes":"","hMaxRequestTimes":"-5--3","hMaxReusableSecs":"9-3"}}"#,
        ),
    )
    .unwrap();
    let signed_xmux = signed_xmux.xhttp_xmux.as_ref().unwrap();
    assert_eq!(signed_xmux.max_concurrency, Some((-1, -1)));
    assert_eq!(signed_xmux.c_max_reuse_times, Some((0, 0)));
    assert_eq!(signed_xmux.h_max_request_times, Some((-5, -3)));
    assert_eq!(signed_xmux.h_max_reusable_secs, Some((3, 9)));

    let err = build_resident_proxy_plan_for_node(
        &config,
        "proxy".to_owned(),
        "xhttp_xmux_conflict".to_owned(),
        vless_xhttp_parser_fixture_url(
            "packet-up",
            "h2",
            r#"{"xmux":{"maxConcurrency":8,"maxConnections":2}}"#,
        ),
    )
    .unwrap_err();
    assert!(err.contains("maxConnections together with maxConcurrency"));
}

#[test]
pub(super) fn resident_dataplane_plan_admits_vless_xhttp_extended_settings_surface() {
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
        "xhttp_extended".to_owned(),
        vless_xhttp_parser_fixture_url(
            "packet-up",
            "h2",
            r#"{"headers":{"X-Test":"alpha"},"xPaddingBytes":"100-200","xPaddingObfsMode":true,"xPaddingKey":"pad","xPaddingHeader":"X-Pad","xPaddingPlacement":"header","xPaddingMethod":"tokenish","uplinkHTTPMethod":"POST","sessionIDPlacement":"header","sessionIDKey":"X-Sid","sessionIDTable":"Base62","sessionIDLength":"6","seqPlacement":"query","seqKey":"seq","uplinkDataPlacement":"header","uplinkDataKey":"X-Body","uplinkChunkSize":"128-256","noGRPCHeader":true,"noSSEHeader":true,"scMaxEachPostBytes":"4096","scMinPostsIntervalMs":"40-50","scMaxBufferedPosts":7,"scStreamUpServerSecs":"30-40","serverMaxHeaderBytes":16384,"xmux":{"maxConnections":2}}"#,
        ),
    )
    .unwrap();

    assert_eq!(proxy.xhttp_mode, ResidentXhttpMode::PacketUp);
    assert_eq!(
        proxy
            .xhttp_settings
            .headers
            .get("X-Test")
            .map(String::as_str),
        Some("alpha")
    );
    assert_eq!(proxy.xhttp_settings.x_padding_bytes, Some((100, 200)));
    assert!(proxy.xhttp_settings.x_padding_obfs_mode);
    assert_eq!(proxy.xhttp_settings.x_padding_key, "pad");
    assert_eq!(proxy.xhttp_settings.x_padding_header, "X-Pad");
    assert_eq!(
        proxy.xhttp_settings.x_padding_placement,
        ResidentXhttpPaddingPlacement::Header
    );
    assert_eq!(
        proxy.xhttp_settings.x_padding_method,
        ResidentXhttpPaddingMethod::Tokenish
    );
    assert_eq!(proxy.xhttp_settings.uplink_http_method, "POST");
    assert_eq!(
        proxy.xhttp_settings.session_id_placement,
        ResidentXhttpMetaPlacement::Header
    );
    assert_eq!(proxy.xhttp_settings.session_id_key, "X-Sid");
    assert_eq!(
        proxy.xhttp_settings.session_id_table,
        "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    );
    assert_eq!(proxy.xhttp_settings.session_id_length, Some((6, 6)));
    assert_eq!(
        proxy.xhttp_settings.seq_placement,
        ResidentXhttpMetaPlacement::Query
    );
    assert_eq!(proxy.xhttp_settings.seq_key, "seq");
    assert_eq!(
        proxy.xhttp_settings.uplink_data_placement,
        ResidentXhttpUplinkDataPlacement::Header
    );
    assert_eq!(proxy.xhttp_settings.uplink_data_key, "X-Body");
    assert_eq!(proxy.xhttp_settings.uplink_chunk_size, Some((128, 256)));
    assert!(proxy.xhttp_settings.no_grpc_header);
    assert!(proxy.xhttp_settings.no_sse_header);
    assert_eq!(
        proxy.xhttp_settings.sc_max_each_post_bytes,
        Some((4096, 4096))
    );
    assert_eq!(
        proxy.xhttp_settings.sc_min_posts_interval_ms,
        Some((40, 50))
    );
    assert_eq!(proxy.xhttp_settings.sc_max_buffered_posts, 7);
    assert_eq!(
        proxy.xhttp_settings.sc_stream_up_server_secs,
        Some((30, 40))
    );
    assert_eq!(proxy.xhttp_settings.server_max_header_bytes, 16384);
    assert_eq!(
        proxy.xhttp_xmux.as_ref().unwrap().max_connections,
        Some((2, 2))
    );

    let graph = proxy.executable_graph_value();
    let evidence =
        &graph["runtimeComponents"]["streamWrapperFactory"]["xhttpExtendedSettings"]["primary"];
    assert_eq!(evidence["headers"]["names"], serde_json::json!(["X-Test"]));
    assert_eq!(evidence["xPadding"]["placement"], "header");
    assert_eq!(evidence["uplink"]["dataPlacement"], "header");
    assert_eq!(evidence["metadata"]["sessionIDPlacement"], "header");
    assert_eq!(evidence["headersPolicy"]["noSSEHeader"], true);
    assert_eq!(evidence["streamOne"]["effectiveScMaxBufferedPosts"], 7);
}

#[test]
pub(super) fn resident_dataplane_plan_admits_vless_xhttp_download_mode_and_nested_extra_surface() {
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
        "xhttp_download_extended".to_owned(),
        vless_xhttp_parser_fixture_url(
            "packet-up",
            "h2",
            r#"{"downloadSettings":{"address":"download.transport.invalid","port":18444,"network":"xhttp","security":"tls","tlsSettings":{"serverName":"download.sni.invalid","alpn":["h2"]},"xhttpSettings":{"host":"download.host.invalid","path":"/down?ed=4096","mode":"stream-up","extra":{"headers":{"X-Down":"beta"},"xPaddingBytes":"101","noSSEHeader":true,"xmux":{"maxConnections":3}}}}}"#,
        ),
    )
    .unwrap();

    let download = proxy.xhttp_download.as_ref().unwrap();
    assert_eq!(download.mode, ResidentXhttpMode::StreamUp);
    assert_eq!(download.stream_host, "download.host.invalid");
    assert_eq!(download.stream_path, "/down/?ed=4096");
    assert_eq!(
        download.settings.headers.get("X-Down").map(String::as_str),
        Some("beta")
    );
    assert_eq!(download.settings.x_padding_bytes, Some((101, 101)));
    assert!(download.settings.no_sse_header);
    assert_eq!(
        download.xmux.as_ref().unwrap().max_connections,
        Some((3, 3))
    );

    let graph = proxy.executable_graph_value();
    let download_evidence =
        &graph["runtimeComponents"]["streamWrapperFactory"]["xhttpExtendedSettings"]["download"];
    assert_eq!(download_evidence["mode"], "stream-up");
    assert_eq!(
        download_evidence["settings"]["headers"]["names"],
        serde_json::json!(["X-Down"])
    );
}

#[test]
pub(super) fn resident_dataplane_plan_rejects_remaining_invalid_vless_xhttp_shapes() {
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
            "xhttp_unknown_extra",
            vless_xhttp_parser_fixture_url("packet-up", "h2", r#"{"definitelyNotOfficial":true}"#),
            "unsupported fields",
        ),
        (
            "xhttp_stream_one_download",
            vless_xhttp_parser_fixture_url(
                "stream-one",
                "h2",
                r#"{"downloadSettings":{"address":"download.transport.invalid","port":18444,"network":"xhttp","security":"tls","xhttpSettings":{"host":"download.host.invalid","path":"/down?ed=4096"}}}"#,
            ),
            "stream-one cannot use downloadSettings",
        ),
        (
            "xhttp_unsupported_alpn",
            vless_xhttp_parser_fixture_url("packet-up", "spdy/3.1", ""),
            "rejected ALPN",
        ),
    ] {
        let err =
            build_resident_proxy_plan_for_node(&config, "proxy".to_owned(), tag.to_owned(), link)
                .unwrap_err();
        assert!(
            err.contains(expected),
            "{tag} rejected with unexpected error: {err}"
        );
    }
}
