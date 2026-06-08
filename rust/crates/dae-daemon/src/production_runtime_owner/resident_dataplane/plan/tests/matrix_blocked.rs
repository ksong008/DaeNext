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

    let err = build_resident_proxy_plan_for_node(
        &config,
        "proxy".to_owned(),
        "too_deep".to_owned(),
        too_deep_chain_fixture_url(),
    )
    .unwrap_err();
    assert!(err.contains("admits two-node chains only"));
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
            "vless_reality",
            vless_reality_fixture_url(),
            "reality",
            "rustls-reality",
            false,
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
        assert_eq!(proxy.allow_insecure, allow_insecure, "{tag}");
    }

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
    let trojan_go_inner_encryption = build_resident_proxy_plan_for_node(
        &config,
        "proxy".to_owned(),
        "trojan_go_inner_encryption".to_owned(),
        trojan_inner_shadowsocks_fixture_url(inner_cipher),
    )
    .unwrap();
    assert_eq!(trojan_go_inner_encryption.protocol, "trojan");
    assert_eq!(trojan_go_inner_encryption.net, "websocket");
    assert!(matches!(
        trojan_go_inner_encryption.handler,
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
    .unwrap_err();
    assert!(vmess_tls.contains("admits only plain VMess TCP endpoints"));

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

    let juicity_without_verification = build_resident_proxy_plan_for_node(
        &config,
        "proxy".to_owned(),
        "juicity_without_verification".to_owned(),
        juicity_fixture_url("juicity", &primary_host, fixture_port(9), false),
    )
    .unwrap_err();
    assert!(
        juicity_without_verification
            .contains("requires Juicity allow_insecure or pinned_certchain_sha256")
    );
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
        domain(suffix: target.example) -> secondary
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
pub(super) fn resident_dataplane_plan_rejects_vless_without_vision_flow() {
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
    let err = build_resident_dataplane_plan(&config).unwrap_err();
    assert!(err.contains("admits tcp flow=xtls-rprx-vision"));
    assert!(err.contains("resident shape remains fail-closed"));
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
}

#[test]
pub(super) fn resident_dataplane_plan_rejects_unimplemented_vless_xhttp_shapes() {
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
            vless_xhttp_parser_fixture_url("packet-up", "h2", r#"{"xmux":{"maxConnections":2}}"#),
            "admits default extra settings only",
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
