use super::*;
pub(super) fn assert_vmess_vless_handlers(config: &Config) -> Vec<ResidentProxyPlan> {
    let primary_host = fixture_host(FixtureEndpoint::Primary);
    let authority_host = fixture_host(FixtureEndpoint::Authority);
    let anytls = build_resident_proxy_plan_for_node(
        &config,
        "proxy".to_owned(),
        "anytls_live".to_owned(),
        anytls_fixture_url(&primary_host, fixture_port(1)),
    )
    .unwrap();
    assert_eq!(anytls.protocol, "anytls");
    assert_eq!(anytls.server_host, primary_host);
    assert_eq!(anytls.server_port, fixture_port(1));
    assert_eq!(anytls.server_name, primary_host);
    assert_eq!(anytls.tls, "tls");
    assert!(matches!(
        anytls.handler,
        ResidentProxyProtocolPlan::AnyTlsTcpTls { .. }
    ));

    let vmess = build_resident_proxy_plan_for_node(
        &config,
        "proxy".to_owned(),
        "vmess_live".to_owned(),
        vmess_fixture_url("vmess", &primary_host, fixture_port(2), "tcp", "", "", ""),
    )
    .unwrap();
    assert_eq!(vmess.protocol, "vmess");
    assert_eq!(vmess.server_host, primary_host);
    assert_eq!(vmess.server_port, fixture_port(2));
    assert_eq!(vmess.tls, "none");
    assert!(matches!(
        vmess.handler,
        ResidentProxyProtocolPlan::VmessAeadTcp { .. }
    ));

    let vmess_tls = build_resident_proxy_plan_for_node(
        &config,
        "proxy".to_owned(),
        "vmess_tls_live".to_owned(),
        vmess_fixture_url_with_sni(
            &primary_host,
            fixture_port(2),
            "tcp",
            "",
            "",
            "tls",
            &authority_host,
        ),
    )
    .unwrap();
    assert_eq!(vmess_tls.protocol, "vmess");
    assert_eq!(vmess_tls.net, "tcp");
    assert_eq!(vmess_tls.server_name, authority_host);
    assert_eq!(vmess_tls.tls, "tls");
    assert!(matches!(
        vmess_tls.handler,
        ResidentProxyProtocolPlan::VmessAeadTcp { .. }
    ));
    let vmess_tls_graph = vmess_tls.executable_graph_value();
    assert_eq!(vmess_tls_graph["streamWrapper"], "none");
    assert_eq!(vmess_tls_graph["securityUnderlay"], "standard-tls");
    assert_eq!(
        vmess_tls_graph["runtimeComponents"]["underlayFactory"]["provider"],
        "rustls"
    );

    let vmess_websocket = build_resident_proxy_plan_for_node(
        &config,
        "proxy".to_owned(),
        "vmess_ws_live".to_owned(),
        vmess_fixture_url(
            "vmess-ws",
            &primary_host,
            fixture_port(3),
            "ws",
            &authority_host,
            "/vmess",
            "",
        ),
    )
    .unwrap();
    assert_eq!(vmess_websocket.protocol, "vmess");
    assert_eq!(vmess_websocket.net, "websocket");
    assert_eq!(vmess_websocket.stream_host, authority_host);
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
    assert!(!vmess_websocket_graph.to_string().contains(&authority_host));

    let vmess_websocket_tls = build_resident_proxy_plan_for_node(
        &config,
        "proxy".to_owned(),
        "vmess_ws_tls_live".to_owned(),
        vmess_fixture_url_with_sni(
            &primary_host,
            fixture_port(3),
            "ws",
            &authority_host,
            "/vmess",
            "tls",
            &authority_host,
        ),
    )
    .unwrap();
    assert_eq!(vmess_websocket_tls.protocol, "vmess");
    assert_eq!(vmess_websocket_tls.net, "websocket");
    assert_eq!(vmess_websocket_tls.server_name, authority_host);
    assert_eq!(vmess_websocket_tls.stream_host, authority_host);
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
            &primary_host,
            fixture_port(4),
            "httpupgrade",
            &authority_host,
            "/vmess-upgrade",
            "",
        ),
    )
    .unwrap();
    assert_eq!(vmess_httpupgrade.protocol, "vmess");
    assert_eq!(vmess_httpupgrade.net, "httpupgrade");
    assert_eq!(vmess_httpupgrade.stream_host, authority_host);
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
            .contains(&authority_host)
    );

    let vmess_httpupgrade_tls = build_resident_proxy_plan_for_node(
        &config,
        "proxy".to_owned(),
        "vmess_httpupgrade_tls_live".to_owned(),
        vmess_fixture_url_with_sni(
            &primary_host,
            fixture_port(4),
            "httpupgrade",
            &authority_host,
            "/vmess-upgrade",
            "tls",
            &authority_host,
        ),
    )
    .unwrap();
    assert_eq!(vmess_httpupgrade_tls.protocol, "vmess");
    assert_eq!(vmess_httpupgrade_tls.net, "httpupgrade");
    assert_eq!(vmess_httpupgrade_tls.server_name, authority_host);
    assert_eq!(vmess_httpupgrade_tls.stream_host, authority_host);
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
            &primary_host,
            fixture_port(5),
            "grpc",
            &authority_host,
            "GunService",
            "tls",
        ),
    )
    .unwrap();
    assert_eq!(vmess_grpc.protocol, "vmess");
    assert_eq!(vmess_grpc.net, "grpc");
    assert_eq!(vmess_grpc.server_host, primary_host);
    assert_eq!(vmess_grpc.server_port, fixture_port(5));
    assert_eq!(vmess_grpc.server_name, primary_host);
    assert_eq!(vmess_grpc.stream_host, authority_host);
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
    assert!(!vmess_grpc_graph.to_string().contains(&authority_host));

    let vmess_h2 = build_resident_proxy_plan_for_node(
        &config,
        "proxy".to_owned(),
        "vmess_h2_live".to_owned(),
        vmess_fixture_url_with_sni(
            &primary_host,
            fixture_port(5),
            "h2",
            &authority_host,
            "/vmess-h2",
            "tls",
            &authority_host,
        ),
    )
    .unwrap();
    assert_eq!(vmess_h2.protocol, "vmess");
    assert_eq!(vmess_h2.net, "h2");
    assert_eq!(vmess_h2.server_host, primary_host);
    assert_eq!(vmess_h2.server_name, authority_host);
    assert_eq!(vmess_h2.stream_host, authority_host);
    assert_eq!(vmess_h2.stream_path, "/vmess-h2");
    assert_eq!(vmess_h2.tls, "tls");
    assert_eq!(vmess_h2.alpn, vec!["h2".to_owned()]);
    assert!(matches!(
        vmess_h2.handler,
        ResidentProxyProtocolPlan::VmessAeadTcp { .. }
    ));
    let vmess_h2_graph = vmess_h2.executable_graph_value();
    assert_eq!(vmess_h2_graph["streamWrapper"], "h2");
    assert_eq!(vmess_h2_graph["securityUnderlay"], "standard-tls");
    assert_eq!(
        vmess_h2_graph["runtimeComponents"]["streamWrapperFactory"]["provider"],
        "resident-http2-body-stream"
    );
    assert!(
        vmess_h2_graph["streamWrapperEndpoint"]["hostHash"]
            .as_str()
            .unwrap()
            .starts_with("sha256:")
    );
    assert!(!vmess_h2_graph.to_string().contains(&authority_host));

    let vless_websocket = build_resident_proxy_plan_for_node(
        &config,
        "proxy".to_owned(),
        "vless_ws_live".to_owned(),
        vless_fixture_url(
            "vless-ws",
            &primary_host,
            fixture_port(6),
            "ws",
            &authority_host,
            "/ws",
            &authority_host,
            "",
            "",
        ),
    )
    .unwrap();
    assert_eq!(vless_websocket.protocol, "vless");
    assert_eq!(vless_websocket.server_host, primary_host);
    assert_eq!(vless_websocket.server_port, fixture_port(6));
    assert_eq!(vless_websocket.server_name, authority_host);
    assert_eq!(vless_websocket.net, "websocket");
    assert_eq!(vless_websocket.stream_host, authority_host);
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
    assert!(!vless_websocket_graph.to_string().contains(&authority_host));

    let vless_httpupgrade = build_resident_proxy_plan_for_node(
        &config,
        "proxy".to_owned(),
        "vless_httpupgrade_live".to_owned(),
        vless_fixture_url(
            "vless-httpupgrade",
            &primary_host,
            fixture_port(7),
            "httpupgrade",
            &authority_host,
            "/vless-upgrade",
            &authority_host,
            "",
            "",
        ),
    )
    .unwrap();
    assert_eq!(vless_httpupgrade.protocol, "vless");
    assert_eq!(vless_httpupgrade.server_host, primary_host);
    assert_eq!(vless_httpupgrade.server_port, fixture_port(7));
    assert_eq!(vless_httpupgrade.server_name, authority_host);
    assert_eq!(vless_httpupgrade.net, "httpupgrade");
    assert_eq!(vless_httpupgrade.stream_host, authority_host);
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
            .contains(&authority_host)
    );

    let vless_h2 = build_resident_proxy_plan_for_node(
        &config,
        "proxy".to_owned(),
        "vless_h2_live".to_owned(),
        vless_fixture_url(
            "vless-h2",
            &primary_host,
            fixture_port(8),
            "h2",
            &authority_host,
            "/vless-h2",
            &authority_host,
            "",
            "",
        ),
    )
    .unwrap();
    assert_eq!(vless_h2.protocol, "vless");
    assert_eq!(vless_h2.server_host, primary_host);
    assert_eq!(vless_h2.server_name, authority_host);
    assert_eq!(vless_h2.net, "h2");
    assert_eq!(vless_h2.stream_host, authority_host);
    assert_eq!(vless_h2.stream_path, "/vless-h2");
    assert_eq!(vless_h2.alpn, vec!["h2".to_owned()]);
    assert!(matches!(
        vless_h2.handler,
        ResidentProxyProtocolPlan::VlessVisionTcpTls { .. }
    ));
    let vless_h2_graph = vless_h2.executable_graph_value();
    assert_eq!(vless_h2_graph["streamWrapper"], "h2");
    assert_eq!(
        vless_h2_graph["runtimeComponents"]["streamWrapperFactory"]["provider"],
        "resident-http2-body-stream"
    );
    assert_eq!(vless_h2_graph["streamWrapperEndpoint"]["path"], "/vless-h2");
    assert!(!vless_h2_graph.to_string().contains(&authority_host));

    vec![
        anytls,
        vmess,
        vmess_tls,
        vmess_websocket,
        vmess_httpupgrade,
        vmess_h2,
        vless_websocket,
        vless_httpupgrade,
        vless_h2,
    ]
}
