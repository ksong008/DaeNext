use super::*;
pub(super) fn assert_vmess_vless_handlers(config: &Config) -> Vec<ResidentProxyPlan> {
    let anytls = build_resident_proxy_plan_for_node(
        &config,
        "proxy".to_owned(),
        "anytls_live".to_owned(),
        "anytls://password@secure-stream.example.net:443?sni=secure-stream.example.net".to_owned(),
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

    vec![
        anytls,
        vmess,
        vmess_websocket,
        vmess_httpupgrade,
        vless_websocket,
        vless_httpupgrade,
    ]
}
