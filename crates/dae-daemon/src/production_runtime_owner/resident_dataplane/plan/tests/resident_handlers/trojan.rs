use super::*;
pub(super) fn assert_trojan_handlers(config: &Config) -> Vec<ResidentProxyPlan> {
    let primary_host = fixture_host(FixtureEndpoint::Primary);
    let authority_host = fixture_host(FixtureEndpoint::Authority);
    let primary_port = fixture_port(1);
    let trojan = build_resident_proxy_plan_for_node(
        &config,
        "proxy".to_owned(),
        "trojan_live".to_owned(),
        trojan_fixture_url("trojan", &primary_host, primary_port),
    )
    .unwrap();
    assert_eq!(trojan.protocol, "trojan");
    assert_eq!(trojan.server_host, primary_host);
    assert_eq!(trojan.server_port, primary_port);
    assert_eq!(trojan.server_name, authority_host);
    assert_eq!(trojan.tls, "tls");
    assert!(matches!(
        trojan.handler,
        ResidentProxyProtocolPlan::TrojanTcpTls { .. }
    ));

    let trojan_websocket = build_resident_proxy_plan_for_node(
        &config,
        "proxy".to_owned(),
        "trojan_ws_live".to_owned(),
        trojan_websocket_fixture_url("trojan-ws", &primary_host, fixture_port(2)),
    )
    .unwrap();
    assert_eq!(trojan_websocket.protocol, "trojan");
    assert_eq!(trojan_websocket.server_host, primary_host);
    assert_eq!(trojan_websocket.server_port, fixture_port(2));
    assert_eq!(trojan_websocket.server_name, authority_host);
    assert_eq!(trojan_websocket.net, "websocket");
    assert_eq!(trojan_websocket.stream_host, authority_host);
    assert_eq!(trojan_websocket.stream_path, "/resource");
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
        "/resource"
    );
    assert!(!trojan_websocket_graph.to_string().contains(&authority_host));

    let trojan_httpupgrade = build_resident_proxy_plan_for_node(
        &config,
        "proxy".to_owned(),
        "trojan_httpupgrade_live".to_owned(),
        trojan_httpupgrade_fixture_url("trojan-httpupgrade", &primary_host, fixture_port(3)),
    )
    .unwrap();
    assert_eq!(trojan_httpupgrade.protocol, "trojan");
    assert_eq!(trojan_httpupgrade.server_host, primary_host);
    assert_eq!(trojan_httpupgrade.server_port, fixture_port(3));
    assert_eq!(trojan_httpupgrade.server_name, authority_host);
    assert_eq!(trojan_httpupgrade.net, "httpupgrade");
    assert_eq!(trojan_httpupgrade.stream_host, authority_host);
    assert_eq!(trojan_httpupgrade.stream_path, "/resource");
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
        "/resource"
    );
    assert!(
        !trojan_httpupgrade_graph
            .to_string()
            .contains(&authority_host)
    );

    let trojan_grpc = build_resident_proxy_plan_for_node(
        &config,
        "proxy".to_owned(),
        "trojan_grpc_live".to_owned(),
        trojan_grpc_fixture_url("trojan-grpc", &primary_host, fixture_port(4)),
    )
    .unwrap();
    assert_eq!(trojan_grpc.protocol, "trojan");
    assert_eq!(trojan_grpc.server_host, primary_host);
    assert_eq!(trojan_grpc.server_port, fixture_port(4));
    assert_eq!(trojan_grpc.server_name, authority_host);
    assert_eq!(trojan_grpc.net, "grpc");
    assert_eq!(trojan_grpc.stream_host, authority_host);
    assert_eq!(trojan_grpc.stream_path, "ServiceEndpoint");
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
        "ServiceEndpoint"
    );
    assert!(!trojan_grpc_graph.to_string().contains(&authority_host));

    vec![trojan, trojan_websocket, trojan_httpupgrade]
}
