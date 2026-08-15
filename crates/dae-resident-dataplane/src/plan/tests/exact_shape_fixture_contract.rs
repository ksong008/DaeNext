use super::*;

fn fixture_field<'a>(shape: &'a serde_json::Value, field: &str) -> &'a str {
    shape[field]
        .as_str()
        .unwrap_or_else(|| panic!("exact-shape fixture field {field} must be a string: {shape}"))
}

fn exact_shape_source(id: &str) -> String {
    let primary = fixture_host(FixtureEndpoint::Primary);
    let authority = fixture_host(FixtureEndpoint::Authority);
    match id {
        "socks5-basic" => socks5_fixture_url(&primary, fixture_port(1)),
        "http-connect" => http_proxy_fixture_url(&primary, fixture_port(1)),
        "https-connect" => https_proxy_fixture_url(&primary, fixture_port(1)),
        "connect-udp-h2" => format!(
            "masque://identity-1:credential-1@{primary}:{}?transport=h2&auth=basic&template=%2F.well-known%2Fmasque%2Fudp%2F%7Btarget_host%7D%2F%7Btarget_port%7D%2F&sni={authority}#fixture-connect-udp-h2",
            fixture_port(1),
        ),
        "connect-udp-h3" => format!(
            "masque://{primary}:{}?transport=h3&auth=none&template=%2F.well-known%2Fmasque%2Fudp%2F%7Btarget_host%7D%2F%7Btarget_port%7D%2F&sni={authority}#fixture-connect-udp-h3",
            fixture_port(1),
        ),
        "hysteria2-quic" => hysteria2_fixture_url("", &primary, fixture_port(6)),
        "vless-websocket-tls" => vless_fixture_url(
            "",
            &primary,
            fixture_port(5),
            "ws",
            &authority,
            "/ws",
            &authority,
            "",
            "",
        ),
        "vless-meek-tls" => vless_fixture_url(
            "",
            &primary,
            fixture_port(5),
            "meek",
            "",
            "https://node-4.fixture.invalid/meek",
            &authority,
            "",
            "",
        ),
        "vmess-h2-tls" => vmess_fixture_url_with_sni(
            &primary,
            fixture_port(4),
            "h2",
            &authority,
            "/h2",
            "tls",
            &authority,
        ),
        "vless-reality-vision" => vless_reality_fixture_url(),
        other => panic!("unmapped resident exact-shape fixture {other}"),
    }
}

#[test]
fn rust_execution_plan_matches_shared_web_exact_shape_contract() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/resident_protocol_exact_shapes.json"
    )))
    .unwrap();
    assert_eq!(fixture["schemaVersion"], 1);
    let shapes = fixture["shapes"].as_array().unwrap();
    assert!(shapes.len() >= 8);

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

    for shape in shapes {
        let id = fixture_field(shape, "id");
        let source = exact_shape_source(id);
        if matches!(id, "connect-udp-h2" | "connect-udp-h3") {
            let error = build_resident_proxy_plan_for_node(
                &config,
                "proxy".to_owned(),
                id.to_owned(),
                source,
            )
            .expect_err("removed CONNECT-UDP source must remain fail-closed");
            assert!(error.contains("unsupported masque node"), "{id}: {error}");
            continue;
        }
        let proxy =
            build_resident_proxy_plan_for_node(&config, "proxy".to_owned(), id.to_owned(), source)
                .unwrap_or_else(|err| panic!("build shared exact-shape fixture {id}: {err}"));
        let execution = proxy.execution_plan();
        let contract = execution.executor_contract();
        let graph = proxy.executable_graph_value();

        assert_eq!(proxy.protocol, fixture_field(shape, "protocol"), "{id}");
        assert_eq!(
            execution.security.graph_label(),
            fixture_field(shape, "securityUnderlay"),
            "{id}"
        );
        assert_eq!(
            execution.wrapper.graph_label(),
            fixture_field(shape, "streamWrapper"),
            "{id}"
        );
        assert_eq!(
            contract.tcp_executor,
            fixture_field(shape, "tcpExecutor"),
            "{id}"
        );
        assert_eq!(
            contract.udp_executor,
            fixture_field(shape, "udpExecutor"),
            "{id}"
        );
        assert_eq!(
            if contract.udp_policy_closed {
                "fail-closed"
            } else {
                "admitted"
            },
            fixture_field(shape, "udpStatus"),
            "{id}"
        );
        assert_eq!(
            execution.protocol.runtime_dispatch().as_str(),
            fixture_field(shape, "runtimeDispatch"),
            "{id}"
        );
        assert_eq!(
            execution.protocol.probe_dispatch().as_str(),
            fixture_field(shape, "probeDispatch"),
            "{id}"
        );
        assert_eq!(
            graph["runtimeComponents"]["packetSessionManager"]["executor"],
            fixture_field(shape, "udpExecutor"),
            "{id}"
        );
        assert_eq!(
            graph["runtimeComponents"]["streamWrapperFactory"]["status"], "admitted",
            "{id}"
        );
        match id {
            "connect-udp-h2" => assert_eq!(
                graph["runtimeComponents"]["streamWrapperFactory"]["provider"],
                "resident-connect-udp-h2-capsule-session"
            ),
            "connect-udp-h3" => assert_eq!(
                graph["runtimeComponents"]["streamWrapperFactory"]["provider"],
                "resident-connect-udp-h3-datagram-session"
            ),
            _ => {}
        }
    }
}
