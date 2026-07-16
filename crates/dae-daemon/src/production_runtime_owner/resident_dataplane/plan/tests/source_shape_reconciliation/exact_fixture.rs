use super::*;

fn fixture_field<'a>(shape: &'a serde_json::Value, field: &str) -> &'a str {
    shape[field]
        .as_str()
        .unwrap_or_else(|| panic!("shared exact-shape fixture field {field} must be a string"))
}

fn fixture_source(id: &str) -> String {
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
        other => panic!("unmapped resident registry fixture source {other}"),
    }
}

fn registry_shape_id(id: &str) -> &'static str {
    match id {
        "socks5-basic" => "baseline-socks-endpoint",
        "http-connect" => "baseline-connect-endpoint",
        "https-connect" => "secure-endpoint-capability",
        "connect-udp-h2" => "connect-udp-h2-endpoint",
        "connect-udp-h3" => "connect-udp-h3-endpoint",
        "hysteria2-quic" => "baseline-quic-auth-endpoint",
        "vless-websocket-tls" => "stream-wrapper-websocket",
        "vless-meek-tls" => "vless-meek-tls-stream-wrapper",
        "vmess-h2-tls" => "vmess-h2-stream-wrapper",
        "vless-reality-vision" => "reality-security-underlay",
        other => panic!("unmapped resident registry fixture {other}"),
    }
}

#[test]
fn shared_exact_shapes_match_typed_registry_selectors() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/resident_protocol_exact_shapes.json"
    )))
    .unwrap();
    let shapes = fixture["shapes"].as_array().unwrap();
    let config = fixture_config();

    for shape in shapes {
        let id = fixture_field(shape, "id");
        let source = fixture_source(id);
        let proxy = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            id.to_owned(),
            source.clone(),
        )
        .unwrap_or_else(|err| panic!("build shared exact-shape fixture {id}: {err}"));
        let materialized = materialized_source_shape(&proxy, &source);
        let registry_id = registry_shape_id(id);

        assert!(
            source_shape_reconciliation(registry_id)
                .unwrap()
                .matches(materialized),
            "{id} -> {registry_id}: {materialized:?}"
        );
    }
}
