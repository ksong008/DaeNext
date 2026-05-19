use super::*;

#[test]
fn socks5_native_optin_matches_golden_fixture() {
    let fixture = fixture("outbound/protocol/socks5_native_optin.json");

    assert_eq!(
        crate::socks5::contract::ADAPTER_MODE,
        fixture["rust_adapter_mode"].as_str().unwrap()
    );
    assert_eq!(
        crate::socks5::contract::DEFAULT_GO_PATH,
        fixture["default_go_path"].as_bool().unwrap()
    );
    assert_eq!(
        crate::socks5::contract::PROTOCOL_SCOPE,
        fixture["protocol_scope"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect::<Vec<_>>()
            .as_slice()
    );

    let link = &fixture["link_parser"];
    let parsed = parse_link_chain(link["input"].as_str().unwrap()).unwrap();
    assert_eq!(
        parsed.plaintext_tag.as_deref(),
        Some(link["plaintext_tag"].as_str().unwrap())
    );
    assert_eq!(parsed.linklike, link["linklike"].as_str().unwrap());
    assert_eq!(parsed.property_name, link["name"].as_str().unwrap());
    assert_eq!(parsed.property_protocol, link["protocol"].as_str().unwrap());
    assert_eq!(parsed.property_address, link["address"].as_str().unwrap());
    assert_eq!(parsed.nodes[0].adapter_mode, "native-opt-in");
    assert_eq!(
        parsed.nodes[1].scheme,
        link["socks_alias_scheme"].as_str().unwrap()
    );
    assert_eq!(
        parsed.nodes[1].protocol,
        link["socks_alias_protocol"].as_str().unwrap()
    );

    for case in fixture["address_codec"].as_array().unwrap() {
        let addr = crate::socks5::Socks5Address::parse(case["input"].as_str().unwrap()).unwrap();
        assert_eq!(
            hex_encode(&addr.encode().unwrap()),
            case["hex"].as_str().unwrap()
        );
        let encoded = hex_decode(case["hex"].as_str().unwrap());
        let (decoded, consumed) = crate::socks5::Socks5Address::decode(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(decoded.authority(), case["string"].as_str().unwrap());
    }

    let handshake = &fixture["handshake"];
    assert_eq!(
        hex_encode(&crate::socks5::handshake::greeting("", "")),
        handshake["greeting_no_auth_hex"].as_str().unwrap()
    );
    assert_eq!(
        hex_encode(&crate::socks5::handshake::greeting("user", "pass")),
        handshake["greeting_with_auth_hex"].as_str().unwrap()
    );
    assert_eq!(
        hex_encode(&crate::socks5::handshake::username_password_auth("user", "pass").unwrap()),
        handshake["username_password_auth_hex"].as_str().unwrap()
    );
    assert_eq!(
        hex_encode(&crate::socks5::handshake::connect_request("example.com:443").unwrap()),
        handshake["connect_example_com_443_hex"].as_str().unwrap()
    );
    assert_eq!(
        hex_encode(&crate::socks5::handshake::udp_associate_request("0.0.0.0:0").unwrap()),
        handshake["udp_associate_0_0_0_0_0_hex"].as_str().unwrap()
    );
    let reply = crate::socks5::handshake::parse_server_reply(&hex_decode(
        handshake["success_reply_hex"].as_str().unwrap(),
    ))
    .unwrap();
    assert_eq!(reply.bind.authority(), "127.0.0.1:5300");

    let packet = &fixture["udp_packet"];
    let wrapped = crate::socks5::udp_packet::wrap_target(
        packet["target"].as_str().unwrap(),
        packet["payload_ascii"].as_str().unwrap().as_bytes(),
    )
    .unwrap();
    assert_eq!(
        hex_encode(&wrapped),
        packet["write_packet_hex"].as_str().unwrap()
    );
    let unwrapped = crate::socks5::udp_packet::unwrap(&wrapped).unwrap();
    assert_eq!(unwrapped.reserved, [0, 0]);
    assert_eq!(unwrapped.fragment, 0);
    assert_eq!(
        unwrapped.target.authority(),
        packet["target"].as_str().unwrap()
    );
    assert_eq!(
        String::from_utf8(unwrapped.payload).unwrap(),
        packet["payload_ascii"].as_str().unwrap()
    );
}

#[test]
fn http_native_optin_matches_golden_fixture() {
    let fixture = fixture("outbound/protocol/http_native_optin.json");

    assert_eq!(
        crate::http_proxy::contract::ADAPTER_MODE,
        fixture["rust_adapter_mode"].as_str().unwrap()
    );
    assert_eq!(
        crate::http_proxy::contract::DEFAULT_GO_PATH,
        fixture["default_go_path"].as_bool().unwrap()
    );
    assert_eq!(
        crate::http_proxy::contract::PROTOCOL_SCOPE,
        fixture["protocol_scope"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect::<Vec<_>>()
            .as_slice()
    );

    for case in fixture["link_parser"].as_array().unwrap() {
        let parsed =
            crate::http_proxy::HttpProxyLink::parse(case["input"].as_str().unwrap()).unwrap();
        assert_eq!(parsed.server, case["server"].as_str().unwrap());
        assert_eq!(parsed.port, case["port"].as_u64().unwrap() as u16);
        assert_eq!(parsed.username, case["username"].as_str().unwrap());
        assert_eq!(parsed.password, case["password"].as_str().unwrap());
        assert_eq!(parsed.sni, case["sni"].as_str().unwrap());
        assert_eq!(parsed.protocol.as_str(), case["protocol"].as_str().unwrap());
        assert_eq!(
            parsed.allow_insecure,
            case["allowInsecure"].as_bool().unwrap()
        );
        assert_eq!(parsed.export_url(), case["export"].as_str().unwrap());
        let parsed_chain = parse_link_chain(case["input"].as_str().unwrap()).unwrap();
        assert_eq!(parsed_chain.nodes[0].adapter_mode, "native-opt-in");
    }

    for case in fixture["connect"].as_array().unwrap() {
        let mut options =
            crate::http_proxy::HttpConnectOptions::connect(case["target"].as_str().unwrap());
        options.username = case["username"].as_str().unwrap().to_owned();
        options.password = case["password"].as_str().unwrap().to_owned();
        options.host_override = case["host_override"].as_str().unwrap().to_owned();
        options.transport.enabled = case["transport"].as_bool().unwrap();
        options.transport.path = case["path"].as_str().unwrap().to_owned();
        assert_eq!(
            hex_encode(&crate::http_proxy::request::connect_request(&options)),
            case["request_hex"].as_str().unwrap(),
            "{}",
            case["name"].as_str().unwrap()
        );
    }

    let passthrough = &fixture["http_request_passthrough"];
    assert_eq!(
        hex_encode(
            &crate::http_proxy::request::forward_http_request(&hex_decode(
                passthrough["input_hex"].as_str().unwrap()
            ))
            .unwrap()
        ),
        passthrough["request_hex"].as_str().unwrap()
    );

    let flags = &fixture["https_flags"];
    assert_eq!(
        crate::http_proxy::contract::HTTPS_DEFAULT_TLS_IMPLEMENTATION,
        flags["tls_implementation_default"].as_str().unwrap()
    );
    assert_eq!(
        crate::http_proxy::contract::HTTPS_DEFAULT_ALPN_QUERY_VALUE,
        flags["alpn_default_query_value"].as_str().unwrap()
    );
    assert_eq!(
        crate::http_proxy::contract::HTTPS_H2_ROUTE_CONTEXT_REQUIRED,
        flags["h2_route_context_required"].as_bool().unwrap()
    );
}
