use super::*;

#[test]
fn anytls_underlay_rejects_oversized_magic_network() {
    let network = "x".repeat(u8::MAX as usize + 1);
    assert!(matches!(
        crate::anytls::link::underlay_contract(&network, 0, false),
        Err(crate::error::OutboundError::BadAnyTLS(message)) if message.contains("network too long")
    ));
}

#[test]
pub(super) fn anytls_rust_native_matches_nativelden_fixture() {
    let fixture = fixture("outbound/protocol/anytls_rust_native.json");

    assert_eq!(
        crate::anytls::contract::ADAPTER_MODE,
        fixture["rust_adapter_mode"].as_str().unwrap()
    );
    assert_eq!(
        crate::anytls::contract::PROTOCOL_SCOPE,
        fixture["protocol_scope"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect::<Vec<_>>()
            .as_slice()
    );

    for case in fixture["link_parser"].as_array().unwrap() {
        let parsed = crate::anytls::AnyTLSLink::parse(case["input"].as_str().unwrap()).unwrap();
        assert_eq!(parsed.name, case["name"].as_str().unwrap());
        assert_eq!(parsed.auth, case["auth"].as_str().unwrap());
        assert_eq!(parsed.host, case["host"].as_str().unwrap());
        assert_eq!(parsed.hostname, case["hostname"].as_str().unwrap());
        assert_eq!(parsed.sni, case["sni"].as_str().unwrap());
        assert_eq!(
            parsed.tls_server_name,
            case["tls_server_name"].as_str().unwrap()
        );
        assert_eq!(parsed.insecure, case["insecure"].as_bool().unwrap());
        assert_eq!(parsed.protocol, case["protocol"].as_str().unwrap());
        assert_eq!(parsed.export_url(), case["property_link"].as_str().unwrap());
        assert_eq!(parsed.address(), case["property_address"].as_str().unwrap());
        let chain = parse_link_chain(case["input"].as_str().unwrap()).unwrap();
        assert_eq!(chain.nodes[0].adapter_mode, "rust-native");
        assert_eq!(
            chain.property_address,
            case["property_address"].as_str().unwrap()
        );
        assert_eq!(chain.property_name, case["property_name"].as_str().unwrap());
        assert_eq!(
            chain.property_protocol,
            case["property_protocol"].as_str().unwrap()
        );
    }

    for case in fixture["insecure_cases"].as_array().unwrap() {
        let parsed = crate::anytls::AnyTLSLink::parse(case["input"].as_str().unwrap()).unwrap();
        assert_eq!(parsed.insecure, case["insecure"].as_bool().unwrap());
    }

    let tls = &fixture["tls_contract"];
    assert_eq!(
        crate::anytls::contract::EMPTY_SNI_SERVER_NAME,
        tls["empty_sni_server_name"].as_str().unwrap()
    );
    assert_eq!(
        crate::anytls::contract::INSECURE_ONLY_WHEN,
        tls["insecure_only_when"].as_str().unwrap()
    );
    assert_eq!(
        crate::anytls::contract::PEER_OVERRIDES_SNI,
        tls["peer_overrides_sni"].as_bool().unwrap()
    );

    let auth = &fixture["auth_key"];
    assert_eq!(
        hex_encode(&crate::anytls::link::auth_key(
            auth["auth"].as_str().unwrap()
        )),
        auth["sha256_hex"].as_str().unwrap()
    );
    assert_eq!(
        crate::anytls::link::auth_key(auth["auth"].as_str().unwrap()).len(),
        auth["key_len"].as_u64().unwrap() as usize
    );

    let session = &fixture["session_contract"];
    assert_eq!(
        hex_encode(&crate::anytls::link::handshake_auth_bytes(
            auth["auth"].as_str().unwrap()
        )),
        session["first_handshake"]["auth_key_then_u16_30_and_default_padding_hex"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        crate::anytls::contract::IDLE_SESSION_REUSE_MAP,
        session["idle_session_reuse_map"].as_bool().unwrap()
    );
    assert_eq!(
        crate::anytls::contract::DEFAULT_PADDING_MD5,
        session["padding"]["md5"].as_str().unwrap()
    );
    assert_eq!(
        String::from_utf8(crate::anytls::link::settings_bytes()).unwrap(),
        session["padding"]["settings"].as_str().unwrap()
    );
    assert_eq!(
        hex_encode(
            &crate::anytls::link::frame(
                crate::anytls::contract::CMD_SETTINGS,
                1,
                &crate::anytls::link::settings_bytes()
            )
            .unwrap()
        ),
        session["frame"]["settings_frame_hex"].as_str().unwrap()
    );
    assert_eq!(
        hex_encode(&crate::anytls::link::frame(crate::anytls::contract::CMD_SYN, 1, &[]).unwrap()),
        session["frame"]["syn_frame_hex"].as_str().unwrap()
    );
    assert_eq!(
        hex_encode(
            &crate::anytls::link::frame(
                crate::anytls::contract::CMD_PSH,
                1,
                &crate::anytls::link::socks_addr("fixture.invalid:443").unwrap()
            )
            .unwrap()
        ),
        session["frame"]["psh_addr_frame_hex"].as_str().unwrap()
    );

    let packet = &fixture["packet_stream"];
    assert_eq!(
        crate::anytls::contract::UDP_MAGIC_DOMAIN,
        packet["udp_magic_domain"].as_str().unwrap()
    );
    assert_eq!(
        crate::anytls::link::udp_stream_target(packet["udp_input_target"].as_str().unwrap())
            .unwrap(),
        packet["udp_stream_target"].as_str().unwrap()
    );
    assert_eq!(
        hex_encode(
            &crate::anytls::link::packet_first_write(
                packet["udp_input_target"].as_str().unwrap(),
                b"ping"
            )
            .unwrap()
        ),
        packet["first_write_hex"].as_str().unwrap()
    );
    assert_eq!(
        hex_encode(&crate::anytls::link::packet_next_write(b"ping").unwrap()),
        packet["next_write_hex"].as_str().unwrap()
    );

    let underlay = &fixture["underlay_contract"];
    let tcp = crate::anytls::link::underlay_contract("tcp", 1234, true).unwrap();
    assert_eq!(
        STANDARD.encode(&tcp.underlay_encoded),
        underlay["tcp_request"]["underlay_b64"].as_str().unwrap()
    );
    assert_eq!(
        tcp.same_encoded_value,
        underlay["tcp_request"]["same_encoded_value"]
            .as_bool()
            .unwrap()
    );
    let udp = crate::anytls::link::underlay_contract("udp", 1234, true).unwrap();
    assert_eq!(
        udp.underlay_network,
        underlay["udp_request"]["underlay_network"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        udp.underlay_mptcp,
        underlay["udp_request"]["underlay_mptcp"].as_bool().unwrap()
    );
    assert_eq!(
        crate::anytls::contract::PRODUCTION_DATA_PLANE_OWNER,
        underlay["production_data_plane_owner"].as_str().unwrap()
    );
    assert_eq!(
        crate::anytls::contract::STANDALONE_SMOKE_SURFACE,
        underlay["standalone_smoke_surface"].as_str().unwrap()
    );
}
