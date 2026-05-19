use super::*;

#[test]
fn hysteria2_native_optin_matches_golden_fixture() {
    let fixture = fixture("outbound/protocol/hysteria2_native_optin.json");

    assert_eq!(
        crate::hysteria2::contract::ADAPTER_MODE,
        fixture["rust_adapter_mode"].as_str().unwrap()
    );
    assert_eq!(
        crate::hysteria2::contract::DEFAULT_GO_PATH,
        fixture["default_go_path"].as_bool().unwrap()
    );
    assert_eq!(
        crate::hysteria2::contract::PROTOCOL_SCOPE,
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
            crate::hysteria2::Hysteria2Link::parse(case["input"].as_str().unwrap()).unwrap();
        assert_eq!(parsed.user, case["user"].as_str().unwrap());
        assert_eq!(parsed.password, case["password"].as_str().unwrap());
        assert_eq!(parsed.server, case["server"].as_str().unwrap());
        assert_eq!(parsed.insecure, case["insecure"].as_bool().unwrap());
        assert_eq!(parsed.sni, case["sni"].as_str().unwrap());
        assert_eq!(parsed.pin_sha256, case["pinSHA256"].as_str().unwrap());
        assert_eq!(parsed.max_tx, case["maxTx"].as_u64().unwrap());
        assert_eq!(parsed.max_rx, case["maxRx"].as_u64().unwrap());
        assert_eq!(parsed.export_url(), case["export"].as_str().unwrap());
        assert_eq!(
            crate::hysteria2::link::normalize_pin_sha256(&parsed.pin_sha256),
            case["pinSHA256_normal"].as_str().unwrap()
        );
        let chain = parse_link_chain(case["input"].as_str().unwrap()).unwrap();
        assert_eq!(chain.nodes[0].adapter_mode, "native-opt-in");
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

    for case in fixture["pin_sha256"].as_array().unwrap() {
        assert_eq!(
            crate::hysteria2::link::normalize_pin_sha256(case["input"].as_str().unwrap()),
            case["normalized"].as_str().unwrap()
        );
    }

    for case in fixture["server_contract"].as_array().unwrap() {
        let contract = crate::hysteria2::link::server_contract(case["server"].as_str().unwrap());
        assert_eq!(contract.host, case["host"].as_str().unwrap());
        assert_eq!(contract.port, case["port"].as_str().unwrap());
        assert_eq!(contract.host_port, case["host_port"].as_str().unwrap());
        assert_eq!(
            contract.port_hopping,
            case["port_hopping"].as_bool().unwrap()
        );
    }

    let underlay = &fixture["underlay_contract"];
    assert_eq!(
        crate::hysteria2::contract::ALWAYS_UDP_UNDERLAY,
        underlay["always_udp_underlay"].as_bool().unwrap()
    );
    assert_eq!(
        crate::hysteria2::contract::PRESERVE_MARK,
        underlay["preserve_mark"].as_bool().unwrap()
    );
    assert_eq!(
        crate::hysteria2::contract::TRUE_QUIC_DATA_PLANE_DEFERRED_ITEM,
        underlay["true_quic_data_plane_deferred_item"]
            .as_u64()
            .unwrap() as u16
    );
}

#[test]
fn tuic_native_optin_matches_golden_fixture() {
    let fixture = fixture("outbound/protocol/tuic_native_optin.json");

    assert_eq!(
        crate::tuic::contract::ADAPTER_MODE,
        fixture["rust_adapter_mode"].as_str().unwrap()
    );
    assert_eq!(
        crate::tuic::contract::DEFAULT_GO_PATH,
        fixture["default_go_path"].as_bool().unwrap()
    );
    assert_eq!(
        crate::tuic::contract::PROTOCOL_SCOPE,
        fixture["protocol_scope"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect::<Vec<_>>()
            .as_slice()
    );

    for case in fixture["link_parser"].as_array().unwrap() {
        let parsed = crate::tuic::TuicLink::parse(case["input"].as_str().unwrap()).unwrap();
        assert_eq!(parsed.user, case["user"].as_str().unwrap());
        assert_eq!(parsed.password, case["password"].as_str().unwrap());
        assert_eq!(parsed.server, case["server"].as_str().unwrap());
        assert_eq!(parsed.port, case["port"].as_u64().unwrap() as u16);
        assert_eq!(parsed.sni, case["sni"].as_str().unwrap());
        assert_eq!(
            parsed.allow_insecure,
            case["allowInsecure"].as_bool().unwrap()
        );
        assert_eq!(parsed.disable_sni, case["disable_sni"].as_bool().unwrap());
        assert_eq!(
            parsed.congestion_control,
            case["congestion_control"].as_str().unwrap()
        );
        assert_eq!(
            parsed.alpn,
            case["alpn"]
                .as_array()
                .map(|items| {
                    items
                        .iter()
                        .map(|value| value.as_str().unwrap().to_owned())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default()
        );
        assert_eq!(
            parsed.udp_relay_mode,
            case["udp_relay_mode"].as_str().unwrap()
        );
        assert_eq!(parsed.protocol, case["protocol"].as_str().unwrap());
        assert_eq!(parsed.export_url(), case["export"].as_str().unwrap());
        assert_eq!(parsed.address(), case["property_address"].as_str().unwrap());
        parsed.validate_uuid().unwrap();
        let chain = parse_link_chain(case["input"].as_str().unwrap()).unwrap();
        assert_eq!(chain.nodes[0].adapter_mode, "native-opt-in");
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

    for case in fixture["allow_insecure_aliases"].as_array().unwrap() {
        let parsed = crate::tuic::TuicLink::parse(case["input"].as_str().unwrap()).unwrap();
        assert_eq!(
            parsed.allow_insecure,
            case["allowInsecure"].as_bool().unwrap()
        );
        assert_eq!(parsed.export_url(), case["export"].as_str().unwrap());
    }

    assert!(
        crate::tuic::link::validate_uuid(fixture["uuid_contract"]["valid"].as_str().unwrap())
            .is_ok()
    );
    let invalid =
        crate::tuic::link::validate_uuid(fixture["uuid_contract"]["invalid"].as_str().unwrap())
            .unwrap_err()
            .to_string();
    assert!(
        invalid.contains(
            fixture["uuid_contract"]["invalid_error"]["error_contains"]
                .as_str()
                .unwrap()
        )
    );

    let quic = &fixture["quic_contract"];
    assert_eq!(
        crate::tuic::contract::TLS_MIN_VERSION,
        quic["tls_min_version"].as_u64().unwrap() as u16
    );
    assert_eq!(
        crate::tuic::contract::ENABLE_DATAGRAMS,
        quic["enable_datagrams"].as_bool().unwrap()
    );
    assert_eq!(
        crate::tuic::contract::KEEPALIVE_SECONDS,
        quic["keepalive_seconds"].as_u64().unwrap()
    );
    assert_eq!(
        crate::tuic::contract::HANDSHAKE_IDLE_TIMEOUT_SECONDS,
        quic["handshake_idle_timeout_seconds"].as_u64().unwrap()
    );
    assert_eq!(
        crate::tuic::contract::MAX_UDP_RELAY_PACKET_SIZE,
        quic["max_udp_relay_packet_size"].as_u64().unwrap() as u16
    );

    let udp_relay = &fixture["udp_relay_mode"];
    assert_eq!(
        crate::tuic::contract::UDP_RELAY_MODE_GO_PROTOCOL_EFFECTIVE_MODE,
        udp_relay["go_protocol_effective_mode"].as_str().unwrap()
    );
    assert_eq!(
        crate::tuic::contract::UDP_RELAY_MODE_QUIC_FIXME_DEFERRED,
        udp_relay["quic_mode_fixme_deferred"].as_bool().unwrap()
    );

    let underlay = &fixture["underlay_contract"];
    let tcp = crate::tuic::link::underlay_contract("tcp", 1234, true);
    assert_eq!(
        tcp.underlay_network,
        underlay["tcp_request"]["underlay_network"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        tcp.underlay_mptcp,
        underlay["tcp_request"]["underlay_mptcp"].as_bool().unwrap()
    );
    assert_eq!(
        STANDARD.encode(&tcp.underlay_encoded),
        underlay["tcp_request"]["underlay_b64"].as_str().unwrap()
    );
    let udp = crate::tuic::link::underlay_contract("udp", 1234, true);
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
        STANDARD.encode(&udp.underlay_encoded),
        underlay["udp_request"]["underlay_b64"].as_str().unwrap()
    );
    assert_eq!(
        crate::tuic::contract::TRUE_QUIC_DATA_PLANE_DEFERRED_ITEM,
        underlay["true_quic_data_plane_deferred"].as_u64().unwrap() as u16
    );
}

#[test]
fn juicity_native_optin_matches_golden_fixture() {
    let fixture = fixture("outbound/protocol/juicity_native_optin.json");

    assert_eq!(
        crate::juicity::contract::ADAPTER_MODE,
        fixture["rust_adapter_mode"].as_str().unwrap()
    );
    assert_eq!(
        crate::juicity::contract::DEFAULT_GO_PATH,
        fixture["default_go_path"].as_bool().unwrap()
    );
    assert_eq!(
        crate::juicity::contract::PROTOCOL_SCOPE,
        fixture["protocol_scope"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect::<Vec<_>>()
            .as_slice()
    );

    for case in fixture["link_parser"].as_array().unwrap() {
        let parsed = crate::juicity::JuicityLink::parse(case["input"].as_str().unwrap()).unwrap();
        assert_eq!(parsed.user, case["user"].as_str().unwrap());
        assert_eq!(parsed.password, case["password"].as_str().unwrap());
        assert_eq!(parsed.server, case["server"].as_str().unwrap());
        assert_eq!(parsed.port, case["port"].as_u64().unwrap() as u16);
        assert_eq!(parsed.sni, case["sni"].as_str().unwrap());
        assert_eq!(
            parsed.allow_insecure,
            case["allowInsecure"].as_bool().unwrap()
        );
        assert_eq!(
            parsed.congestion_control,
            case["congestion_control"].as_str().unwrap()
        );
        assert_eq!(
            parsed.pinned_certchain_sha256,
            case["pinned_certchain_sha256"].as_str().unwrap()
        );
        assert_eq!(parsed.protocol, case["protocol"].as_str().unwrap());
        assert_eq!(parsed.export_url(), case["export"].as_str().unwrap());
        assert_eq!(parsed.address(), case["property_address"].as_str().unwrap());
        assert_eq!(
            parsed.pin_forces_insecure_verify(),
            case["pin_forces_insecure_verify"].as_bool().unwrap()
        );
        parsed.validate_uuid().unwrap();
        let decoded =
            crate::juicity::link::decode_pinned_certchain(&parsed.pinned_certchain_sha256).unwrap();
        assert_eq!(
            decoded.format,
            case["pinned_certchain_decoded"]["format"].as_str().unwrap()
        );
        assert_eq!(
            hex_encode(&decoded.decoded),
            case["pinned_certchain_decoded"]["decoded_hex"]
                .as_str()
                .unwrap()
        );
        let chain = parse_link_chain(case["input"].as_str().unwrap()).unwrap();
        assert_eq!(chain.nodes[0].adapter_mode, "native-opt-in");
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

    for case in fixture["allow_insecure_aliases"].as_array().unwrap() {
        let parsed = crate::juicity::JuicityLink::parse(case["input"].as_str().unwrap()).unwrap();
        assert_eq!(
            parsed.allow_insecure,
            case["allowInsecure"].as_bool().unwrap()
        );
        assert_eq!(parsed.export_url(), case["export"].as_str().unwrap());
    }

    for case in fixture["pinned_certchain_sha256"].as_array().unwrap() {
        let got = crate::juicity::link::decode_pinned_certchain(case["input"].as_str().unwrap());
        if case["ok"].as_bool().unwrap() {
            let got = got.unwrap();
            assert_eq!(got.format, case["format"].as_str().unwrap());
            assert_eq!(
                hex_encode(&got.decoded),
                case["decoded_hex"].as_str().unwrap()
            );
        } else {
            assert!(
                got.unwrap_err()
                    .to_string()
                    .contains(case["error_contains"].as_str().unwrap())
            );
        }
    }

    assert!(
        crate::juicity::link::validate_uuid(fixture["uuid_contract"]["valid"].as_str().unwrap())
            .is_ok()
    );
    let invalid =
        crate::juicity::link::validate_uuid(fixture["uuid_contract"]["invalid"].as_str().unwrap())
            .unwrap_err()
            .to_string();
    assert!(
        invalid.contains(
            fixture["uuid_contract"]["invalid_error"]["error_contains"]
                .as_str()
                .unwrap()
        )
    );

    let quic = &fixture["quic_contract"];
    assert_eq!(
        crate::juicity::contract::ALPN,
        quic["alpn"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect::<Vec<_>>()
            .as_slice()
    );
    assert_eq!(
        crate::juicity::contract::TLS_MIN_VERSION,
        quic["tls_min_version"].as_u64().unwrap() as u16
    );
    assert_eq!(
        crate::juicity::contract::ENABLE_DATAGRAMS,
        quic["enable_datagrams"].as_bool().unwrap()
    );
    assert_eq!(
        crate::juicity::contract::KEEPALIVE_SECONDS,
        quic["keepalive_seconds"].as_u64().unwrap()
    );
    assert_eq!(
        crate::juicity::contract::RESERVED_STREAMS_CAPABILITY,
        quic["reserved_streams_capability"].as_u64().unwrap()
    );

    let underlay = &fixture["underlay_contract"];
    let tcp = crate::juicity::link::underlay_contract("tcp", 1234, true);
    assert_eq!(
        tcp.underlay_network,
        underlay["tcp_request"]["underlay_network"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        tcp.underlay_mptcp,
        underlay["tcp_request"]["underlay_mptcp"].as_bool().unwrap()
    );
    assert_eq!(
        STANDARD.encode(&tcp.underlay_encoded),
        underlay["tcp_request"]["underlay_b64"].as_str().unwrap()
    );
    let udp = crate::juicity::link::underlay_contract("udp", 1234, true);
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
        crate::juicity::contract::UDP_PORT_ZERO_PACKET_CONN,
        underlay["udp_port_zero_packet_conn"].as_str().unwrap()
    );
    assert_eq!(
        crate::juicity::contract::UDP_NONZERO_PORT_PACKET_CONN,
        underlay["udp_nonzero_port_packet_conn"].as_str().unwrap()
    );
    assert_eq!(
        crate::juicity::contract::TRUE_QUIC_DATA_PLANE_DEFERRED_ITEM,
        underlay["true_quic_data_plane_deferred"].as_u64().unwrap() as u16
    );
}

#[test]
fn anytls_native_optin_matches_golden_fixture() {
    let fixture = fixture("outbound/protocol/anytls_native_optin.json");

    assert_eq!(
        crate::anytls::contract::ADAPTER_MODE,
        fixture["rust_adapter_mode"].as_str().unwrap()
    );
    assert_eq!(
        crate::anytls::contract::DEFAULT_GO_PATH,
        fixture["default_go_path"].as_bool().unwrap()
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
        assert_eq!(chain.nodes[0].adapter_mode, "native-opt-in");
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
        session["first_handshake"]["auth_key_then_zero_u16_hex"]
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
        hex_encode(&crate::anytls::link::frame(
            crate::anytls::contract::CMD_SETTINGS,
            1,
            &crate::anytls::link::settings_bytes()
        )),
        session["frame"]["settings_frame_hex"].as_str().unwrap()
    );
    assert_eq!(
        hex_encode(&crate::anytls::link::frame(
            crate::anytls::contract::CMD_SYN,
            1,
            &[]
        )),
        session["frame"]["syn_frame_hex"].as_str().unwrap()
    );
    assert_eq!(
        hex_encode(&crate::anytls::link::frame(
            crate::anytls::contract::CMD_PSH,
            1,
            &crate::anytls::link::socks_addr("example.com:443").unwrap()
        )),
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
        hex_encode(&crate::anytls::link::packet_next_write(b"ping")),
        packet["next_write_hex"].as_str().unwrap()
    );

    let underlay = &fixture["underlay_contract"];
    let tcp = crate::anytls::link::underlay_contract("tcp", 1234, true);
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
    let udp = crate::anytls::link::underlay_contract("udp", 1234, true);
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
        crate::anytls::contract::TRUE_SESSION_DATA_PLANE_DEFERRED_ITEM,
        underlay["true_session_data_plane_deferred"]
            .as_u64()
            .unwrap() as u16
    );
}
