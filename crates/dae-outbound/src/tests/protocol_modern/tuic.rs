use super::*;
#[test]
pub(super) fn tuic_rust_native_matches_nativelden_fixture() {
    let fixture = fixture("outbound/protocol/tuic_rust_native.json");

    assert_eq!(
        crate::tuic::contract::ADAPTER_MODE,
        fixture["rust_adapter_mode"].as_str().unwrap()
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
        crate::tuic::contract::UDP_RELAY_MODE_PROTOCOL_EFFECTIVE_MODE,
        udp_relay["protocol_effective_mode"].as_str().unwrap()
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
