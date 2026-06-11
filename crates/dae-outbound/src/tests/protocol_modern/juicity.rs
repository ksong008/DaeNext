use super::*;
#[test]
pub(super) fn juicity_rust_native_matches_nativelden_fixture() {
    let fixture = fixture("outbound/protocol/juicity_rust_native.json");

    assert_eq!(
        crate::juicity::contract::ADAPTER_MODE,
        fixture["rust_adapter_mode"].as_str().unwrap()
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
