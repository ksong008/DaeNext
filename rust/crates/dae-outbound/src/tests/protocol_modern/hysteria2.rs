use super::*;
#[test]
pub(super) fn hysteria2_native_optin_matches_golden_fixture() {
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
