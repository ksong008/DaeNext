use super::*;

#[test]
fn shadowsocks_native_optin_matches_golden_fixture() {
    let fixture = fixture("outbound/protocol/shadowsocks_native_optin.json");

    assert_eq!(
        crate::shadowsocks::contract::ADAPTER_MODE,
        fixture["rust_adapter_mode"].as_str().unwrap()
    );
    assert_eq!(
        crate::shadowsocks::contract::DEFAULT_GO_PATH,
        fixture["default_go_path"].as_bool().unwrap()
    );
    assert_eq!(
        crate::shadowsocks::contract::PROTOCOL_SCOPE,
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
            crate::shadowsocks::ShadowsocksLink::parse(case["input"].as_str().unwrap()).unwrap();
        assert_eq!(parsed.server, case["server"].as_str().unwrap());
        assert_eq!(parsed.port, case["port"].as_u64().unwrap() as u16);
        assert_eq!(parsed.cipher, case["cipher"].as_str().unwrap());
        assert_eq!(parsed.password, case["password"].as_str().unwrap());
        assert_eq!(parsed.protocol, case["protocol"].as_str().unwrap());
        assert_eq!(parsed.udp, case["udp"].as_bool().unwrap());
        assert_eq!(parsed.export_url(), case["export"].as_str().unwrap());
        assert_eq!(parsed.plugin.name, case["plugin"]["name"].as_str().unwrap());
        assert_eq!(
            parsed.plugin.opts.tls,
            case["plugin"]["tls"].as_str().unwrap()
        );
        assert_eq!(
            parsed.plugin.opts.obfs,
            case["plugin"]["obfs"].as_str().unwrap()
        );
        assert_eq!(
            parsed.plugin.opts.host,
            case["plugin"]["host"].as_str().unwrap()
        );
        assert_eq!(
            parsed.plugin.opts.path,
            case["plugin"]["path"].as_str().unwrap()
        );
        let chain = parse_link_chain(case["input"].as_str().unwrap()).unwrap();
        assert_eq!(chain.nodes[0].adapter_mode, "native-opt-in");
        assert_eq!(
            chain.property_address,
            case["property_address"].as_str().unwrap()
        );
    }

    for case in fixture["cipher_dispatch"].as_array().unwrap() {
        let info = crate::shadowsocks::classify_cipher(case["cipher"].as_str().unwrap()).unwrap();
        assert_eq!(
            info.go_protocol_dialer,
            case["go_protocol_dialer"].as_str().unwrap()
        );
        assert_eq!(
            info.rust_capability_label,
            case["rust_capability_label"].as_str().unwrap()
        );
        assert_eq!(
            info.export_userinfo_plain,
            case["export_userinfo_plain"].as_bool().unwrap()
        );
    }

    for case in fixture["metadata"].as_array().unwrap() {
        let metadata =
            crate::shadowsocks::ShadowsocksMetadata::parse(case["input"].as_str().unwrap())
                .unwrap();
        assert_eq!(
            metadata.metadata_type().byte(),
            case["type"].as_u64().unwrap() as u8
        );
        assert_eq!(metadata.hostname(), case["hostname"].as_str().unwrap());
        assert_eq!(metadata.port(), case["port"].as_u64().unwrap() as u16);
        assert_eq!(
            hex_encode(&metadata.encode().unwrap()),
            case["hex"].as_str().unwrap()
        );
    }

    for case in fixture["ss2022"]["cipher_conf"].as_array().unwrap() {
        let conf =
            crate::shadowsocks::ss2022::cipher_conf(case["cipher"].as_str().unwrap()).unwrap();
        assert_eq!(conf.key_len, case["key_len"].as_u64().unwrap() as usize);
        assert_eq!(conf.salt_len, case["salt_len"].as_u64().unwrap() as usize);
        assert_eq!(conf.nonce_len, case["nonce_len"].as_u64().unwrap() as usize);
        assert_eq!(conf.tag_len, case["tag_len"].as_u64().unwrap() as usize);
        assert_eq!(
            conf.packet_nonce_len,
            case["packet_nonce_len"].as_u64().unwrap() as usize
        );
        assert_eq!(conf.packet_cipher, case["packet_cipher"].as_bool().unwrap());
    }

    for case in fixture["ss2022"]["psk"].as_array().unwrap() {
        let info = crate::shadowsocks::ss2022::validate_psk_list(
            case["cipher"].as_str().unwrap(),
            case["password"].as_str().unwrap(),
        )
        .unwrap();
        assert_eq!(info.psk_count, case["psk_count"].as_u64().unwrap() as usize);
        assert_eq!(
            info.upsk_index,
            case["upsk_index"].as_u64().unwrap() as usize
        );
        assert_eq!(
            info.expected_key_len,
            case["expected_key_len"].as_u64().unwrap() as usize
        );
    }

    let tcp = &fixture["ss2022"]["tcp_header"];
    let tcp_contract = crate::shadowsocks::ss2022::tcp_header_contract(
        tcp["target"].as_str().unwrap(),
        tcp["timestamp"].as_u64().unwrap(),
        true,
    )
    .unwrap();
    assert_eq!(
        tcp_contract.fixed_header_len,
        tcp["fixed_header_len"].as_u64().unwrap() as usize
    );
    assert_eq!(
        tcp_contract.address_hex,
        tcp["address_hex"].as_str().unwrap()
    );
    assert!(tcp_contract.empty_initial_payload_has_padding);

    let udp = &fixture["ss2022"]["udp_packet_id"];
    let udp_contract =
        crate::shadowsocks::ss2022::udp_packet_id_contract(udp["cipher"].as_str().unwrap());
    assert_eq!(
        udp_contract.first_packet_id,
        udp["first_packet_id"].as_u64().unwrap()
    );
    assert_eq!(
        udp_contract.replay_window_size,
        udp["replay_window_size"].as_u64().unwrap() as usize
    );

    let replay = &fixture["ss2022"]["replay_filter"];
    let mut duplicate = crate::shadowsocks::ss2022::SlidingWindowFilter::new(
        replay["window"].as_u64().unwrap() as usize,
    );
    assert_eq!(
        duplicate.check_and_update(1),
        replay["first_packet_accepted"].as_bool().unwrap()
    );
    assert_eq!(
        duplicate.check_and_update(1),
        replay["duplicate_packet_accepted"].as_bool().unwrap()
    );
    let mut old = crate::shadowsocks::ss2022::SlidingWindowFilter::new(
        replay["window"].as_u64().unwrap() as usize,
    );
    for packet_id in [10, 11, 12, 13, 14] {
        assert!(old.check_and_update(packet_id));
    }
    assert_eq!(
        old.check_and_update(10),
        replay["too_old_packet_accepted"].as_bool().unwrap()
    );
}

#[test]
fn trojan_native_optin_matches_golden_fixture() {
    let fixture = fixture("outbound/protocol/trojan_native_optin.json");

    assert_eq!(
        crate::trojan::contract::ADAPTER_MODE,
        fixture["rust_adapter_mode"].as_str().unwrap()
    );
    assert_eq!(
        crate::trojan::contract::DEFAULT_GO_PATH,
        fixture["default_go_path"].as_bool().unwrap()
    );
    assert_eq!(
        crate::trojan::contract::PROTOCOL_SCOPE,
        fixture["protocol_scope"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect::<Vec<_>>()
            .as_slice()
    );

    for case in fixture["link_parser"].as_array().unwrap() {
        let parsed = crate::trojan::TrojanLink::parse(case["input"].as_str().unwrap()).unwrap();
        assert_eq!(parsed.server, case["server"].as_str().unwrap());
        assert_eq!(parsed.port, case["port"].as_u64().unwrap() as u16);
        assert_eq!(parsed.password, case["password"].as_str().unwrap());
        assert_eq!(parsed.sni, case["sni"].as_str().unwrap());
        assert_eq!(parsed.transport_type, case["type"].as_str().unwrap());
        assert_eq!(parsed.encryption, case["encryption"].as_str().unwrap());
        assert_eq!(parsed.host, case["host"].as_str().unwrap());
        assert_eq!(parsed.path, case["path"].as_str().unwrap());
        assert_eq!(parsed.service_name, case["serviceName"].as_str().unwrap());
        assert_eq!(
            parsed.allow_insecure,
            case["allowInsecure"].as_bool().unwrap()
        );
        assert_eq!(parsed.protocol, case["protocol"].as_str().unwrap());
        assert_eq!(parsed.export_url(), case["export"].as_str().unwrap());
        let chain = parse_link_chain(case["input"].as_str().unwrap()).unwrap();
        assert_eq!(chain.nodes[0].adapter_mode, "native-opt-in");
        assert_eq!(
            chain.property_address,
            case["property_address"].as_str().unwrap()
        );
        assert_eq!(
            chain.property_protocol,
            case["property_protocol"].as_str().unwrap()
        );
    }

    for case in fixture["metadata"].as_array().unwrap() {
        let metadata = crate::trojan::TrojanMetadata::parse(
            case["network"].as_str().unwrap(),
            case["input"].as_str().unwrap(),
        )
        .unwrap();
        assert_eq!(
            metadata.network.byte(),
            case["network_byte"].as_u64().unwrap() as u8
        );
        assert_eq!(
            metadata.metadata_type_byte(),
            case["type"].as_u64().unwrap() as u8
        );
        assert_eq!(metadata.hostname(), case["hostname"].as_str().unwrap());
        assert_eq!(metadata.port(), case["port"].as_u64().unwrap() as u16);
        assert_eq!(
            metadata.len().unwrap(),
            case["len"].as_u64().unwrap() as usize
        );
        assert_eq!(
            hex_encode(&metadata.encode().unwrap()),
            case["hex"].as_str().unwrap()
        );
    }

    let framing = &fixture["framing"];
    assert_eq!(
        crate::trojan::packet::password_sha224_hex(framing["password"].as_str().unwrap()),
        framing["password_sha224_hex"].as_str().unwrap()
    );
    assert_eq!(
        hex_encode(crate::trojan::packet::CRLF),
        framing["crlf_hex"].as_str().unwrap()
    );
    let tcp = &framing["tcp_request_header"];
    assert_eq!(
        hex_encode(
            &crate::trojan::packet::tcp_request_header(
                framing["password"].as_str().unwrap(),
                tcp["network"].as_str().unwrap(),
                tcp["target"].as_str().unwrap(),
                tcp["payload_ascii"].as_str().unwrap().as_bytes(),
            )
            .unwrap()
        ),
        tcp["header_hex"].as_str().unwrap()
    );
    let udp = &framing["udp_packet"];
    assert_eq!(
        hex_encode(
            &crate::trojan::packet::udp_packet(
                udp["target"].as_str().unwrap(),
                udp["payload_ascii"].as_str().unwrap().as_bytes(),
            )
            .unwrap()
        ),
        udp["packet_hex"].as_str().unwrap()
    );

    let transport = &fixture["transport_contract"];
    assert_eq!(
        crate::trojan::contract::DEFAULT_TROJAN_TLS_BEFORE_TROJANC,
        transport["default_trojan_tls_before_trojanc"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        crate::trojan::contract::TROJAN_GO_GRPC_CONTAINS_TLS,
        transport["trojan_go_grpc_contains_tls"].as_bool().unwrap()
    );
    assert_eq!(
        crate::trojan::contract::TROJAN_GO_GRPC_NO_OUTER_TLS,
        transport["trojan_go_grpc_no_outer_tls"].as_bool().unwrap()
    );
    assert_eq!(
        crate::trojan::contract::TROJAN_GO_SS_INNER_LAYER,
        transport["trojan_go_ss_inner_layer"].as_bool().unwrap()
    );
}
