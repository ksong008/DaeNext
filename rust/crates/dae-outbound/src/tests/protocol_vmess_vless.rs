use super::*;

#[test]
fn vmess_native_optin_matches_golden_fixture() {
    let fixture = fixture("outbound/protocol/vmess_native_optin.json");

    assert_eq!(
        crate::vmess::contract::ADAPTER_MODE,
        fixture["rust_adapter_mode"].as_str().unwrap()
    );
    assert_eq!(
        crate::vmess::contract::DEFAULT_GO_PATH,
        fixture["default_go_path"].as_bool().unwrap()
    );
    assert_eq!(
        crate::vmess::contract::PROTOCOL_SCOPE,
        fixture["protocol_scope"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect::<Vec<_>>()
            .as_slice()
    );

    for case in fixture["link_parser"].as_array().unwrap() {
        let parsed = crate::vmess::VMessLink::parse(case["input"].as_str().unwrap()).unwrap();
        parsed.validate_aead().unwrap();
        parsed.validate_transport().unwrap();
        assert_eq!(parsed.ps, case["ps"].as_str().unwrap());
        assert_eq!(parsed.add, case["add"].as_str().unwrap());
        assert_eq!(parsed.port, case["port"].as_str().unwrap());
        assert_eq!(parsed.id, case["id"].as_str().unwrap());
        assert_eq!(parsed.aid, case["aid"].as_str().unwrap());
        assert_eq!(parsed.net, case["net"].as_str().unwrap());
        assert_eq!(parsed.r#type, case["type"].as_str().unwrap());
        assert_eq!(parsed.host, case["host"].as_str().unwrap());
        assert_eq!(parsed.sni, case["sni"].as_str().unwrap());
        assert_eq!(parsed.path, case["path"].as_str().unwrap());
        assert_eq!(parsed.tls, case["tls"].as_str().unwrap());
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
        assert_eq!(chain.property_name, case["property_name"].as_str().unwrap());
        assert_eq!(
            chain.property_protocol,
            case["property_protocol"].as_str().unwrap()
        );
    }

    let bad_aid = &fixture["unsupported"]["non_aead_alter_id_error"];
    let bad = crate::vmess::VMessLink::parse(bad_aid["input"].as_str().unwrap()).unwrap();
    let err = bad.validate_aead().unwrap_err().to_string();
    assert!(err.contains(bad_aid["error_contains"].as_str().unwrap()));
    assert_eq!(
        crate::vmess::contract::VMESS_REALITY_MUST_ERROR,
        fixture["transport_contract"]["vmess_reality_must_error"]
            .as_bool()
            .unwrap()
    );

    let uuid = &fixture["uuid"];
    assert_eq!(
        crate::vmess::uuid::normalize_vmess_uuid(uuid["canonical"].as_str().unwrap()),
        uuid["canonical"].as_str().unwrap()
    );
    assert_eq!(
        crate::vmess::uuid::normalize_vmess_uuid(uuid["short_input"].as_str().unwrap()),
        uuid["short_uuid5"].as_str().unwrap()
    );
    assert_eq!(
        crate::vmess::uuid::normalize_vmess_uuid(uuid["long_input"].as_str().unwrap()),
        uuid["long_uuid5"].as_str().unwrap()
    );

    for case in fixture["metadata"].as_array().unwrap() {
        let metadata = crate::vmess::VMessMetadata::parse(
            case["network"].as_str().unwrap(),
            case["input"].as_str().unwrap(),
        )
        .unwrap();
        assert_eq!(
            metadata.network.byte(),
            case["network_byte"].as_u64().unwrap() as u8
        );
        assert_eq!(
            metadata.metadata_type().byte(),
            case["type"].as_u64().unwrap() as u8
        );
        assert_eq!(metadata.hostname(), case["hostname"].as_str().unwrap());
        assert_eq!(metadata.port(), case["port"].as_u64().unwrap() as u16);
        assert_eq!(
            metadata.addr_len(),
            case["addr_len"].as_u64().unwrap() as usize
        );
        let encoded = metadata.encode_addr().unwrap();
        assert_eq!(encoded.len(), case["packed_len"].as_u64().unwrap() as usize);
        assert_eq!(hex_encode(&encoded), case["addr_hex"].as_str().unwrap());
    }

    let header = &fixture["header_contract"];
    assert_eq!(
        crate::vmess::contract::HEADER_VERSION,
        header["version"].as_u64().unwrap() as u8
    );
    assert_eq!(
        crate::vmess::contract::OPTION_CHUNK_STREAM,
        header["option_chunk_stream"].as_u64().unwrap() as u8
    );
    assert_eq!(
        crate::vmess::contract::OPTION_CHUNK_LENGTH_MASKING,
        header["option_chunk_length_masking"].as_u64().unwrap() as u8
    );
    assert_eq!(
        crate::vmess::contract::OPTION_GLOBAL_PADDING,
        header["option_global_padding"].as_u64().unwrap() as u8
    );
    assert_eq!(
        crate::vmess::contract::SECURITY_AUTO_CIPHER,
        header["security_auto_cipher"].as_u64().unwrap() as u8
    );
}

#[test]
fn vless_native_optin_matches_golden_fixture() {
    let fixture = fixture("outbound/protocol/vless_native_optin.json");

    assert_eq!(
        crate::vless::contract::ADAPTER_MODE,
        fixture["rust_adapter_mode"].as_str().unwrap()
    );
    assert_eq!(
        crate::vless::contract::DEFAULT_GO_PATH,
        fixture["default_go_path"].as_bool().unwrap()
    );
    assert_eq!(
        crate::vless::contract::PROTOCOL_SCOPE,
        fixture["protocol_scope"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect::<Vec<_>>()
            .as_slice()
    );

    for case in fixture["link_parser"].as_array().unwrap() {
        let parsed = crate::vless::VLESSLink::parse(case["input"].as_str().unwrap()).unwrap();
        parsed.validate_flow_client(true).unwrap();
        parsed.validate_transport_contract().unwrap();
        assert_eq!(parsed.ps, case["ps"].as_str().unwrap());
        assert_eq!(parsed.add, case["add"].as_str().unwrap());
        assert_eq!(parsed.port, case["port"].as_str().unwrap());
        assert_eq!(parsed.id, case["id"].as_str().unwrap());
        assert_eq!(parsed.net, case["net"].as_str().unwrap());
        assert_eq!(parsed.r#type, case["type"].as_str().unwrap());
        assert_eq!(parsed.host, case["host"].as_str().unwrap());
        assert_eq!(parsed.sni, case["sni"].as_str().unwrap());
        assert_eq!(parsed.path, case["path"].as_str().unwrap());
        assert_eq!(parsed.xhttp_mode, case["mode"].as_str().unwrap());
        assert_eq!(parsed.xhttp_extra, case["extra"].as_str().unwrap());
        assert_eq!(parsed.tls, case["tls"].as_str().unwrap());
        assert_eq!(parsed.flow, case["flow"].as_str().unwrap());
        assert_eq!(parsed.alpn, case["alpn"].as_str().unwrap());
        assert_eq!(
            parsed.allow_insecure,
            case["allowInsecure"].as_bool().unwrap()
        );
        assert_eq!(parsed.fingerprint, case["fp"].as_str().unwrap());
        assert_eq!(parsed.public_key, case["pbk"].as_str().unwrap());
        assert_eq!(parsed.short_id, case["sid"].as_str().unwrap());
        assert_eq!(parsed.spider_x, case["spx"].as_str().unwrap());
        assert_eq!(parsed.protocol, case["protocol"].as_str().unwrap());
        assert_eq!(parsed.export_url(), case["export"].as_str().unwrap());
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
        let parsed = crate::vless::VLESSLink::parse(case["input"].as_str().unwrap()).unwrap();
        assert_eq!(
            parsed.allow_insecure,
            case["allowInsecure"].as_bool().unwrap()
        );
        assert_eq!(parsed.export_url(), case["export"].as_str().unwrap());
    }

    let unsupported = &fixture["unsupported"];
    let bad = crate::vless::VLESSLink {
        flow: unsupported["unsupported_flow_error"]["input_flow"]
            .as_str()
            .unwrap()
            .to_owned(),
        ..crate::vless::VLESSLink::parse(fixture["link_parser"][0]["input"].as_str().unwrap())
            .unwrap()
    };
    assert!(
        bad.validate_flow_client(true)
            .unwrap_err()
            .to_string()
            .contains(
                unsupported["unsupported_flow_error"]["error_contains"]
                    .as_str()
                    .unwrap()
            )
    );
    let server = crate::vless::VLESSLink {
        flow: crate::vless::contract::XTLS_RPRX_VISION.to_owned(),
        ..crate::vless::VLESSLink::parse(fixture["link_parser"][0]["input"].as_str().unwrap())
            .unwrap()
    };
    assert!(
        server
            .validate_flow_client(false)
            .unwrap_err()
            .to_string()
            .contains(
                unsupported["server_mode_vision_error"]["error_contains"]
                    .as_str()
                    .unwrap()
            )
    );
    let bad_tcp = crate::vless::VLESSLink::parse(
        unsupported["tcp_bad_header_type_error"]["input"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    assert!(
        bad_tcp
            .validate_transport_contract()
            .unwrap_err()
            .to_string()
            .contains(
                unsupported["tcp_bad_header_type_error"]["error_contains"]
                    .as_str()
                    .unwrap()
            )
    );

    let key = &fixture["key"];
    assert_eq!(
        hex_encode(&crate::vless::password_to_key(key["canonical"].as_str().unwrap()).unwrap()),
        key["canonical_key_hex"].as_str().unwrap()
    );
    assert_eq!(
        crate::vmess::uuid::normalize_vmess_uuid(key["short_input"].as_str().unwrap()),
        key["short_uuid5"].as_str().unwrap()
    );
    assert_eq!(
        hex_encode(&crate::vless::password_to_key(key["short_input"].as_str().unwrap()).unwrap()),
        key["short_key_hex"].as_str().unwrap()
    );

    for case in fixture["request_header"].as_array().unwrap() {
        let key =
            crate::vless::password_to_key(fixture["key"]["canonical"].as_str().unwrap()).unwrap();
        let got = crate::vless::packet::first_write_bytes(
            &key,
            case["flow"].as_str().unwrap(),
            case["network"].as_str().unwrap(),
            case["target"].as_str().unwrap(),
            case["mux"].as_bool().unwrap(),
            case["payload_ascii"].as_str().unwrap().as_bytes(),
        )
        .unwrap();
        assert_eq!(hex_encode(&got), case["captured_hex"].as_str().unwrap());
    }

    let transport = &fixture["transport_contract"];
    assert_eq!(
        crate::vless::contract::XTLS_RPRX_VISION,
        transport["vision_flow"].as_str().unwrap()
    );
    assert_eq!(
        crate::vless::contract::VISION_REQUIRES_TLS_OR_REALITY_HOOK,
        transport["vision_requires_tls_or_reality_hook"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        crate::vless::contract::SHARED_TRANSPORT_DEFERRED_TO_ITEM,
        transport["shared_transport_deferred_to_item"]
            .as_u64()
            .unwrap() as u16
    );
}
