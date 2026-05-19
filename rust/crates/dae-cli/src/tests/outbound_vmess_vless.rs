use super::*;

#[test]
fn optin_runner_outbound_vmess_commands_match_fixture() {
    let fixture = load("outbound/protocol/vmess_native_optin.json");

    let contract = run_with_args(["outbound", "vmess", "contract"]);
    assert_eq!(contract.exit_code, 0);
    assert_eq!(contract.stderr, "");
    let contract_json: Value = serde_json::from_str(&contract.stdout).unwrap();
    assert_eq!(
        contract_json["name"].as_str().unwrap(),
        fixture["name"].as_str().unwrap()
    );
    assert_eq!(
        contract_json["rust_adapter_mode"].as_str().unwrap(),
        fixture["rust_adapter_mode"].as_str().unwrap()
    );
    assert!(contract_json["default_go_path"].as_bool().unwrap());
    assert_eq!(
        contract_json["transport_contract"]["shared_transport_deferred_to_item"]
            .as_u64()
            .unwrap(),
        113
    );

    let link_case = fixture["link_parser"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"].as_str().unwrap() == "legacy-websocket-tls")
        .unwrap();
    let link = run_with_args([
        "outbound",
        "vmess",
        "link",
        "--link",
        link_case["input"].as_str().unwrap(),
    ]);
    assert_eq!(link.exit_code, 0, "{}", link.stdout);
    assert_eq!(link.stderr, "");
    let link_json: Value = serde_json::from_str(&link.stdout).unwrap();
    assert_eq!(
        link_json["export"].as_str().unwrap(),
        link_case["export"].as_str().unwrap()
    );
    assert_eq!(link_json["net"].as_str().unwrap(), "ws");

    let metadata_case = fixture["metadata"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"].as_str().unwrap() == "domain-tcp")
        .unwrap();
    let metadata = run_with_args([
        "outbound",
        "vmess",
        "metadata",
        "--network",
        metadata_case["network"].as_str().unwrap(),
        "--target",
        metadata_case["input"].as_str().unwrap(),
    ]);
    assert_eq!(metadata.exit_code, 0);
    assert_eq!(metadata.stderr, "");
    let metadata_json: Value = serde_json::from_str(&metadata.stdout).unwrap();
    assert_eq!(
        metadata_json["addr_hex"].as_str().unwrap(),
        metadata_case["addr_hex"].as_str().unwrap()
    );
    assert_eq!(
        metadata_json["network_byte"].as_u64().unwrap(),
        metadata_case["network_byte"].as_u64().unwrap()
    );

    let uuid = &fixture["uuid"];
    let uuid_cmd = run_with_args([
        "outbound",
        "vmess",
        "uuid",
        "--input",
        uuid["short_input"].as_str().unwrap(),
    ]);
    assert_eq!(uuid_cmd.exit_code, 0);
    assert_eq!(uuid_cmd.stderr, "");
    let uuid_json: Value = serde_json::from_str(&uuid_cmd.stdout).unwrap();
    assert_eq!(
        uuid_json["uuid"].as_str().unwrap(),
        uuid["short_uuid5"].as_str().unwrap()
    );

    let smoke = run_with_args([
        "outbound",
        "vmess",
        "smoke",
        "--link",
        link_case["input"].as_str().unwrap(),
        "--target",
        metadata_case["input"].as_str().unwrap(),
    ]);
    assert_eq!(smoke.exit_code, 0, "{}", smoke.stdout);
    assert_eq!(smoke.stderr, "");
    let smoke_json: Value = serde_json::from_str(&smoke.stdout).unwrap();
    assert!(smoke_json["ok"].as_bool().unwrap());
    assert_eq!(
        smoke_json["metadata_addr_hex"].as_str().unwrap(),
        metadata_case["addr_hex"].as_str().unwrap()
    );
    assert_eq!(
        smoke_json["transport_data_plane_deferred_to_item"]
            .as_u64()
            .unwrap(),
        113
    );

    let bad_aid = &fixture["unsupported"]["non_aead_alter_id_error"];
    let bad = run_with_args([
        "outbound",
        "vmess",
        "link",
        "--link",
        bad_aid["input"].as_str().unwrap(),
    ]);
    assert_eq!(bad.exit_code, 1);
    assert!(
        bad.stdout
            .contains(bad_aid["error_contains"].as_str().unwrap())
    );
}

#[test]
fn optin_runner_outbound_vless_commands_match_fixture() {
    let fixture = load("outbound/protocol/vless_native_optin.json");

    let contract = run_with_args(["outbound", "vless", "contract"]);
    assert_eq!(contract.exit_code, 0);
    assert_eq!(contract.stderr, "");
    let contract_json: Value = serde_json::from_str(&contract.stdout).unwrap();
    assert_eq!(
        contract_json["name"].as_str().unwrap(),
        fixture["name"].as_str().unwrap()
    );
    assert_eq!(
        contract_json["rust_adapter_mode"].as_str().unwrap(),
        fixture["rust_adapter_mode"].as_str().unwrap()
    );
    assert!(contract_json["default_go_path"].as_bool().unwrap());

    let link_case = fixture["link_parser"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"].as_str().unwrap() == "xhttp-flow-none-omitted")
        .unwrap();
    let link = run_with_args([
        "outbound",
        "vless",
        "link",
        "--link",
        link_case["input"].as_str().unwrap(),
    ]);
    assert_eq!(link.exit_code, 0, "{}", link.stdout);
    assert_eq!(link.stderr, "");
    let link_json: Value = serde_json::from_str(&link.stdout).unwrap();
    assert_eq!(
        link_json["export"].as_str().unwrap(),
        link_case["export"].as_str().unwrap()
    );
    assert_eq!(link_json["flow"].as_str().unwrap(), "");

    let key = &fixture["key"];
    let key_cmd = run_with_args([
        "outbound",
        "vless",
        "key",
        "--password",
        key["short_input"].as_str().unwrap(),
    ]);
    assert_eq!(key_cmd.exit_code, 0);
    assert_eq!(key_cmd.stderr, "");
    let key_json: Value = serde_json::from_str(&key_cmd.stdout).unwrap();
    assert_eq!(
        key_json["key_hex"].as_str().unwrap(),
        key["short_key_hex"].as_str().unwrap()
    );

    let header_case = fixture["request_header"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"].as_str().unwrap() == "tcp-vision-addons")
        .unwrap();
    let header = run_with_args([
        "outbound",
        "vless",
        "request-header",
        "--password",
        key["canonical"].as_str().unwrap(),
        "--flow",
        header_case["flow"].as_str().unwrap(),
        "--network",
        header_case["network"].as_str().unwrap(),
        "--target",
        header_case["target"].as_str().unwrap(),
        "--payload",
        header_case["payload_ascii"].as_str().unwrap(),
    ]);
    assert_eq!(header.exit_code, 0, "{}", header.stdout);
    assert_eq!(header.stderr, "");
    let header_json: Value = serde_json::from_str(&header.stdout).unwrap();
    assert_eq!(
        header_json["captured_hex"].as_str().unwrap(),
        header_case["captured_hex"].as_str().unwrap()
    );

    let smoke = run_with_args([
        "outbound",
        "vless",
        "smoke",
        "--link",
        fixture["link_parser"][0]["input"].as_str().unwrap(),
        "--target",
        "example.com:443",
        "--payload",
        "ping",
    ]);
    assert_eq!(smoke.exit_code, 0, "{}", smoke.stdout);
    assert_eq!(smoke.stderr, "");
    let smoke_json: Value = serde_json::from_str(&smoke.stdout).unwrap();
    assert!(smoke_json["ok"].as_bool().unwrap());
    assert_eq!(
        smoke_json["transport_data_plane_deferred_to_item"]
            .as_u64()
            .unwrap(),
        113
    );

    let bad = run_with_args([
        "outbound",
        "vless",
        "link",
        "--link",
        fixture["unsupported"]["tcp_bad_header_type_error"]["input"]
            .as_str()
            .unwrap(),
    ]);
    assert_eq!(bad.exit_code, 1);
    assert!(
        bad.stdout.contains(
            fixture["unsupported"]["tcp_bad_header_type_error"]["error_contains"]
                .as_str()
                .unwrap()
        )
    );
}
