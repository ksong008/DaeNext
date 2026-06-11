use super::*;

#[test]
fn runtime_runner_outbound_shadowsocks_commands_match_fixture() {
    let fixture = load("outbound/protocol/shadowsocks_rust_native.json");

    let contract = run_with_args(["outbound", "shadowsocks", "contract"]);
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

    let link_case = fixture["link_parser"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"].as_str().unwrap() == "ss2022-multi-psk")
        .unwrap();
    let link = run_with_args([
        "outbound",
        "shadowsocks",
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
    assert_eq!(
        link_json["capability"].as_str().unwrap(),
        "shadowsocks-2022"
    );

    let cipher_case = fixture["cipher_dispatch"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"].as_str().unwrap() == "stream-legacy")
        .unwrap();
    let cipher = run_with_args([
        "outbound",
        "shadowsocks",
        "cipher",
        "--cipher",
        cipher_case["cipher"].as_str().unwrap(),
    ]);
    assert_eq!(cipher.exit_code, 0);
    assert_eq!(cipher.stderr, "");
    let cipher_json: Value = serde_json::from_str(&cipher.stdout).unwrap();
    assert_eq!(
        cipher_json["protocol_dialer"].as_str().unwrap(),
        cipher_case["protocol_dialer"].as_str().unwrap()
    );

    let metadata_case = fixture["metadata"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"].as_str().unwrap() == "domain")
        .unwrap();
    let metadata = run_with_args([
        "outbound",
        "shadowsocks",
        "metadata",
        "--target",
        metadata_case["input"].as_str().unwrap(),
    ]);
    assert_eq!(metadata.exit_code, 0);
    assert_eq!(metadata.stderr, "");
    let metadata_json: Value = serde_json::from_str(&metadata.stdout).unwrap();
    assert_eq!(
        metadata_json["hex"].as_str().unwrap(),
        metadata_case["hex"].as_str().unwrap()
    );

    let psk_case = fixture["ss2022"]["psk"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"].as_str().unwrap() == "multi-aes128")
        .unwrap();
    let psk = run_with_args([
        "outbound",
        "shadowsocks",
        "ss2022-psk",
        "--cipher",
        psk_case["cipher"].as_str().unwrap(),
        "--password",
        psk_case["password"].as_str().unwrap(),
    ]);
    assert_eq!(psk.exit_code, 0);
    assert_eq!(psk.stderr, "");
    let psk_json: Value = serde_json::from_str(&psk.stdout).unwrap();
    assert_eq!(
        psk_json["psk_count"].as_u64().unwrap(),
        psk_case["psk_count"].as_u64().unwrap()
    );

    let replay = run_with_args(["outbound", "ss", "replay-filter", "--window", "4"]);
    assert_eq!(replay.exit_code, 0);
    assert_eq!(replay.stderr, "");
    let replay_json: Value = serde_json::from_str(&replay.stdout).unwrap();
    assert!(!replay_json["duplicate_packet_accepted"].as_bool().unwrap());
    assert!(!replay_json["too_old_packet_accepted"].as_bool().unwrap());

    let smoke = run_with_args([
        "outbound",
        "shadowsocks",
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
        smoke_json["metadata_hex"].as_str().unwrap(),
        metadata_case["hex"].as_str().unwrap()
    );
    assert!(smoke_json["replay_duplicate_rejected"].as_bool().unwrap());
}

#[test]
fn runtime_runner_outbound_trojan_commands_match_fixture() {
    let fixture = load("outbound/protocol/trojan_rust_native.json");

    let contract = run_with_args(["outbound", "trojan", "contract"]);
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

    let link_case = fixture["link_parser"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"].as_str().unwrap() == "trojan-type-forces-trojan-go-grpc")
        .unwrap();
    let link = run_with_args([
        "outbound",
        "trojan",
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
    assert_eq!(
        link_json["serviceName"].as_str().unwrap(),
        link_case["serviceName"].as_str().unwrap()
    );
    assert_eq!(link_json["protocol"].as_str().unwrap(), "trojan-go");

    let metadata_case = fixture["metadata"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"].as_str().unwrap() == "domain-udp")
        .unwrap();
    let metadata = run_with_args([
        "outbound",
        "trojan",
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
        metadata_json["hex"].as_str().unwrap(),
        metadata_case["hex"].as_str().unwrap()
    );
    assert_eq!(
        metadata_json["network_byte"].as_u64().unwrap(),
        metadata_case["network_byte"].as_u64().unwrap()
    );

    let tcp_case = &fixture["framing"]["tcp_request_header"];
    let tcp = run_with_args([
        "outbound",
        "trojan",
        "tcp-header",
        "--password",
        fixture["framing"]["password"].as_str().unwrap(),
        "--network",
        tcp_case["network"].as_str().unwrap(),
        "--target",
        tcp_case["target"].as_str().unwrap(),
        "--payload",
        tcp_case["payload_ascii"].as_str().unwrap(),
    ]);
    assert_eq!(tcp.exit_code, 0);
    assert_eq!(tcp.stderr, "");
    let tcp_json: Value = serde_json::from_str(&tcp.stdout).unwrap();
    assert_eq!(
        tcp_json["header_hex"].as_str().unwrap(),
        tcp_case["header_hex"].as_str().unwrap()
    );

    let udp_case = &fixture["framing"]["udp_packet"];
    let udp = run_with_args([
        "outbound",
        "trojan",
        "udp-packet",
        "--target",
        udp_case["target"].as_str().unwrap(),
        "--payload",
        udp_case["payload_ascii"].as_str().unwrap(),
    ]);
    assert_eq!(udp.exit_code, 0);
    assert_eq!(udp.stderr, "");
    let udp_json: Value = serde_json::from_str(&udp.stdout).unwrap();
    assert_eq!(
        udp_json["packet_hex"].as_str().unwrap(),
        udp_case["packet_hex"].as_str().unwrap()
    );

    let smoke = run_with_args([
        "outbound",
        "trojan-go",
        "smoke",
        "--link",
        link_case["input"].as_str().unwrap(),
        "--target",
        tcp_case["target"].as_str().unwrap(),
        "--payload",
        tcp_case["payload_ascii"].as_str().unwrap(),
    ]);
    assert_eq!(smoke.exit_code, 0, "{}", smoke.stdout);
    assert_eq!(smoke.stderr, "");
    let smoke_json: Value = serde_json::from_str(&smoke.stdout).unwrap();
    assert!(smoke_json["ok"].as_bool().unwrap());
    assert_eq!(
        smoke_json["tcp_header_hex"].as_str().unwrap(),
        tcp_case["header_hex"].as_str().unwrap()
    );
    assert_eq!(
        smoke_json["udp_packet_hex"].as_str().unwrap(),
        udp_case["packet_hex"].as_str().unwrap()
    );
}
