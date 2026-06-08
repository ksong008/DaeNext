use super::*;
#[test]
pub(super) fn optin_runner_outbound_anytls_commands_match_fixture() {
    let fixture = load("outbound/protocol/anytls_native_optin.json");

    let contract = run_with_args(["outbound", "anytls", "contract"]);
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
        .find(|case| case["case"].as_str().unwrap() == "basic-insecure")
        .unwrap();
    let link = run_with_args([
        "outbound",
        "anytls",
        "link",
        "--link",
        link_case["input"].as_str().unwrap(),
    ]);
    assert_eq!(link.exit_code, 0, "{}", link.stdout);
    assert_eq!(link.stderr, "");
    let link_json: Value = serde_json::from_str(&link.stdout).unwrap();
    assert_eq!(
        link_json["link_preserved"].as_str().unwrap(),
        link_case["property_link"].as_str().unwrap()
    );
    assert_eq!(
        link_json["tls_server_name"].as_str().unwrap(),
        link_case["tls_server_name"].as_str().unwrap()
    );

    let auth = run_with_args([
        "outbound",
        "anytls",
        "auth-key",
        "--auth",
        fixture["auth_key"]["auth"].as_str().unwrap(),
    ]);
    assert_eq!(auth.exit_code, 0);
    assert_eq!(auth.stderr, "");
    let auth_json: Value = serde_json::from_str(&auth.stdout).unwrap();
    assert_eq!(
        auth_json["sha256_hex"].as_str().unwrap(),
        fixture["auth_key"]["sha256_hex"].as_str().unwrap()
    );
    assert_eq!(
        auth_json["handshake_hex"].as_str().unwrap(),
        fixture["session_contract"]["first_handshake"]["auth_key_then_zero_u16_hex"]
            .as_str()
            .unwrap()
    );

    let frame = run_with_args(["outbound", "anytls", "frame", "--target", "example.com:443"]);
    assert_eq!(frame.exit_code, 0);
    assert_eq!(frame.stderr, "");
    let frame_json: Value = serde_json::from_str(&frame.stdout).unwrap();
    assert_eq!(
        frame_json["settings_frame_hex"].as_str().unwrap(),
        fixture["session_contract"]["frame"]["settings_frame_hex"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        frame_json["psh_addr_frame_hex"].as_str().unwrap(),
        fixture["session_contract"]["frame"]["psh_addr_frame_hex"]
            .as_str()
            .unwrap()
    );

    let packet = run_with_args([
        "outbound",
        "anytls",
        "packet",
        "--target",
        fixture["packet_stream"]["udp_input_target"]
            .as_str()
            .unwrap(),
        "--payload",
        "ping",
    ]);
    assert_eq!(packet.exit_code, 0);
    assert_eq!(packet.stderr, "");
    let packet_json: Value = serde_json::from_str(&packet.stdout).unwrap();
    assert_eq!(
        packet_json["udp_stream_target"].as_str().unwrap(),
        fixture["packet_stream"]["udp_stream_target"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        packet_json["first_write_hex"].as_str().unwrap(),
        fixture["packet_stream"]["first_write_hex"]
            .as_str()
            .unwrap()
    );

    let underlay = run_with_args([
        "outbound",
        "anytls",
        "underlay",
        "--network",
        "udp",
        "--mark",
        "1234",
        "--mptcp",
        "true",
    ]);
    assert_eq!(underlay.exit_code, 0);
    assert_eq!(underlay.stderr, "");
    let underlay_json: Value = serde_json::from_str(&underlay.stdout).unwrap();
    assert_eq!(
        underlay_json["underlay_network"].as_str().unwrap(),
        fixture["underlay_contract"]["udp_request"]["underlay_network"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        underlay_json["underlay_mptcp"].as_bool().unwrap(),
        fixture["underlay_contract"]["udp_request"]["underlay_mptcp"]
            .as_bool()
            .unwrap()
    );

    let smoke = run_with_args([
        "outbound",
        "anytls",
        "smoke",
        "--link",
        link_case["input"].as_str().unwrap(),
    ]);
    assert_eq!(smoke.exit_code, 0, "{}", smoke.stdout);
    assert_eq!(smoke.stderr, "");
    let smoke_json: Value = serde_json::from_str(&smoke.stdout).unwrap();
    assert!(smoke_json["ok"].as_bool().unwrap());
    assert_eq!(
        smoke_json["udp_stream_target"].as_str().unwrap(),
        fixture["packet_stream"]["udp_stream_target"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        smoke_json["transport_data_plane_deferred_to_item"]
            .as_u64()
            .unwrap(),
        fixture["underlay_contract"]["true_session_data_plane_deferred"]
            .as_u64()
            .unwrap()
    );
}
