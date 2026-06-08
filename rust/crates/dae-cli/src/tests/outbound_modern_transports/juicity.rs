use super::*;
#[test]
pub(super) fn optin_runner_outbound_juicity_commands_match_fixture() {
    let fixture = load("outbound/protocol/juicity_native_optin.json");

    let contract = run_with_args(["outbound", "juicity", "contract"]);
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
        contract_json["quic_contract"]["enable_datagrams"]
            .as_bool()
            .unwrap(),
        fixture["quic_contract"]["enable_datagrams"]
            .as_bool()
            .unwrap()
    );

    let link_case = fixture["link_parser"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"].as_str().unwrap() == "basic-urlbase64-pin")
        .unwrap();
    let link = run_with_args([
        "outbound",
        "juicity",
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
        link_json["pinned_certchain_decoded"]["format"]
            .as_str()
            .unwrap(),
        link_case["pinned_certchain_decoded"]["format"]
            .as_str()
            .unwrap()
    );

    let uuid = run_with_args([
        "outbound",
        "juicity",
        "uuid",
        "--user",
        fixture["uuid_contract"]["valid"].as_str().unwrap(),
    ]);
    assert_eq!(uuid.exit_code, 0);
    assert_eq!(uuid.stderr, "");
    let uuid_json: Value = serde_json::from_str(&uuid.stdout).unwrap();
    assert!(uuid_json["ok"].as_bool().unwrap());

    let bad_uuid = run_with_args([
        "outbound",
        "juicity",
        "uuid",
        "--user",
        fixture["uuid_contract"]["invalid"].as_str().unwrap(),
    ]);
    assert_eq!(bad_uuid.exit_code, 1);
    assert!(
        bad_uuid.stdout.contains(
            fixture["uuid_contract"]["invalid_error"]["error_contains"]
                .as_str()
                .unwrap()
        )
    );

    let pin_case = fixture["pinned_certchain_sha256"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"].as_str().unwrap() == "std-base64")
        .unwrap();
    let pin = run_with_args([
        "outbound",
        "juicity",
        "pin",
        "--input",
        pin_case["input"].as_str().unwrap(),
    ]);
    assert_eq!(pin.exit_code, 0, "{}", pin.stdout);
    assert_eq!(pin.stderr, "");
    let pin_json: Value = serde_json::from_str(&pin.stdout).unwrap();
    assert_eq!(
        pin_json["format"].as_str().unwrap(),
        pin_case["format"].as_str().unwrap()
    );
    assert_eq!(
        pin_json["decoded_hex"].as_str().unwrap(),
        pin_case["decoded_hex"].as_str().unwrap()
    );

    let underlay = run_with_args([
        "outbound",
        "juicity",
        "underlay",
        "--network",
        "tcp",
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
        fixture["underlay_contract"]["tcp_request"]["underlay_network"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        underlay_json["underlay_mptcp"].as_bool().unwrap(),
        fixture["underlay_contract"]["tcp_request"]["underlay_mptcp"]
            .as_bool()
            .unwrap()
    );

    let smoke = run_with_args([
        "outbound",
        "juicity",
        "smoke",
        "--link",
        link_case["input"].as_str().unwrap(),
    ]);
    assert_eq!(smoke.exit_code, 0, "{}", smoke.stdout);
    assert_eq!(smoke.stderr, "");
    let smoke_json: Value = serde_json::from_str(&smoke.stdout).unwrap();
    assert!(smoke_json["ok"].as_bool().unwrap());
    assert!(!smoke_json["quic_enable_datagrams"].as_bool().unwrap());
    assert_eq!(
        smoke_json["udp_port_zero_packet_conn"].as_str().unwrap(),
        fixture["underlay_contract"]["udp_port_zero_packet_conn"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        smoke_json["transport_data_plane_deferred_to_item"]
            .as_u64()
            .unwrap(),
        fixture["underlay_contract"]["true_quic_data_plane_deferred"]
            .as_u64()
            .unwrap()
    );
}
