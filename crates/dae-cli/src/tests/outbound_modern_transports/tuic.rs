use super::*;
#[test]
pub(super) fn runtime_runner_outbound_tuic_commands_match_fixture() {
    let fixture = load("outbound/protocol/tuic_rust_native.json");

    let contract = run_with_args(["outbound", "tuic", "contract"]);
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
    assert_eq!(
        contract_json["udp_relay_mode"]["protocol_effective_mode"]
            .as_str()
            .unwrap(),
        fixture["udp_relay_mode"]["protocol_effective_mode"]
            .as_str()
            .unwrap()
    );

    let link_case = fixture["link_parser"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"].as_str().unwrap() == "basic-quic-flag")
        .unwrap();
    let link = run_with_args([
        "outbound",
        "tuic",
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
        link_json["udp_relay_mode"].as_str().unwrap(),
        link_case["udp_relay_mode"].as_str().unwrap()
    );

    let uuid = run_with_args([
        "outbound",
        "tuic",
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
        "tuic",
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

    let underlay = run_with_args([
        "outbound",
        "tuic",
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
        "tuic",
        "smoke",
        "--link",
        link_case["input"].as_str().unwrap(),
    ]);
    assert_eq!(smoke.exit_code, 0, "{}", smoke.stdout);
    assert_eq!(smoke.stderr, "");
    let smoke_json: Value = serde_json::from_str(&smoke.stdout).unwrap();
    assert!(smoke_json["ok"].as_bool().unwrap());
    assert_eq!(
        smoke_json["udp_relay_effective_mode"].as_str().unwrap(),
        fixture["udp_relay_mode"]["protocol_effective_mode"]
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
