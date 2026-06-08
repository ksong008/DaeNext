use super::*;
#[test]
pub(super) fn optin_runner_outbound_hysteria2_commands_match_fixture() {
    let fixture = load("outbound/protocol/hysteria2_native_optin.json");

    let contract = run_with_args(["outbound", "hysteria2", "contract"]);
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
        .find(|case| case["name"].as_str().unwrap() == "port-hopping")
        .unwrap();
    let link = run_with_args([
        "outbound",
        "hy2",
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
        link_json["pinSHA256_normal"].as_str().unwrap(),
        link_case["pinSHA256_normal"].as_str().unwrap()
    );

    let pin_case = &fixture["pin_sha256"][1];
    let pin = run_with_args([
        "outbound",
        "hysteria2",
        "pin",
        "--input",
        pin_case["input"].as_str().unwrap(),
    ]);
    assert_eq!(pin.exit_code, 0);
    assert_eq!(pin.stderr, "");
    let pin_json: Value = serde_json::from_str(&pin.stdout).unwrap();
    assert_eq!(
        pin_json["normalized"].as_str().unwrap(),
        pin_case["normalized"].as_str().unwrap()
    );

    let server_case = fixture["server_contract"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["port_hopping"].as_bool().unwrap())
        .unwrap();
    let server = run_with_args([
        "outbound",
        "hysteria2",
        "server",
        "--server",
        server_case["server"].as_str().unwrap(),
    ]);
    assert_eq!(server.exit_code, 0);
    assert_eq!(server.stderr, "");
    let server_json: Value = serde_json::from_str(&server.stdout).unwrap();
    assert_eq!(
        server_json["host_port"].as_str().unwrap(),
        server_case["host_port"].as_str().unwrap()
    );
    assert!(server_json["port_hopping"].as_bool().unwrap());

    let smoke = run_with_args([
        "outbound",
        "hy2",
        "smoke",
        "--link",
        link_case["input"].as_str().unwrap(),
    ]);
    assert_eq!(smoke.exit_code, 0, "{}", smoke.stdout);
    assert_eq!(smoke.stderr, "");
    let smoke_json: Value = serde_json::from_str(&smoke.stdout).unwrap();
    assert!(smoke_json["ok"].as_bool().unwrap());
    assert_eq!(smoke_json["underlay_network"].as_str().unwrap(), "udp");
    assert_eq!(
        smoke_json["transport_data_plane_deferred_to_item"]
            .as_u64()
            .unwrap(),
        113
    );
}
