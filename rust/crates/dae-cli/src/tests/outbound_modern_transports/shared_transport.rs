use super::*;
#[test]
pub(super) fn optin_runner_outbound_transport_commands_match_fixture() {
    let fixture = load("outbound/protocol/shared_transport_native_optin.json");

    let contract = run_with_args(["outbound", "transport", "contract"]);
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
    assert_eq!(contract_json["transport_scope"], fixture["transport_scope"]);
    assert_eq!(
        contract_json["grpc_transport"]["sample_cache_key_a"]
            .as_str()
            .unwrap(),
        fixture["grpc_transport"]["sample_cache_key_a"]
            .as_str()
            .unwrap()
    );

    let mode_case = fixture["xhttp_transport"]["mode_cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"].as_str().unwrap() == "auto reality download")
        .unwrap();
    let mode = run_with_args([
        "outbound",
        "transport",
        "xhttp-mode",
        "--mode",
        mode_case["mode"].as_str().unwrap(),
        "--scheme",
        mode_case["scheme"].as_str().unwrap(),
        "--security",
        mode_case["security"].as_str().unwrap(),
        "--download",
        "true",
    ]);
    assert_eq!(mode.exit_code, 0);
    assert_eq!(mode.stderr, "");
    let mode_json: Value = serde_json::from_str(&mode.stdout).unwrap();
    assert_eq!(
        mode_json["normalized"].as_str().unwrap(),
        mode_case["normalized"].as_str().unwrap()
    );
    assert_eq!(
        mode_json["ok"].as_bool().unwrap(),
        mode_case["ok"].as_bool().unwrap()
    );

    let alpn_case = fixture["xhttp_transport"]["alpn_cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"].as_str().unwrap() == "reality-h3")
        .unwrap();
    let alpn = run_with_args([
        "outbound",
        "transport",
        "xhttp-alpn",
        "--security",
        alpn_case["security"].as_str().unwrap(),
        "--alpn",
        alpn_case["alpn"].as_str().unwrap(),
    ]);
    assert_eq!(alpn.exit_code, 0);
    assert_eq!(alpn.stderr, "");
    let alpn_json: Value = serde_json::from_str(&alpn.stdout).unwrap();
    assert_eq!(
        alpn_json["ok"].as_bool().unwrap(),
        alpn_case["ok"].as_bool().unwrap()
    );
    assert_eq!(
        alpn_json["error_contains"].as_str().unwrap(),
        alpn_case["error_contains"].as_str().unwrap()
    );

    let path_case = &fixture["xhttp_transport"]["path_cases"][4];
    let path = run_with_args([
        "outbound",
        "transport",
        "xhttp-path",
        "--input",
        path_case["input"].as_str().unwrap(),
    ]);
    assert_eq!(path.exit_code, 0);
    assert_eq!(path.stderr, "");
    let path_json: Value = serde_json::from_str(&path.stdout).unwrap();
    assert_eq!(
        path_json["path"].as_str().unwrap(),
        path_case["path"].as_str().unwrap()
    );
    assert_eq!(
        path_json["query"].as_str().unwrap(),
        path_case["query"].as_str().unwrap()
    );

    let extra = run_with_args([
        "outbound",
        "transport",
        "xhttp-extra",
        "--raw",
        fixture["xhttp_transport"]["extra_raw"].as_str().unwrap(),
    ]);
    assert_eq!(extra.exit_code, 0);
    assert_eq!(extra.stderr, "");
    let extra_json: Value = serde_json::from_str(&extra.stdout).unwrap();
    assert_eq!(
        extra_json["canonical"].as_str().unwrap(),
        fixture["xhttp_transport"]["extra_canonical"]
            .as_str()
            .unwrap()
    );

    let grpc = run_with_args([
        "outbound",
        "transport",
        "grpc-cache-key",
        "--address",
        "addr:443",
        "--server-name",
        "sni.example",
        "--dialer",
        "dialer-1",
        "--allow-insecure",
        "true",
        "--mark",
        "1234",
        "--mptcp",
        "true",
    ]);
    assert_eq!(grpc.exit_code, 0);
    assert_eq!(grpc.stderr, "");
    let grpc_json: Value = serde_json::from_str(&grpc.stdout).unwrap();
    assert_eq!(
        grpc_json["cache_key"].as_str().unwrap(),
        fixture["grpc_transport"]["sample_cache_key_a"]
            .as_str()
            .unwrap()
    );

    let reality = run_with_args([
        "outbound",
        "transport",
        "reality",
        "--sid",
        fixture["reality_transport"]["sid_input"].as_str().unwrap(),
        "--pbk",
        fixture["reality_transport"]["pbk_input"].as_str().unwrap(),
        "--spx",
        fixture["reality_transport"]["spx_input"].as_str().unwrap(),
    ]);
    assert_eq!(reality.exit_code, 0);
    assert_eq!(reality.stderr, "");
    let reality_json: Value = serde_json::from_str(&reality.stdout).unwrap();
    assert_eq!(
        reality_json["sid_decoded_hex"].as_str().unwrap(),
        fixture["reality_transport"]["sid_decoded_hex"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        reality_json["pbk_decoded_hex"].as_str().unwrap(),
        fixture["reality_transport"]["pbk_decoded_hex"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        reality_json["spider_y"],
        fixture["reality_transport"]["spider_y"]
    );

    let smoke = run_with_args(["outbound", "transport", "smoke"]);
    assert_eq!(smoke.exit_code, 0, "{}", smoke.stdout);
    assert_eq!(smoke.stderr, "");
    let smoke_json: Value = serde_json::from_str(&smoke.stdout).unwrap();
    assert!(smoke_json["ok"].as_bool().unwrap());
    assert_eq!(
        smoke_json["rust_adapter_mode"].as_str().unwrap(),
        fixture["rust_adapter_mode"].as_str().unwrap()
    );
    assert!(
        smoke_json["true_transport_data_plane_deferred"]
            .as_bool()
            .unwrap()
    );
}
