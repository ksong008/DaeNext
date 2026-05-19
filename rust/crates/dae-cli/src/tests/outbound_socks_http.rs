use super::*;

#[test]
fn optin_runner_outbound_socks5_commands_match_fixture() {
    let fixture = load("outbound/protocol/socks5_native_optin.json");

    let contract = run_with_args(["outbound", "socks5", "contract"]);
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
        contract_json["link_parser"]["protocol"].as_str().unwrap(),
        fixture["link_parser"]["protocol"].as_str().unwrap()
    );

    let domain = fixture["address_codec"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"].as_str().unwrap() == "domain")
        .unwrap();
    let codec = run_with_args([
        "outbound",
        "socks5",
        "codec",
        "--target",
        domain["input"].as_str().unwrap(),
    ]);
    assert_eq!(codec.exit_code, 0);
    assert_eq!(codec.stderr, "");
    let codec_json: Value = serde_json::from_str(&codec.stdout).unwrap();
    assert_eq!(
        codec_json["encoded_hex"].as_str().unwrap(),
        domain["hex"].as_str().unwrap()
    );

    let handshake = &fixture["handshake"];
    let hs = run_with_args([
        "outbound",
        "socks5",
        "handshake",
        "--target",
        "example.com:443",
        "--username",
        "user",
        "--password",
        "pass",
    ]);
    assert_eq!(hs.exit_code, 0);
    assert_eq!(hs.stderr, "");
    let hs_json: Value = serde_json::from_str(&hs.stdout).unwrap();
    assert_eq!(
        hs_json["greeting_hex"].as_str().unwrap(),
        handshake["greeting_with_auth_hex"].as_str().unwrap()
    );
    assert_eq!(
        hs_json["auth_hex"].as_str().unwrap(),
        handshake["username_password_auth_hex"].as_str().unwrap()
    );
    assert_eq!(
        hs_json["request_hex"].as_str().unwrap(),
        handshake["connect_example_com_443_hex"].as_str().unwrap()
    );

    let udp = &fixture["udp_packet"];
    let packet = run_with_args([
        "outbound",
        "socks5",
        "udp-packet",
        "--target",
        udp["target"].as_str().unwrap(),
        "--payload",
        udp["payload_ascii"].as_str().unwrap(),
    ]);
    assert_eq!(packet.exit_code, 0);
    assert_eq!(packet.stderr, "");
    let packet_json: Value = serde_json::from_str(&packet.stdout).unwrap();
    assert_eq!(
        packet_json["packet_hex"].as_str().unwrap(),
        udp["write_packet_hex"].as_str().unwrap()
    );

    let (proxy, handle) = spawn_fake_socks5_server(true, 1);
    let smoke = run_with_args([
        "outbound",
        "socks5",
        "smoke",
        "--proxy",
        &proxy,
        "--target",
        "example.com:443",
        "--username",
        "user",
        "--password",
        "pass",
    ]);
    assert_eq!(smoke.exit_code, 0, "{}", smoke.stdout);
    assert_eq!(smoke.stderr, "");
    handle.join().unwrap();
    let smoke_json: Value = serde_json::from_str(&smoke.stdout).unwrap();
    assert!(smoke_json["ok"].as_bool().unwrap());
    assert_eq!(smoke_json["method"].as_u64().unwrap(), 2);
    assert_eq!(smoke_json["bind"].as_str().unwrap(), "127.0.0.1:5300");

    let (proxy, handle) = spawn_fake_socks5_server(false, 3);
    let udp_smoke = run_with_args([
        "outbound",
        "socks5",
        "smoke",
        "--proxy",
        &proxy,
        "--target",
        "0.0.0.0:0",
        "--command",
        "udp-associate",
    ]);
    assert_eq!(udp_smoke.exit_code, 0, "{}", udp_smoke.stdout);
    assert_eq!(udp_smoke.stderr, "");
    handle.join().unwrap();
    let udp_smoke_json: Value = serde_json::from_str(&udp_smoke.stdout).unwrap();
    assert!(udp_smoke_json["ok"].as_bool().unwrap());
    assert_eq!(udp_smoke_json["method"].as_u64().unwrap(), 0);
    assert_eq!(udp_smoke_json["command"].as_str().unwrap(), "udp-associate");
}

#[test]
fn optin_runner_outbound_http_commands_match_fixture() {
    let fixture = load("outbound/protocol/http_native_optin.json");

    let contract = run_with_args(["outbound", "http", "contract"]);
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
        .find(|case| case["name"].as_str().unwrap() == "https-flags")
        .unwrap();
    let link = run_with_args([
        "outbound",
        "http",
        "link",
        "--link",
        link_case["input"].as_str().unwrap(),
    ]);
    assert_eq!(link.exit_code, 0);
    assert_eq!(link.stderr, "");
    let link_json: Value = serde_json::from_str(&link.stdout).unwrap();
    assert_eq!(
        link_json["export"].as_str().unwrap(),
        link_case["export"].as_str().unwrap()
    );
    assert!(link_json["allowInsecure"].as_bool().unwrap());

    let connect_case = fixture["connect"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"].as_str().unwrap() == "connect-basic-auth-host-override")
        .unwrap();
    let connect = run_with_args([
        "outbound",
        "http",
        "connect",
        "--target",
        connect_case["target"].as_str().unwrap(),
        "--username",
        connect_case["username"].as_str().unwrap(),
        "--password",
        connect_case["password"].as_str().unwrap(),
        "--host",
        connect_case["host_override"].as_str().unwrap(),
    ]);
    assert_eq!(connect.exit_code, 0);
    assert_eq!(connect.stderr, "");
    let connect_json: Value = serde_json::from_str(&connect.stdout).unwrap();
    assert_eq!(
        connect_json["request_hex"].as_str().unwrap(),
        connect_case["request_hex"].as_str().unwrap()
    );

    let forward = run_with_args([
        "outbound",
        "http",
        "forward",
        "--raw-hex",
        fixture["http_request_passthrough"]["input_hex"]
            .as_str()
            .unwrap(),
    ]);
    assert_eq!(forward.exit_code, 0);
    assert_eq!(forward.stderr, "");
    let forward_json: Value = serde_json::from_str(&forward.stdout).unwrap();
    assert_eq!(
        forward_json["request_hex"].as_str().unwrap(),
        fixture["http_request_passthrough"]["request_hex"]
            .as_str()
            .unwrap()
    );

    let (proxy, handle) =
        spawn_fake_http_proxy("CONNECT front.example HTTP/1.1", Some("Basic dXNlcjpwYXNz"));
    let smoke = run_with_args([
        "outbound",
        "http",
        "smoke",
        "--proxy",
        &proxy,
        "--target",
        "example.com:443",
        "--username",
        "user",
        "--password",
        "pass",
        "--host",
        "front.example",
    ]);
    assert_eq!(smoke.exit_code, 0, "{}", smoke.stdout);
    assert_eq!(smoke.stderr, "");
    handle.join().unwrap();
    let smoke_json: Value = serde_json::from_str(&smoke.stdout).unwrap();
    assert!(smoke_json["ok"].as_bool().unwrap());
    assert_eq!(smoke_json["status"].as_u64().unwrap(), 200);

    let (proxy, handle) = spawn_fake_http_proxy(
        "PUT http://www.example.com/proxy-path HTTP/1.1",
        Some("Basic dXNlcjpwYXNz"),
    );
    let transport = run_with_args([
        "outbound",
        "http",
        "smoke",
        "--proxy",
        &proxy,
        "--target",
        "example.com:443",
        "--username",
        "user",
        "--password",
        "pass",
        "--transport",
        "true",
        "--path",
        "/proxy-path",
    ]);
    assert_eq!(transport.exit_code, 0, "{}", transport.stdout);
    assert_eq!(transport.stderr, "");
    handle.join().unwrap();
    let transport_json: Value = serde_json::from_str(&transport.stdout).unwrap();
    assert!(transport_json["ok"].as_bool().unwrap());
    assert!(transport_json["transport"].as_bool().unwrap());
}
