use super::*;

#[test]
fn optin_runner_outbound_hysteria2_commands_match_fixture() {
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

#[test]
fn optin_runner_outbound_tuic_commands_match_fixture() {
    let fixture = load("outbound/protocol/tuic_native_optin.json");

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
    assert!(contract_json["default_go_path"].as_bool().unwrap());
    assert_eq!(
        contract_json["udp_relay_mode"]["go_protocol_effective_mode"]
            .as_str()
            .unwrap(),
        fixture["udp_relay_mode"]["go_protocol_effective_mode"]
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
        fixture["udp_relay_mode"]["go_protocol_effective_mode"]
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

#[test]
fn optin_runner_outbound_juicity_commands_match_fixture() {
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

#[test]
fn optin_runner_outbound_anytls_commands_match_fixture() {
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

#[test]
fn optin_runner_outbound_transport_commands_match_fixture() {
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
