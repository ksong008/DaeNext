use super::*;

#[test]
fn stage94_runtime_admission_fixture_matches() {
    let fixture = load("engine/runtime_stage94/sip003_v2ray_plugin_dataplane_admission.json");
    let output = run_with_args(["runtime", "stage94-sip003-v2ray-plugin-dataplane-admission"]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();

    assert_eq!(
        json["name"].as_str().unwrap(),
        fixture["name"].as_str().unwrap()
    );
    assert_eq!(
        json["stage"].as_str().unwrap(),
        fixture["stage"].as_str().unwrap()
    );
    assert!(!json["execute_smoke"].as_bool().unwrap());
    assert!(json["read_only"].as_bool().unwrap());
    assert!(!json["blocked"].as_bool().unwrap());
    assert!(json["sip003_simple_obfs_http_admitted"].as_bool().unwrap());
    assert!(json["sip003_simple_obfs_tls_admitted"].as_bool().unwrap());
    assert!(!json["sip003_v2ray_plugin_smoke_passed"].as_bool().unwrap());
    assert!(!json["sip003_v2ray_plugin_admitted"].as_bool().unwrap());
    assert!(!json["sip003_plugin_transport_admitted"].as_bool().unwrap());
    assert!(
        !json["shadowsocksr_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["shadowsocks_protocol_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["outbound_true_dataplane_admitted"].as_bool().unwrap());
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
    assert_eq!(
        json["sip003_contract"]["plugin"].as_str().unwrap(),
        "v2ray-plugin"
    );
    assert_eq!(json["sip003_contract"]["obfs"].as_str().unwrap(), "");
    assert_eq!(json["sip003_contract"]["tls"].as_str().unwrap(), "tls");
    assert_eq!(
        json["sip003_contract"]["tls_server_name"].as_str().unwrap(),
        "stage94-v2ray-plugin.example"
    );
    assert_eq!(
        json["sip003_contract"]["ws_host"].as_str().unwrap(),
        "stage94-v2ray-host.example"
    );
    assert_eq!(json["sip003_contract"]["ws_path"].as_str().unwrap(), "/");
    assert_eq!(
        json["sip003_contract"]["mux"]["id_hex"].as_str().unwrap(),
        "0000"
    );
    assert!(
        json["sip003_contract"]["passthrough_udp"]["tls"]
            .as_bool()
            .unwrap()
    );
    assert!(
        json["sip003_contract"]["passthrough_udp"]["websocket"]
            .as_bool()
            .unwrap()
    );
    assert!(
        json["sip003_contract"]["passthrough_udp"]["mux"]
            .as_bool()
            .unwrap()
    );
}

#[test]
fn stage94_runtime_admission_blocks_unsafe_execution() {
    let blocked = run_with_args([
        "runtime",
        "stage94-sip003-v2ray-plugin-dataplane-admission",
        "--execute-smoke",
    ]);
    assert_eq!(blocked.exit_code, 1);
    assert!(
        blocked
            .stdout
            .contains("stage94 root-gated smoke requires --ack-root-gate")
    );
}
