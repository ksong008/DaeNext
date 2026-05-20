use super::*;

#[test]
fn stage95_runtime_admission_fixture_matches() {
    let fixture = load("engine/runtime_stage95/shadowsocksr_three_layer_dataplane_admission.json");
    let output = run_with_args([
        "runtime",
        "stage95-shadowsocksr-three-layer-dataplane-admission",
    ]);
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
    assert!(json["sip003_plugin_transport_admitted"].as_bool().unwrap());
    assert!(
        !json["shadowsocksr_three_layer_smoke_passed"]
            .as_bool()
            .unwrap()
    );
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
        json["shadowsocksr_contract"]["obfs"].as_str().unwrap(),
        "http_simple"
    );
    assert_eq!(
        json["shadowsocksr_contract"]["stream_cipher"]
            .as_str()
            .unwrap(),
        "aes-128-cfb"
    );
    assert_eq!(
        json["shadowsocksr_contract"]["ssr_protocol"]
            .as_str()
            .unwrap(),
        "origin"
    );
    assert!(
        json["shadowsocksr_contract"]["parser_compatibility"]["ipv6_colon_host_merge"]
            .as_bool()
            .unwrap()
    );
}

#[test]
fn stage95_runtime_admission_blocks_unsafe_execution() {
    let blocked = run_with_args([
        "runtime",
        "stage95-shadowsocksr-three-layer-dataplane-admission",
        "--execute-smoke",
    ]);
    assert_eq!(blocked.exit_code, 1);
    assert!(
        blocked
            .stdout
            .contains("stage95 root-gated smoke requires --ack-root-gate")
    );
}
