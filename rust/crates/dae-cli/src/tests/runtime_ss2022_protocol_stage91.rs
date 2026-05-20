use super::*;

#[test]
fn stage91_runtime_admission_fixture_matches() {
    let fixture = load("engine/runtime_stage91/ss2022_protocol_wide_admission.json");
    let output = run_with_args(["runtime", "stage91-ss2022-protocol-wide-admission"]);
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
    assert!(json["read_only"].as_bool().unwrap());
    assert!(!json["blocked"].as_bool().unwrap());
    assert!(
        json["ss2022_tcp_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        json["ss2022_multi_psk_identity_header_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        json["ss2022_udp_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(json["ss2022_true_dataplane_admitted"].as_bool().unwrap());
    assert!(!json["sip003_plugin_transport_admitted"].as_bool().unwrap());
    assert!(
        !json["shadowsocks_protocol_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["outbound_true_dataplane_admitted"].as_bool().unwrap());
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
}

#[test]
fn stage91_runtime_admission_rejects_extra_args() {
    let blocked = run_with_args([
        "runtime",
        "stage91-ss2022-protocol-wide-admission",
        "--execute-smoke",
    ]);
    assert_eq!(blocked.exit_code, 2);
    assert!(
        blocked
            .stderr
            .contains("unsupported stage91 argument: --execute-smoke")
    );
}
