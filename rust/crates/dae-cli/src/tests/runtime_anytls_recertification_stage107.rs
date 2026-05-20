use super::*;

#[test]
fn stage107_anytls_protocol_wide_fixture_matches() {
    let fixture = load("engine/runtime_stage107/anytls_protocol_wide_recertification.json");
    let output = run_with_args(["runtime", "stage107-anytls-protocol-wide-recertification"]);
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
        json["anytls_session_frame_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        json["anytls_udp_packet_stream_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        json["anytls_idle_session_reuse_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(json["anytls_true_dataplane_admitted"].as_bool().unwrap());
    assert!(!json["outbound_true_dataplane_admitted"].as_bool().unwrap());
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
    assert!(!json["product_chain_switch_allowed"].as_bool().unwrap());
}

#[test]
fn stage107_anytls_protocol_wide_rejects_extra_args() {
    let blocked = run_with_args([
        "runtime",
        "stage107-anytls-protocol-wide-recertification",
        "--execute-smoke",
    ]);
    assert_eq!(blocked.exit_code, 2);
    assert!(
        blocked
            .stderr
            .contains("unsupported stage107 argument: --execute-smoke")
    );
}
