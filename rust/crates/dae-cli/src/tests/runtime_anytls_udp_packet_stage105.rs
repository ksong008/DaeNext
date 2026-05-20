use super::*;

#[test]
fn stage105_anytls_udp_packet_fixture_matches() {
    let fixture = load("engine/runtime_stage105/anytls_udp_packet_stream_admission.json");
    let output = run_with_args(["runtime", "stage105-anytls-udp-packet-stream-admission"]);
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
        !json["anytls_udp_packet_stream_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["anytls_true_dataplane_admitted"].as_bool().unwrap());
    assert!(!json["outbound_true_dataplane_admitted"].as_bool().unwrap());
    assert_eq!(
        json["anytls_contract"]["session_stream_target"]
            .as_str()
            .unwrap(),
        "sp.v2.udp-over-tcp.arpa:5353"
    );
    assert_eq!(
        json["anytls_contract"]["udp_magic_domain"]
            .as_str()
            .unwrap(),
        "sp.v2.udp-over-tcp.arpa"
    );
}

#[test]
fn stage105_anytls_udp_packet_requires_ack_for_smoke() {
    let blocked = run_with_args([
        "runtime",
        "stage105-anytls-udp-packet-stream-admission",
        "--execute-smoke",
    ]);
    assert_eq!(blocked.exit_code, 1);
    assert!(
        blocked
            .stdout
            .contains("stage105 root-gated smoke requires")
    );
}

#[test]
fn stage105_anytls_udp_packet_rejects_invalid_target() {
    let blocked = run_with_args([
        "runtime",
        "stage105-anytls-udp-packet-stream-admission",
        "--target",
        "missing-port.example",
    ]);
    assert_eq!(blocked.exit_code, 2);
    assert!(
        blocked
            .stderr
            .contains("stage105 original UDP target is invalid")
    );
}
