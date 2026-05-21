use super::*;

#[test]
fn stage120_juicity_packet_state_fixture_matches() {
    let fixture = load("engine/runtime_stage120/juicity_packet_state_admission.json");
    let output = run_with_args(["runtime", "stage120-juicity-packet-state-admission"]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();

    assert_eq!(json, fixture);
    assert!(json["read_only"].as_bool().unwrap());
    assert!(json["blocked"].as_bool().unwrap());
    assert!(json["juicity_h3_handshake_admitted"].as_bool().unwrap());
    assert!(
        json["juicity_tls_certchain_verification_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["juicity_dialauth_record_protocol_state_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["juicity_udp_port_zero_transport_packet_conn_route_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["juicity_stream_packet_conn_frame_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["juicity_dialauth_over_h3_admitted"].as_bool().unwrap());
    assert!(
        !json["juicity_transport_packet_conn_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["juicity_stream_packet_conn_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["juicity_true_quic_h3_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["outbound_true_dataplane_admitted"].as_bool().unwrap());
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
    assert!(!json["product_chain_switch_allowed"].as_bool().unwrap());
    assert_eq!(
        json["packet_state"]["port_zero_target"].as_str().unwrap(),
        "stage120-zero.example:0"
    );
    assert_eq!(
        json["packet_state"]["stream_target"].as_str().unwrap(),
        "stage120-stream.example:5353"
    );
}

#[test]
fn stage120_juicity_packet_state_rejects_bad_args() {
    let blocked = run_with_args([
        "runtime",
        "stage120-juicity-packet-state-admission",
        "--benchmark-iters=0",
    ]);
    assert_eq!(blocked.exit_code, 2);
    assert!(
        blocked
            .stderr
            .contains("stage120 --benchmark-iters must be greater than zero")
    );
}
