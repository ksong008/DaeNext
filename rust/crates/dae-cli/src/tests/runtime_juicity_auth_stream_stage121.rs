use super::*;

#[test]
fn stage121_juicity_auth_stream_fixture_matches() {
    let fixture = load("engine/runtime_stage121/juicity_auth_stream_admission.json");
    let output = run_with_args(["runtime", "stage121-juicity-auth-stream-admission"]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();

    assert_eq!(json, fixture);
    assert!(json["read_only"].as_bool().unwrap());
    assert!(json["blocked"].as_bool().unwrap());
    assert!(
        json["juicity_dialauth_record_protocol_state_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        json["juicity_udp_port_zero_transport_packet_conn_route_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        json["juicity_stream_packet_conn_frame_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["juicity_authenticate_header_layout_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["juicity_auth_uni_stream_write_order_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["juicity_dialauth_record_over_auth_stream_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["juicity_auth_token_live_ekm_admitted"]
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
        json["auth_stream"]["target"].as_str().unwrap(),
        "stage121-zero.example:0"
    );
    assert_eq!(json["auth_stream"]["authenticate_header_len"], 50);
}

#[test]
fn stage121_juicity_auth_stream_rejects_bad_args() {
    let blocked = run_with_args([
        "runtime",
        "stage121-juicity-auth-stream-admission",
        "--benchmark-iters=0",
    ]);
    assert_eq!(blocked.exit_code, 2);
    assert!(
        blocked
            .stderr
            .contains("stage121 --benchmark-iters must be greater than zero")
    );
}
