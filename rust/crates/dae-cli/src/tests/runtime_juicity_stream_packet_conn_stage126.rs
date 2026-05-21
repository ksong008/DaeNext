use super::*;

#[test]
fn stage126_juicity_stream_packet_conn_fixture_matches() {
    let fixture = load("engine/runtime_stage126/juicity_stream_packet_conn_admission.json");
    let output = run_with_args(["runtime", "stage126-juicity-stream-packet-conn-admission"]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();

    assert_eq!(json, fixture);
    assert!(json["read_only"].as_bool().unwrap());
    assert!(json["blocked"].as_bool().unwrap());
    assert!(
        json["juicity_transport_packet_conn_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["juicity_stream_packet_conn_live_stream_admitted"]
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
    assert_eq!(json["stream_packet_conn"]["alpn_protocol"], "h3");
    assert_eq!(json["stream_packet_conn"]["connection_network_byte"], 3);
    assert_eq!(json["stream_packet_conn"]["request_payload_len"], 28);
    assert_eq!(json["stream_packet_conn"]["response_payload_len"], 28);
}

#[test]
fn stage126_juicity_stream_packet_conn_rejects_bad_args() {
    let blocked = run_with_args([
        "runtime",
        "stage126-juicity-stream-packet-conn-admission",
        "--benchmark-iters=0",
    ]);
    assert_eq!(blocked.exit_code, 2);
    assert!(
        blocked
            .stderr
            .contains("stage126 --benchmark-iters must be greater than zero")
    );

    let blocked = run_with_args([
        "runtime",
        "stage126-juicity-stream-packet-conn-admission",
        "--payload=",
    ]);
    assert_eq!(blocked.exit_code, 2);
    assert!(
        blocked
            .stderr
            .contains("stage126 --payload cannot be empty")
    );

    let blocked = run_with_args([
        "runtime",
        "stage126-juicity-stream-packet-conn-admission",
        "--response-payload=",
    ]);
    assert_eq!(blocked.exit_code, 2);
    assert!(
        blocked
            .stderr
            .contains("stage126 --response-payload cannot be empty")
    );
}
