use super::*;

#[test]
fn stage125_juicity_transport_packet_conn_fixture_matches() {
    let fixture = load("engine/runtime_stage125/juicity_transport_packet_conn_admission.json");
    let output = run_with_args([
        "runtime",
        "stage125-juicity-transport-packet-conn-admission",
    ]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();

    assert_eq!(json, fixture);
    assert!(json["read_only"].as_bool().unwrap());
    assert!(json["blocked"].as_bool().unwrap());
    assert!(
        json["juicity_send_authentication_lifecycle_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["juicity_transport_packet_conn_crypto_admitted"]
            .as_bool()
            .unwrap()
    );
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
    assert_eq!(
        json["transport_packet_conn"]["reused_info_raw"]
            .as_str()
            .unwrap(),
        "juicity-reused-info"
    );
    assert_eq!(json["transport_packet_conn"]["nonce_len"], 12);
    assert_eq!(json["transport_packet_conn"]["tag_len"], 16);
}

#[test]
fn stage125_juicity_transport_packet_conn_rejects_bad_args() {
    let blocked = run_with_args([
        "runtime",
        "stage125-juicity-transport-packet-conn-admission",
        "--benchmark-iters=0",
    ]);
    assert_eq!(blocked.exit_code, 2);
    assert!(
        blocked
            .stderr
            .contains("stage125 --benchmark-iters must be greater than zero")
    );

    let blocked = run_with_args([
        "runtime",
        "stage125-juicity-transport-packet-conn-admission",
        "--payload=",
    ]);
    assert_eq!(blocked.exit_code, 2);
    assert!(
        blocked
            .stderr
            .contains("stage125 --payload cannot be empty")
    );

    let blocked = run_with_args([
        "runtime",
        "stage125-juicity-transport-packet-conn-admission",
        "--response-payload=",
    ]);
    assert_eq!(blocked.exit_code, 2);
    assert!(
        blocked
            .stderr
            .contains("stage125 --response-payload cannot be empty")
    );
}
