use super::*;

#[test]
fn stage127_juicity_congestion_fixture_matches() {
    let fixture = load("engine/runtime_stage127/juicity_congestion_admission.json");
    let output = run_with_args(["runtime", "stage127-juicity-congestion-admission"]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();

    assert_eq!(json, fixture);
    assert!(json["read_only"].as_bool().unwrap());
    assert!(json["blocked"].as_bool().unwrap());
    assert!(
        json["juicity_stream_packet_conn_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["juicity_congestion_behavior_admitted"]
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
        json["stream_packet_congestion"]["congestion_control_effective"],
        "bbr"
    );
    assert_eq!(
        json["stream_packet_congestion"]["rust_bbr_initial_window_bytes"],
        40960
    );
    assert_eq!(
        json["stream_packet_congestion"]["request_payload_len"],
        4096
    );
    assert_eq!(
        json["stream_packet_congestion"]["response_payload_len"],
        1024
    );
    assert_eq!(json["stream_packet_congestion"]["max_in_flight_streams"], 4);
}

#[test]
fn stage127_juicity_congestion_rejects_bad_args() {
    let blocked = run_with_args([
        "runtime",
        "stage127-juicity-congestion-admission",
        "--benchmark-iters=0",
    ]);
    assert_eq!(blocked.exit_code, 2);
    assert!(
        blocked
            .stderr
            .contains("stage127 --benchmark-iters must be greater than zero")
    );

    let blocked = run_with_args([
        "runtime",
        "stage127-juicity-congestion-admission",
        "--max-in-flight-streams=0",
    ]);
    assert_eq!(blocked.exit_code, 2);
    assert!(
        blocked
            .stderr
            .contains("stage127 --max-in-flight-streams must be greater than zero")
    );

    let blocked = run_with_args([
        "runtime",
        "stage127-juicity-congestion-admission",
        "--payload-len=0",
    ]);
    assert_eq!(blocked.exit_code, 2);
    assert!(
        blocked
            .stderr
            .contains("stage127 --payload cannot be empty")
    );

    let blocked = run_with_args([
        "runtime",
        "stage127-juicity-congestion-admission",
        "--response-payload-len=0",
    ]);
    assert_eq!(blocked.exit_code, 2);
    assert!(
        blocked
            .stderr
            .contains("stage127 --response-payload cannot be empty")
    );
}
