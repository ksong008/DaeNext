use super::*;

#[test]
fn stage129_juicity_outbound_dataplane_fixture_matches() {
    let fixture = load("engine/runtime_stage129/juicity_outbound_dataplane_admission.json");
    let output = run_with_args(["runtime", "stage129-juicity-outbound-dataplane-admission"]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();

    assert_eq!(json, fixture);
    assert!(json["read_only"].as_bool().unwrap());
    assert!(json["blocked"].as_bool().unwrap());
    assert!(
        json["juicity_client_integration_candidate_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["juicity_true_quic_h3_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["outbound_true_dataplane_admitted"].as_bool().unwrap());
    assert_eq!(json["outbound_dataplane"]["raw_link_count"], 3);
    assert_eq!(json["outbound_dataplane"]["valid_dialer_count"], 2);
    assert_eq!(json["outbound_dataplane"]["skipped_link_count"], 1);
    assert_eq!(json["outbound_dataplane"]["selected_index"], 1);
    assert_eq!(json["outbound_dataplane"]["selected_latency_ms"], 52);
    assert_eq!(json["client_integration"]["total_exchange_count"], 19);
}

#[test]
fn stage129_juicity_outbound_dataplane_rejects_bad_args() {
    for (flag, message) in [
        (
            "--auth-iters=0",
            "stage129 --auth-iters must be greater than zero",
        ),
        (
            "--transport-iters=0",
            "stage129 --transport-iters must be greater than zero",
        ),
        (
            "--stream-iters=0",
            "stage129 --stream-iters must be greater than zero",
        ),
        (
            "--congestion-iters=0",
            "stage129 --congestion-iters must be greater than zero",
        ),
        (
            "--max-in-flight-streams=0",
            "stage129 --max-in-flight-streams must be greater than zero",
        ),
    ] {
        let blocked = run_with_args([
            "runtime",
            "stage129-juicity-outbound-dataplane-admission",
            flag,
        ]);
        assert_eq!(blocked.exit_code, 2);
        assert!(blocked.stderr.contains(message), "{}", blocked.stderr);
    }
}
