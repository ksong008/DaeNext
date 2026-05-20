use super::*;

#[test]
fn stage106_anytls_session_reuse_fixture_matches() {
    let fixture = load("engine/runtime_stage106/anytls_idle_session_reuse_admission.json");
    let output = run_with_args(["runtime", "stage106-anytls-idle-session-reuse-admission"]);
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
        !json["anytls_idle_session_reuse_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["anytls_true_dataplane_admitted"].as_bool().unwrap());
    assert!(!json["outbound_true_dataplane_admitted"].as_bool().unwrap());
    assert_eq!(
        json["anytls_contract"]["logical_stream_count"]
            .as_u64()
            .unwrap(),
        2
    );
    assert_eq!(
        json["anytls_contract"]["physical_session_count"]
            .as_u64()
            .unwrap(),
        1
    );
}

#[test]
fn stage106_anytls_session_reuse_requires_ack_for_smoke() {
    let blocked = run_with_args([
        "runtime",
        "stage106-anytls-idle-session-reuse-admission",
        "--execute-smoke",
    ]);
    assert_eq!(blocked.exit_code, 1);
    assert!(
        blocked
            .stdout
            .contains("stage106 root-gated smoke requires")
    );
}

#[test]
fn stage106_anytls_session_reuse_rejects_invalid_second_target() {
    let blocked = run_with_args([
        "runtime",
        "stage106-anytls-idle-session-reuse-admission",
        "--second-target",
        "missing-port.example",
    ]);
    assert_eq!(blocked.exit_code, 2);
    assert!(blocked.stderr.contains("stage106 second target is invalid"));
}
