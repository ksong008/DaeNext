use super::*;

#[test]
fn stage124_juicity_auth_lifecycle_fixture_matches() {
    let fixture = load("engine/runtime_stage124/juicity_auth_lifecycle_admission.json");
    let output = run_with_args(["runtime", "stage124-juicity-auth-lifecycle-admission"]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();

    assert_eq!(json, fixture);
    assert!(json["read_only"].as_bool().unwrap());
    assert!(json["blocked"].as_bool().unwrap());
    assert!(
        json["juicity_auth_token_live_ekm_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["juicity_send_authentication_lifecycle_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["juicity_underlay_auth_channel_order_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["juicity_multiple_dialauth_records_over_auth_stream_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["juicity_auth_stream_finish_boundary_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["juicity_dialauth_over_h3_admitted"].as_bool().unwrap());
    assert!(
        !json["juicity_true_quic_h3_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["outbound_true_dataplane_admitted"].as_bool().unwrap());
    assert_eq!(json["auth_lifecycle"]["record_count"], 3);
    assert_eq!(json["auth_lifecycle"]["underlay_auth_channel_capacity"], 64);
}

#[test]
fn stage124_juicity_auth_lifecycle_rejects_bad_args() {
    let blocked = run_with_args([
        "runtime",
        "stage124-juicity-auth-lifecycle-admission",
        "--benchmark-iters=0",
    ]);
    assert_eq!(blocked.exit_code, 2);
    assert!(
        blocked
            .stderr
            .contains("stage124 --benchmark-iters must be greater than zero")
    );

    let blocked = run_with_args([
        "runtime",
        "stage124-juicity-auth-lifecycle-admission",
        "--password=",
    ]);
    assert_eq!(blocked.exit_code, 2);
    assert!(
        blocked
            .stderr
            .contains("stage124 --password cannot be empty")
    );

    let blocked = run_with_args([
        "runtime",
        "stage124-juicity-auth-lifecycle-admission",
        "--targets=",
    ]);
    assert_eq!(blocked.exit_code, 2);
    assert!(
        blocked
            .stderr
            .contains("stage124 requires at least one non-empty --target")
    );
}
