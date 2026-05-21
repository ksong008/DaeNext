use super::*;

#[test]
fn stage132_quic_h3_family_fixture_matches() {
    let fixture = load("engine/runtime_stage132/quic_h3_family_recertification_admission.json");
    let output = run_with_args([
        "runtime",
        "stage132-quic-h3-family-recertification-admission",
    ]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();

    assert_eq!(json, fixture);
    assert!(json["read_only"].as_bool().unwrap());
    assert!(json["blocked"].as_bool().unwrap());
    assert!(
        json["hysteria2_true_quic_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(json["tuic_true_quic_dataplane_admitted"].as_bool().unwrap());
    assert!(
        !json["tuic_udp_relay_mode_quic_effective_relay_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        json["juicity_true_quic_h3_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["quic_h3_family_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["outbound_true_dataplane_admitted"].as_bool().unwrap());
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
}

#[test]
fn stage132_quic_h3_family_rejects_bad_args() {
    let blocked = run_with_args([
        "runtime",
        "stage132-quic-h3-family-recertification-admission",
        "--bad",
    ]);
    assert_eq!(blocked.exit_code, 2);
    assert!(
        blocked
            .stderr
            .contains("unsupported stage132 argument: --bad"),
        "{}",
        blocked.stderr
    );
}
