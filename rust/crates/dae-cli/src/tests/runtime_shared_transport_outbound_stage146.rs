use super::*;

#[test]
fn stage146_shared_transport_outbound_recertification_fixture_matches() {
    let fixture = load(
        "engine/runtime_stage146/shared_transport_outbound_fallback_aware_recertification_gate.json",
    );
    let output = run_with_args([
        "runtime",
        "stage146-shared-transport-outbound-fallback-aware-recertification-gate",
    ]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();

    assert_eq!(json, fixture);
    assert!(
        json["shared_transport_fallback_aware_recertified"]
            .as_bool()
            .unwrap()
    );
    assert!(
        json["outbound_fallback_aware_recertified"]
            .as_bool()
            .unwrap()
    );
    assert!(
        json["fallback_dependency_policy_recorded"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["shared_transport_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["outbound_true_dataplane_admitted"].as_bool().unwrap());
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
}

#[test]
fn stage146_runtime_rejects_extra_args() {
    let output = run_with_args([
        "runtime",
        "stage146-shared-transport-outbound-fallback-aware-recertification-gate",
        "--execute-smoke",
    ]);
    assert_ne!(output.exit_code, 0);
    assert!(output.stderr.contains("unsupported stage146 argument"));
}
