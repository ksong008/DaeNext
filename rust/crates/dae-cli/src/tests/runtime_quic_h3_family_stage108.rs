use super::*;

#[test]
fn stage108_quic_h3_family_blocker_queue_fixture_matches() {
    let fixture = load("engine/runtime_stage108/quic_h3_family_blocker_queue.json");
    let output = run_with_args(["runtime", "stage108-quic-h3-family-blocker-queue"]);
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
    assert!(json["blocked"].as_bool().unwrap());
    assert!(
        json["hysteria2_native_optin_contract_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        json["tuic_native_optin_contract_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        json["juicity_native_optin_contract_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(json["anytls_true_dataplane_admitted"].as_bool().unwrap());
    assert!(
        !json["hysteria2_true_quic_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["tuic_true_quic_dataplane_admitted"].as_bool().unwrap());
    assert!(
        !json["juicity_true_quic_h3_dataplane_admitted"]
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
    assert!(!json["product_chain_switch_allowed"].as_bool().unwrap());
    assert!(
        json["outbound_quic_go_dependency_preserved"]
            .as_bool()
            .unwrap()
    );
    assert!(json["external_outbound_required"].as_bool().unwrap());
    assert!(json["external_quic_go_required"].as_bool().unwrap());
}

#[test]
fn stage108_quic_h3_family_blocker_queue_rejects_extra_args() {
    let blocked = run_with_args([
        "runtime",
        "stage108-quic-h3-family-blocker-queue",
        "--execute-smoke",
    ]);
    assert_eq!(blocked.exit_code, 2);
    assert!(
        blocked
            .stderr
            .contains("unsupported stage108 argument: --execute-smoke")
    );
}
