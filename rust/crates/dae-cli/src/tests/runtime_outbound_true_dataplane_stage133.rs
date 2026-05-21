use super::*;

#[test]
fn stage133_outbound_true_dataplane_readiness_fixture_matches() {
    let fixture = load("engine/runtime_stage133/outbound_true_dataplane_readiness.json");
    let output = run_with_args(["runtime", "stage133-outbound-true-dataplane-readiness"]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();

    assert_eq!(json, fixture);
    assert!(json["read_only"].as_bool().unwrap());
    assert!(json["blocked"].as_bool().unwrap());
    assert!(
        json["quic_h3_family_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(json["anytls_true_dataplane_admitted"].as_bool().unwrap());
    assert!(
        !json["vless_protocol_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["vmess_protocol_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["trojan_go_shared_transport_admitted"]
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
fn stage133_outbound_true_dataplane_readiness_rejects_bad_args() {
    let blocked = run_with_args([
        "runtime",
        "stage133-outbound-true-dataplane-readiness",
        "--bad",
    ]);
    assert_eq!(blocked.exit_code, 2);
    assert!(
        blocked
            .stderr
            .contains("unsupported stage133 argument: --bad"),
        "{}",
        blocked.stderr
    );
}
