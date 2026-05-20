use super::*;

#[test]
fn stage101_utls_fingerprint_readiness_fixture_matches() {
    let fixture = load("engine/runtime_stage101/trojan_go_utls_fingerprint_readiness.json");
    let output = run_with_args(["runtime", "stage101-trojan-go-utls-fingerprint-readiness"]);
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
        json["trojan_go_utls_fingerprint_selection_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["trojan_go_utls_fingerprint_wire_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["trojan_go_utls_fingerprint_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["trojan_go_shared_transport_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        json["utls_fingerprint_contract"]["supported_name_count"]
            .as_u64()
            .unwrap(),
        45
    );
}

#[test]
fn stage101_utls_fingerprint_readiness_rejects_extra_args() {
    let blocked = run_with_args([
        "runtime",
        "stage101-trojan-go-utls-fingerprint-readiness",
        "--execute-smoke",
    ]);
    assert_eq!(blocked.exit_code, 2);
    assert!(
        blocked
            .stderr
            .contains("unsupported stage101 argument: --execute-smoke")
    );
}
