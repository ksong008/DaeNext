use super::*;

#[test]
fn stage145_runtime_trojan_go_recertification_fixture_matches() {
    let fixture =
        load("engine/runtime_stage145/trojan_go_fallback_aware_recertification_gate.json");
    let output = run_with_args([
        "runtime",
        "stage145-trojan-go-fallback-aware-recertification-gate",
    ]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();

    assert_eq!(json["name"], fixture["name"]);
    assert_eq!(json["stage"], fixture["stage"]);
    assert!(
        json["trojan_go_fallback_aware_recertified"]
            .as_bool()
            .unwrap()
    );
    assert!(
        json["trojan_go_shared_transport_go_fallback_required"]
            .as_bool()
            .unwrap()
    );
    assert!(
        json["trojan_go_grpc_no_double_tls_guarded"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["trojan_go_shared_transport_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["trojan_go_utls_fingerprint_wire_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
}

#[test]
fn stage145_runtime_rejects_extra_args() {
    let output = run_with_args([
        "runtime",
        "stage145-trojan-go-fallback-aware-recertification-gate",
        "--execute-smoke",
    ]);
    assert_ne!(output.exit_code, 0);
    assert!(output.stderr.contains("unsupported stage145 argument"));
}
