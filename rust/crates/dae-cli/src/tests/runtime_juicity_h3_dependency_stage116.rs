use super::*;

#[test]
fn stage116_juicity_h3_dependency_readiness_fixture_matches() {
    let fixture = load("engine/runtime_stage116/juicity_h3_dependency_readiness.json");
    let output = run_with_args(["runtime", "stage116-juicity-h3-dependency-readiness"]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();

    assert_eq!(json, fixture);
    assert!(json["read_only"].as_bool().unwrap());
    assert!(json["blocked"].as_bool().unwrap());
    assert!(json["rustls_dependency_available"].as_bool().unwrap());
    assert!(json["rcgen_dependency_available"].as_bool().unwrap());
    assert!(!json["quinn_dependency_available"].as_bool().unwrap());
    assert!(!json["h3_dependency_available"].as_bool().unwrap());
    assert!(!json["h3_quinn_dependency_available"].as_bool().unwrap());
    assert!(
        !json["juicity_h3_loopback_dependency_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["juicity_h3_handshake_admitted"].as_bool().unwrap());
    assert!(
        !json["juicity_tls_certchain_verification_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["juicity_true_quic_h3_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["outbound_true_dataplane_admitted"].as_bool().unwrap());
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
    assert!(!json["product_chain_switch_allowed"].as_bool().unwrap());
}

#[test]
fn stage116_juicity_h3_dependency_readiness_rejects_extra_args() {
    let blocked = run_with_args([
        "runtime",
        "stage116-juicity-h3-dependency-readiness",
        "--execute-smoke",
    ]);
    assert_eq!(blocked.exit_code, 2);
    assert!(
        blocked
            .stderr
            .contains("unsupported stage116 argument: --execute-smoke")
    );
}
