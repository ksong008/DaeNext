use super::*;

#[test]
fn stage117_juicity_h3_dependency_admission_fixture_matches() {
    let fixture = load("engine/runtime_stage117/juicity_h3_dependency_admission.json");
    let output = run_with_args(["runtime", "stage117-juicity-h3-dependency-admission"]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();

    assert_eq!(json, fixture);
    assert!(json["read_only"].as_bool().unwrap());
    assert!(json["blocked"].as_bool().unwrap());
    assert!(json["quinn_dependency_available"].as_bool().unwrap());
    assert!(json["h3_dependency_available"].as_bool().unwrap());
    assert!(json["h3_quinn_dependency_available"].as_bool().unwrap());
    assert!(json["tokio_quic_runtime_admitted"].as_bool().unwrap());
    assert!(
        json["juicity_h3_loopback_dependency_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["juicity_h3_loopback_smoke_executed"]
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

    let inventory = &json["dependency_inventory"];
    assert_eq!(inventory["quinn_version"].as_str().unwrap(), "0.11.9");
    assert_eq!(inventory["h3_version"].as_str().unwrap(), "0.0.8");
    assert_eq!(inventory["h3_quinn_version"].as_str().unwrap(), "0.0.10");
    assert_eq!(inventory["tokio_version"].as_str().unwrap(), "1.52.3");
    assert!(
        inventory["quinn_endpoint_type"]
            .as_str()
            .unwrap()
            .contains("Endpoint")
    );
    assert!(
        inventory["h3_quinn_connection_type"]
            .as_str()
            .unwrap()
            .contains("Connection")
    );
}

#[test]
fn stage117_juicity_h3_dependency_admission_rejects_extra_args() {
    let blocked = run_with_args([
        "runtime",
        "stage117-juicity-h3-dependency-admission",
        "--execute-smoke",
    ]);
    assert_eq!(blocked.exit_code, 2);
    assert!(
        blocked
            .stderr
            .contains("unsupported stage117 argument: --execute-smoke")
    );
}
