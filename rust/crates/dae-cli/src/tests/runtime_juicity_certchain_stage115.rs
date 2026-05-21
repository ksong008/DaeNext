use super::*;

#[test]
fn stage115_juicity_certchain_verifier_fixture_matches() {
    let fixture = load("engine/runtime_stage115/juicity_certchain_verifier_admission.json");
    let output = run_with_args(["runtime", "stage115-juicity-certchain-verifier-admission"]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();

    assert_eq!(json, fixture);
    assert!(json["read_only"].as_bool().unwrap());
    assert!(json["blocked"].as_bool().unwrap());
    assert!(
        json["juicity_certchain_hash_algorithm_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        json["juicity_pinned_certchain_url_base64_verify_vector_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        json["juicity_pinned_certchain_std_base64_verify_vector_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        json["juicity_pinned_certchain_hex_decode_caveat_recorded"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["juicity_tls_certchain_verification_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["juicity_h3_handshake_admitted"].as_bool().unwrap());
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

    let vector = &json["certchain_vector"];
    assert_eq!(
        vector["url_base64_pin_format"].as_str().unwrap(),
        "url-base64"
    );
    assert_eq!(
        vector["std_base64_pin_format"].as_str().unwrap(),
        "std-base64"
    );
    assert!(vector["url_base64_pin_matched"].as_bool().unwrap());
    assert!(vector["std_base64_pin_matched"].as_bool().unwrap());
    assert_eq!(
        vector["hex_looking_sha256_pin_format"].as_str().unwrap(),
        "url-base64"
    );
    assert!(!vector["hex_looking_sha256_pin_matched"].as_bool().unwrap());
}

#[test]
fn stage115_juicity_certchain_verifier_rejects_extra_args() {
    let blocked = run_with_args([
        "runtime",
        "stage115-juicity-certchain-verifier-admission",
        "--execute-smoke",
    ]);
    assert_eq!(blocked.exit_code, 2);
    assert!(
        blocked
            .stderr
            .contains("unsupported stage115 argument: --execute-smoke")
    );
}
