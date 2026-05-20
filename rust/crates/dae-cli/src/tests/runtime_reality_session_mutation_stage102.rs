use super::*;

#[test]
fn stage102_reality_session_mutation_fixture_matches() {
    let fixture = load("engine/runtime_stage102/reality_session_id_mutation_readiness.json");
    let output = run_with_args(["runtime", "stage102-reality-session-id-mutation-readiness"]);
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
        json["reality_session_id_aead_mutation_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["reality_full_utls_handshake_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["trojan_go_reality_mutation_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        json["reality_mutation_contract"]["aes_gcm"]["mutation_applied_to_hello_raw"]
            .as_bool()
            .unwrap()
    );
}

#[test]
fn stage102_reality_session_mutation_rejects_extra_args() {
    let blocked = run_with_args([
        "runtime",
        "stage102-reality-session-id-mutation-readiness",
        "--execute-smoke",
    ]);
    assert_eq!(blocked.exit_code, 2);
    assert!(
        blocked
            .stderr
            .contains("unsupported stage102 argument: --execute-smoke")
    );
}
