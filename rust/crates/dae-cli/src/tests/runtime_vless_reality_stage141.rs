use super::*;

#[test]
fn stage141_runtime_vless_reality_synthetic_utls_fixture_matches() {
    let fixture =
        load("engine/runtime_stage141/vless_reality_synthetic_utls_raw_mutation_gate.json");
    let output = run_with_args([
        "runtime",
        "stage141-vless-reality-synthetic-utls-raw-mutation-gate",
    ]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();

    assert_eq!(json["name"], fixture["name"]);
    assert_eq!(json["stage"], fixture["stage"]);
    assert!(
        json["vless_reality_synthetic_utls_raw_mutation_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        json["synthetic_reality_utls_raw_mutation"]["mutation_report_count"],
        fixture["synthetic_reality_utls_raw_mutation"]["mutation_report_count"]
    );
    assert_eq!(
        json["synthetic_reality_utls_raw_mutation"]["profile_preserved_count"],
        fixture["synthetic_reality_utls_raw_mutation"]["profile_preserved_count"]
    );
    assert!(
        json["synthetic_reality_utls_raw_mutation"]["all_profiles_preserved_after_mutation"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["vless_reality_full_handshake_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["vless_reality_verify_peer_certificate_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["vless_reality_spider_fallback_admitted"]
            .as_bool()
            .unwrap()
    );
}

#[test]
fn stage141_runtime_rejects_extra_args() {
    let output = run_with_args([
        "runtime",
        "stage141-vless-reality-synthetic-utls-raw-mutation-gate",
        "--execute-smoke",
    ]);
    assert_ne!(output.exit_code, 0);
    assert!(output.stderr.contains("unsupported stage141 argument"));
}
