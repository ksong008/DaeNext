use super::*;

#[test]
fn stage139_runtime_utls_wire_baseline_fixture_matches() {
    let fixture = load("engine/runtime_stage139/vless_vmess_utls_wire_baseline_gate.json");
    let output = run_with_args(["runtime", "stage139-vless-vmess-utls-wire-baseline-gate"]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();

    assert_eq!(json["name"], fixture["name"]);
    assert_eq!(json["stage"], fixture["stage"]);
    assert_eq!(json["evidence_class"], fixture["evidence_class"]);
    assert!(json["read_only"].as_bool().unwrap());
    assert!(
        json["utls_wire_baseline_fixture_recorded"]
            .as_bool()
            .unwrap()
    );
    assert!(json["utls_wire_profile_parser_admitted"].as_bool().unwrap());
    assert_eq!(
        json["utls_wire_baseline"]["sample_count"],
        fixture["utls_wire_baseline"]["sample_count"]
    );
    assert_eq!(
        json["utls_wire_baseline"]["parsed_profile_count"],
        fixture["utls_wire_baseline"]["parsed_profile_count"]
    );
    assert_eq!(
        json["utls_wire_baseline"]["profile_match_count"],
        fixture["utls_wire_baseline"]["profile_match_count"]
    );
    assert!(
        json["utls_wire_baseline"]["all_profiles_match_fixture"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["vless_utls_fingerprint_wire_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["vmess_utls_fingerprint_wire_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["utls_wire_boundaries"]["wire_clienthello_builder_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        json["utls_wire_boundaries"]["rustls_is_not_utls"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["vless_reality_full_handshake_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["vless_vision_tls_reality_admitted"].as_bool().unwrap());
}

#[test]
fn stage139_runtime_rejects_extra_args() {
    let output = run_with_args([
        "runtime",
        "stage139-vless-vmess-utls-wire-baseline-gate",
        "--execute-smoke",
    ]);
    assert_ne!(output.exit_code, 0);
    assert!(output.stderr.contains("unsupported stage139 argument"));
}
