use super::*;

#[test]
fn stage103_trojan_go_combination_fixture_matches() {
    let fixture = load(
        "engine/runtime_stage103/trojan_go_wss_tls_fragment_inner_ss_combination_admission.json",
    );
    let output = run_with_args([
        "runtime",
        "stage103-trojan-go-wss-tls-fragment-inner-ss-combination-admission",
    ]);
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
    assert!(json["trojan_go_wss_admitted"].as_bool().unwrap());
    assert!(json["trojan_go_tls_fragment_admitted"].as_bool().unwrap());
    assert!(
        json["trojan_go_inner_shadowsocks_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["trojan_go_wss_tls_fragment_inner_shadowsocks_combination_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["trojan_go_shared_transport_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["outbound_true_dataplane_admitted"].as_bool().unwrap());
    assert_eq!(
        json["combination_contract"]["fragment_length"]
            .as_str()
            .unwrap(),
        "64-64"
    );
    assert_eq!(
        json["combination_contract"]["inner_shadowsocks_is_client"]
            .as_bool()
            .unwrap(),
        false
    );
}

#[test]
fn stage103_trojan_go_combination_requires_ack_for_smoke() {
    let blocked = run_with_args([
        "runtime",
        "stage103-trojan-go-wss-tls-fragment-inner-ss-combination-admission",
        "--execute-smoke",
    ]);
    assert_eq!(blocked.exit_code, 1);
    assert!(
        blocked
            .stdout
            .contains("stage103 root-gated smoke requires")
    );
}

#[test]
fn stage103_trojan_go_combination_rejects_invalid_fragment_range() {
    let blocked = run_with_args([
        "runtime",
        "stage103-trojan-go-wss-tls-fragment-inner-ss-combination-admission",
        "--fragment-length",
        "64",
    ]);
    assert_eq!(blocked.exit_code, 2);
    assert!(
        blocked
            .stderr
            .contains("stage103 tls fragment options invalid")
    );
}
