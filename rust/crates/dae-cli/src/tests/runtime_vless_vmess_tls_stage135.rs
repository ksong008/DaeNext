use super::*;

#[test]
fn stage135_runtime_admission_fixture_matches() {
    let fixture = load("engine/runtime_stage135/vless_vmess_tls_wss_httpupgrade_admission.json");
    let output = run_with_args([
        "runtime",
        "stage135-vless-vmess-tls-wss-httpupgrade-admission",
    ]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();

    assert_eq!(json["name"], fixture["name"]);
    assert_eq!(json["stage"], fixture["stage"]);
    assert!(!json["execute_smoke"].as_bool().unwrap());
    assert!(json["read_only"].as_bool().unwrap());
    assert!(!json["blocked"].as_bool().unwrap());
    assert!(!json["vless_wss_tls_lifecycle_admitted"].as_bool().unwrap());
    assert!(!json["vmess_wss_tls_lifecycle_admitted"].as_bool().unwrap());
    assert!(
        json["stage135_tls_contract"]["utls_deferred"]
            .as_bool()
            .unwrap()
    );
    assert!(
        json["stage135_tls_contract"]["reality_deferred"]
            .as_bool()
            .unwrap()
    );
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
    assert!(!json["outbound_true_dataplane_admitted"].as_bool().unwrap());
}

#[test]
fn stage135_runtime_admission_blocks_unsafe_execution() {
    let blocked = run_with_args([
        "runtime",
        "stage135-vless-vmess-tls-wss-httpupgrade-admission",
        "--execute-smoke",
    ]);
    assert_eq!(blocked.exit_code, 1);
    assert!(
        blocked
            .stdout
            .contains("stage135 root-gated smoke requires --ack-root-gate")
    );
}

#[test]
fn stage135_runtime_execute_smoke_admits_only_tls_transport_subrows() {
    let output = run_with_args([
        "runtime",
        "stage135-vless-vmess-tls-wss-httpupgrade-admission",
        "--execute-smoke",
        "--ack-root-gate",
        "--benchmark-iters",
        "1",
    ]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    let json: Value = serde_json::from_str(&output.stdout).unwrap();

    assert!(!json["read_only"].as_bool().unwrap());
    assert!(
        json["vless_vmess_tls_wss_httpupgrade_smoke_passed"]
            .as_bool()
            .unwrap()
    );
    assert!(json["vless_wss_tls_lifecycle_admitted"].as_bool().unwrap());
    assert!(json["vmess_wss_tls_lifecycle_admitted"].as_bool().unwrap());
    assert!(
        json["vless_https_httpupgrade_tls_lifecycle_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        json["vmess_https_httpupgrade_tls_lifecycle_admitted"]
            .as_bool()
            .unwrap()
    );
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
        !json["shared_transport_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(json["benchmark"]["benchmark_recorded"].as_bool().unwrap());
    assert_eq!(
        json["benchmark"]["total_exchange_count"].as_u64().unwrap(),
        4
    );
}
