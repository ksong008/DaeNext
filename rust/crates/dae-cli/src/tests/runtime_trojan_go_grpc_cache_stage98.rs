use super::*;

#[test]
fn stage98_runtime_admission_fixture_matches() {
    let fixture = load("engine/runtime_stage98/trojan_go_grpc_cache_cancellation_admission.json");
    let output = run_with_args([
        "runtime",
        "stage98-trojan-go-grpc-cache-cancellation-admission",
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
    assert!(!json["execute_smoke"].as_bool().unwrap());
    assert!(json["read_only"].as_bool().unwrap());
    assert!(!json["blocked"].as_bool().unwrap());
    assert!(
        json["trojan_go_grpc_http2_tls_lifecycle_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["trojan_go_grpc_cache_cancellation_stress_passed"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["trojan_go_grpc_cache_cleanup_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["trojan_go_grpc_cancellation_stress_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        json["trojan_go_shared_transport_partial_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["trojan_go_shared_transport_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        json["grpc_cache_contract"]["base_cache_key"]
            .as_str()
            .unwrap()
            .contains("stage98-trojan-go-grpc-cache.example:443")
    );
    assert!(!json["outbound_true_dataplane_admitted"].as_bool().unwrap());
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
    assert!(!json["product_chain_switch_allowed"].as_bool().unwrap());
}

#[test]
fn stage98_runtime_admission_rejects_zero_iterations() {
    let blocked = run_with_args([
        "runtime",
        "stage98-trojan-go-grpc-cache-cancellation-admission",
        "--benchmark-iters",
        "0",
    ]);
    assert_eq!(blocked.exit_code, 2);
    assert!(
        blocked
            .stderr
            .contains("stage98 --benchmark-iters must be greater than zero")
    );
}
