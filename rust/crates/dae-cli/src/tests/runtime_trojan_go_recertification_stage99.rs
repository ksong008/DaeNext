use super::*;

#[test]
fn stage99_trojan_go_recertification_fixture_matches() {
    let fixture = load("engine/runtime_stage99/trojan_go_shared_transport_recertification.json");
    let output = run_with_args([
        "runtime",
        "stage99-trojan-go-shared-transport-recertification",
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
    assert!(json["trojan_go_httpupgrade_admitted"].as_bool().unwrap());
    assert!(json["trojan_go_grpc_hunk_admitted"].as_bool().unwrap());
    assert!(
        json["trojan_go_grpc_http2_tls_lifecycle_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        json["trojan_go_grpc_cache_cleanup_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        json["trojan_go_grpc_cancellation_stress_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["trojan_go_shared_transport_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["outbound_true_dataplane_admitted"].as_bool().unwrap());
}

#[test]
fn stage99_trojan_go_recertification_rejects_extra_args() {
    let blocked = run_with_args([
        "runtime",
        "stage99-trojan-go-shared-transport-recertification",
        "--execute-smoke",
    ]);
    assert_eq!(blocked.exit_code, 2);
    assert!(
        blocked
            .stderr
            .contains("unsupported stage99 argument: --execute-smoke")
    );
}
