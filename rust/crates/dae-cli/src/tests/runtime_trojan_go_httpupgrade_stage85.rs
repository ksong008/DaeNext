use super::*;

#[test]
fn stage85_runtime_admission_fixture_matches() {
    let fixture = load("engine/runtime_stage85/trojan_go_httpupgrade_dataplane_admission.json");
    let output = run_with_args([
        "runtime",
        "stage85-trojan-go-httpupgrade-dataplane-admission",
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
    assert!(json["trojan_go_wss_admitted"].as_bool().unwrap());
    assert!(
        !json["trojan_go_httpupgrade_smoke_passed"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["trojan_go_httpupgrade_admitted"].as_bool().unwrap());
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
        !json["trojan_go_inner_shadowsocks_admitted"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        json["trojan_go_httpupgrade_contract"]["httpupgrade_host"]
            .as_str()
            .unwrap(),
        "stage85-upgrade-host.example"
    );
    assert_eq!(
        json["trojan_go_httpupgrade_contract"]["httpupgrade_path"]
            .as_str()
            .unwrap(),
        "/trojan-go-upgrade"
    );
    assert!(!json["outbound_true_dataplane_admitted"].as_bool().unwrap());
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
    assert!(!json["product_chain_switch_allowed"].as_bool().unwrap());
}

#[test]
fn stage85_runtime_admission_blocks_unsafe_execution() {
    let blocked = run_with_args([
        "runtime",
        "stage85-trojan-go-httpupgrade-dataplane-admission",
        "--execute-smoke",
    ]);
    assert_eq!(blocked.exit_code, 1);
    assert!(
        blocked
            .stdout
            .contains("stage85 root-gated smoke requires --ack-root-gate")
    );
}
