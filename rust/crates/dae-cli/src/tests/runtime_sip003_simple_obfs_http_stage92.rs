use super::*;

#[test]
fn stage92_runtime_admission_fixture_matches() {
    let fixture = load("engine/runtime_stage92/sip003_simple_obfs_http_dataplane_admission.json");
    let output = run_with_args([
        "runtime",
        "stage92-sip003-simple-obfs-http-dataplane-admission",
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
        json["shadowsocks_aead_protocol_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(json["ss2022_true_dataplane_admitted"].as_bool().unwrap());
    assert!(
        !json["sip003_simple_obfs_http_smoke_passed"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["sip003_simple_obfs_http_admitted"].as_bool().unwrap());
    assert!(!json["sip003_plugin_transport_admitted"].as_bool().unwrap());
    assert!(
        !json["shadowsocksr_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["shadowsocks_protocol_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["outbound_true_dataplane_admitted"].as_bool().unwrap());
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
    assert_eq!(
        json["sip003_contract"]["plugin"].as_str().unwrap(),
        "simple-obfs"
    );
    assert_eq!(json["sip003_contract"]["obfs"].as_str().unwrap(), "http");
    assert_eq!(
        json["sip003_contract"]["host"].as_str().unwrap(),
        "front.example"
    );
    assert_eq!(json["sip003_contract"]["path"].as_str().unwrap(), "/abc/");
}

#[test]
fn stage92_runtime_admission_blocks_unsafe_execution() {
    let blocked = run_with_args([
        "runtime",
        "stage92-sip003-simple-obfs-http-dataplane-admission",
        "--execute-smoke",
    ]);
    assert_eq!(blocked.exit_code, 1);
    assert!(
        blocked
            .stdout
            .contains("stage92 root-gated smoke requires --ack-root-gate")
    );
}
