use super::*;

#[test]
fn stage90_runtime_admission_fixture_matches() {
    let fixture = load("engine/runtime_stage90/ss2022_udp_replay_dataplane_admission.json");
    let output = run_with_args(["runtime", "stage90-ss2022-udp-replay-dataplane-admission"]);
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
        json["ss2022_tcp_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        json["ss2022_multi_psk_identity_header_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["ss2022_udp_smoke_passed"].as_bool().unwrap());
    assert!(
        !json["ss2022_udp_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["ss2022_true_dataplane_admitted"].as_bool().unwrap());
    assert_eq!(
        json["ss2022_udp_contract"]["aes"]["cipher"]
            .as_str()
            .unwrap(),
        "2022-blake3-aes-128-gcm"
    );
    assert_eq!(
        json["ss2022_udp_contract"]["aes"]["psk_count"]
            .as_u64()
            .unwrap(),
        2
    );
    assert_eq!(
        json["ss2022_udp_contract"]["chacha"]["packet_nonce_len"]
            .as_u64()
            .unwrap(),
        24
    );
    assert!(!json["outbound_true_dataplane_admitted"].as_bool().unwrap());
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
    assert!(!json["product_chain_switch_allowed"].as_bool().unwrap());
}

#[test]
fn stage90_runtime_admission_blocks_unsafe_execution() {
    let blocked = run_with_args([
        "runtime",
        "stage90-ss2022-udp-replay-dataplane-admission",
        "--execute-smoke",
    ]);
    assert_eq!(blocked.exit_code, 1);
    assert!(
        blocked
            .stdout
            .contains("stage90 root-gated smoke requires --ack-root-gate")
    );
}
