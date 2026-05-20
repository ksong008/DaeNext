use super::*;

#[test]
fn stage88_runtime_admission_fixture_matches() {
    let fixture = load("engine/runtime_stage88/ss2022_tcp_dataplane_admission.json");
    let output = run_with_args(["runtime", "stage88-ss2022-tcp-dataplane-admission"]);
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
    assert!(!json["ss2022_tcp_smoke_passed"].as_bool().unwrap());
    assert!(
        !json["ss2022_tcp_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["ss2022_udp_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["ss2022_multi_psk_identity_header_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["ss2022_true_dataplane_admitted"].as_bool().unwrap());
    assert_eq!(
        json["ss2022_contract"]["cipher"].as_str().unwrap(),
        "2022-blake3-aes-256-gcm"
    );
    assert_eq!(json["ss2022_contract"]["psk_count"].as_u64().unwrap(), 1);
    assert_eq!(json["ss2022_contract"]["upsk_index"].as_u64().unwrap(), 0);
    assert!(
        json["ss2022_contract"]["multi_psk_identity_header_deferred"]
            .as_bool()
            .unwrap()
    );
    assert!(json["ss2022_contract"]["udp_deferred"].as_bool().unwrap());
    assert!(!json["outbound_true_dataplane_admitted"].as_bool().unwrap());
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
    assert!(!json["product_chain_switch_allowed"].as_bool().unwrap());
}

#[test]
fn stage88_runtime_admission_blocks_unsafe_execution() {
    let blocked = run_with_args([
        "runtime",
        "stage88-ss2022-tcp-dataplane-admission",
        "--execute-smoke",
    ]);
    assert_eq!(blocked.exit_code, 1);
    assert!(
        blocked
            .stdout
            .contains("stage88 root-gated smoke requires --ack-root-gate")
    );
}
