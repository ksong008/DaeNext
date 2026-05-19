use super::*;

#[test]
fn stage65_runtime_admission_fixture_matches() {
    let fixture = load("engine/runtime_stage65/vmess_aead_tcp_dataplane_admission.json");
    let output = run_with_args(["runtime", "stage65-vmess-aead-tcp-dataplane-admission"]);
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
    assert_eq!(
        json["evidence_class"].as_str().unwrap(),
        fixture["evidence_class"].as_str().unwrap()
    );
    assert!(!json["execute_smoke"].as_bool().unwrap());
    assert!(json["read_only"].as_bool().unwrap());
    assert!(!json["blocked"].as_bool().unwrap());
    assert!(json["vless_mux_admitted"].as_bool().unwrap());
    assert!(!json["vmess_aead_tcp_smoke_passed"].as_bool().unwrap());
    assert!(
        !json["vmess_aead_tcp_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["vmess_protocol_partial_admitted"].as_bool().unwrap());
    assert!(
        !json["vmess_protocol_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["vmess_tls_underlay_admitted"].as_bool().unwrap());
    assert!(!json["vmess_shared_transport_admitted"].as_bool().unwrap());
    assert!(!json["vmess_udp_packet_addr_admitted"].as_bool().unwrap());
    assert!(!json["vmess_mux_admitted"].as_bool().unwrap());
    assert_eq!(
        json["vmess_aead_tcp_contract"]["target"].as_str().unwrap(),
        fixture["vmess_aead_tcp_contract"]["target"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        json["vmess_aead_tcp_contract"]["payload_ascii"]
            .as_str()
            .unwrap(),
        fixture["vmess_aead_tcp_contract"]["payload_ascii"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        json["vmess_aead_tcp_contract"]["security_byte"]
            .as_u64()
            .unwrap(),
        fixture["vmess_aead_tcp_contract"]["security_byte"]
            .as_u64()
            .unwrap()
    );
    assert_eq!(
        json["underlay_socket"]["requested_mark"].as_u64().unwrap(),
        fixture["underlay_socket"]["requested_mark"]
            .as_u64()
            .unwrap()
    );
    assert!(
        json["underlay_socket"]["requested_mptcp"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["outbound_true_dataplane_admitted"].as_bool().unwrap());
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
    assert!(!json["product_chain_switch_allowed"].as_bool().unwrap());
    assert!(!json["true_rust_default_daemon_admitted"].as_bool().unwrap());
    assert!(json["go_default_path_preserved"].as_bool().unwrap());
    assert!(json["go_fallback_required"].as_bool().unwrap());
}

#[test]
fn stage65_runtime_admission_blocks_unsafe_execution() {
    let blocked = run_with_args([
        "runtime",
        "stage65-vmess-aead-tcp-dataplane-admission",
        "--execute-smoke",
    ]);
    assert_eq!(blocked.exit_code, 1);
    assert!(
        blocked
            .stdout
            .contains("stage65 root-gated smoke requires --ack-root-gate")
    );
}

#[test]
fn stage66_runtime_admission_fixture_matches() {
    let fixture = load("engine/runtime_stage66/vmess_aead_udp_over_tcp_dataplane_admission.json");
    let output = run_with_args([
        "runtime",
        "stage66-vmess-aead-udp-over-tcp-dataplane-admission",
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
    assert_eq!(
        json["evidence_class"].as_str().unwrap(),
        fixture["evidence_class"].as_str().unwrap()
    );
    assert!(!json["execute_smoke"].as_bool().unwrap());
    assert!(json["read_only"].as_bool().unwrap());
    assert!(!json["blocked"].as_bool().unwrap());
    assert!(
        json["vmess_aead_tcp_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["vmess_aead_udp_over_tcp_smoke_passed"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["vmess_aead_udp_over_tcp_admitted"].as_bool().unwrap());
    assert!(!json["vmess_protocol_partial_admitted"].as_bool().unwrap());
    assert!(
        !json["vmess_protocol_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["vmess_udp_packet_addr_admitted"].as_bool().unwrap());
    assert!(!json["vmess_mux_admitted"].as_bool().unwrap());
    assert_eq!(
        json["vmess_aead_udp_over_tcp_contract"]["target"]
            .as_str()
            .unwrap(),
        fixture["vmess_aead_udp_over_tcp_contract"]["target"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        json["vmess_aead_udp_over_tcp_contract"]["payload_ascii"]
            .as_str()
            .unwrap(),
        fixture["vmess_aead_udp_over_tcp_contract"]["payload_ascii"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        json["vmess_aead_udp_over_tcp_contract"]["packet_len"]
            .as_u64()
            .unwrap(),
        fixture["vmess_aead_udp_over_tcp_contract"]["packet_len"]
            .as_u64()
            .unwrap()
    );
    assert_eq!(
        json["underlay_socket"]["requested_mark"].as_u64().unwrap(),
        fixture["underlay_socket"]["requested_mark"]
            .as_u64()
            .unwrap()
    );
    assert!(
        json["underlay_socket"]["requested_mptcp"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["outbound_true_dataplane_admitted"].as_bool().unwrap());
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
    assert!(!json["product_chain_switch_allowed"].as_bool().unwrap());
    assert!(!json["true_rust_default_daemon_admitted"].as_bool().unwrap());
    assert!(json["go_default_path_preserved"].as_bool().unwrap());
    assert!(json["go_fallback_required"].as_bool().unwrap());
}

#[test]
fn stage66_runtime_admission_blocks_unsafe_execution() {
    let blocked = run_with_args([
        "runtime",
        "stage66-vmess-aead-udp-over-tcp-dataplane-admission",
        "--execute-smoke",
    ]);
    assert_eq!(blocked.exit_code, 1);
    assert!(
        blocked
            .stdout
            .contains("stage66 root-gated smoke requires --ack-root-gate")
    );
}

#[test]
fn stage67_runtime_admission_fixture_matches() {
    let fixture = load("engine/runtime_stage67/vmess_packet_addr_udp_dataplane_admission.json");
    let output = run_with_args([
        "runtime",
        "stage67-vmess-packet-addr-udp-dataplane-admission",
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
    assert_eq!(
        json["evidence_class"].as_str().unwrap(),
        fixture["evidence_class"].as_str().unwrap()
    );
    assert!(!json["execute_smoke"].as_bool().unwrap());
    assert!(json["read_only"].as_bool().unwrap());
    assert!(!json["blocked"].as_bool().unwrap());
    assert!(
        json["vmess_aead_tcp_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(json["vmess_aead_udp_over_tcp_admitted"].as_bool().unwrap());
    assert!(
        !json["vmess_packet_addr_udp_smoke_passed"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["vmess_udp_packet_addr_admitted"].as_bool().unwrap());
    assert!(!json["vmess_protocol_partial_admitted"].as_bool().unwrap());
    assert!(
        !json["vmess_protocol_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["vmess_mux_admitted"].as_bool().unwrap());
    assert_eq!(
        json["vmess_packet_addr_udp_contract"]["magic_domain"]
            .as_str()
            .unwrap(),
        fixture["vmess_packet_addr_udp_contract"]["magic_domain"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        json["vmess_packet_addr_udp_contract"]["request_target"]
            .as_str()
            .unwrap(),
        fixture["vmess_packet_addr_udp_contract"]["request_target"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        json["vmess_packet_addr_udp_contract"]["packet_target"]
            .as_str()
            .unwrap(),
        fixture["vmess_packet_addr_udp_contract"]["packet_target"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        json["vmess_packet_addr_udp_contract"]["packet_addr_len"]
            .as_u64()
            .unwrap(),
        fixture["vmess_packet_addr_udp_contract"]["packet_addr_len"]
            .as_u64()
            .unwrap()
    );
    assert_eq!(
        json["vmess_packet_addr_udp_contract"]["packet_len"]
            .as_u64()
            .unwrap(),
        fixture["vmess_packet_addr_udp_contract"]["packet_len"]
            .as_u64()
            .unwrap()
    );
    assert_eq!(
        json["underlay_socket"]["requested_mark"].as_u64().unwrap(),
        fixture["underlay_socket"]["requested_mark"]
            .as_u64()
            .unwrap()
    );
    assert!(
        json["underlay_socket"]["requested_mptcp"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["outbound_true_dataplane_admitted"].as_bool().unwrap());
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
    assert!(!json["product_chain_switch_allowed"].as_bool().unwrap());
    assert!(!json["true_rust_default_daemon_admitted"].as_bool().unwrap());
    assert!(json["go_default_path_preserved"].as_bool().unwrap());
    assert!(json["go_fallback_required"].as_bool().unwrap());
}

#[test]
fn stage67_runtime_admission_blocks_unsafe_execution() {
    let blocked = run_with_args([
        "runtime",
        "stage67-vmess-packet-addr-udp-dataplane-admission",
        "--execute-smoke",
    ]);
    assert_eq!(blocked.exit_code, 1);
    assert!(
        blocked
            .stdout
            .contains("stage67 root-gated smoke requires --ack-root-gate")
    );
}

#[test]
fn stage68_runtime_admission_fixture_matches() {
    let fixture = load("engine/runtime_stage68/vmess_mux_dataplane_admission.json");
    let output = run_with_args(["runtime", "stage68-vmess-mux-dataplane-admission"]);
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
    assert_eq!(
        json["evidence_class"].as_str().unwrap(),
        fixture["evidence_class"].as_str().unwrap()
    );
    assert!(!json["execute_smoke"].as_bool().unwrap());
    assert!(json["read_only"].as_bool().unwrap());
    assert!(!json["blocked"].as_bool().unwrap());
    assert!(
        json["vmess_aead_tcp_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(json["vmess_aead_udp_over_tcp_admitted"].as_bool().unwrap());
    assert!(json["vmess_udp_packet_addr_admitted"].as_bool().unwrap());
    assert!(!json["vmess_mux_smoke_passed"].as_bool().unwrap());
    assert!(!json["vmess_mux_admitted"].as_bool().unwrap());
    assert!(!json["vmess_protocol_partial_admitted"].as_bool().unwrap());
    assert!(
        !json["vmess_protocol_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["vmess_tls_underlay_admitted"].as_bool().unwrap());
    assert!(!json["vmess_shared_transport_admitted"].as_bool().unwrap());
    assert_eq!(
        json["vmess_mux_contract"]["request_target"]
            .as_str()
            .unwrap(),
        fixture["vmess_mux_contract"]["request_target"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        json["vmess_mux_contract"]["mux_target"].as_str().unwrap(),
        fixture["vmess_mux_contract"]["mux_target"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        json["vmess_mux_contract"]["mux_id_hex"].as_str().unwrap(),
        fixture["vmess_mux_contract"]["mux_id_hex"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        json["vmess_mux_contract"]["payload_ascii"]
            .as_str()
            .unwrap(),
        fixture["vmess_mux_contract"]["payload_ascii"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        json["underlay_socket"]["requested_mark"].as_u64().unwrap(),
        fixture["underlay_socket"]["requested_mark"]
            .as_u64()
            .unwrap()
    );
    assert!(
        json["underlay_socket"]["requested_mptcp"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["outbound_true_dataplane_admitted"].as_bool().unwrap());
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
    assert!(!json["product_chain_switch_allowed"].as_bool().unwrap());
    assert!(!json["true_rust_default_daemon_admitted"].as_bool().unwrap());
    assert!(json["go_default_path_preserved"].as_bool().unwrap());
    assert!(json["go_fallback_required"].as_bool().unwrap());
}

#[test]
fn stage68_runtime_admission_blocks_unsafe_execution() {
    let blocked = run_with_args([
        "runtime",
        "stage68-vmess-mux-dataplane-admission",
        "--execute-smoke",
    ]);
    assert_eq!(blocked.exit_code, 1);
    assert!(
        blocked
            .stdout
            .contains("stage68 root-gated smoke requires --ack-root-gate")
    );
}
