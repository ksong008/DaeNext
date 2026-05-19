use super::*;

#[test]
fn stage55_runtime_admission_fixture_matches() {
    let fixture = load("engine/runtime_stage55/socks5_outbound_true_dataplane_admission.json");
    let output = run_with_args([
        "runtime",
        "stage55-socks5-outbound-true-dataplane-admission",
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
    assert!(!json["socks5_tcp_smoke_passed"].as_bool().unwrap());
    assert!(
        !json["socks5_tcp_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["socks5_auth_observed"].as_bool().unwrap());
    assert!(!json["socks5_connect_request_observed"].as_bool().unwrap());
    assert!(!json["socks5_payload_roundtrip_recorded"].as_bool().unwrap());
    assert_eq!(
        json["socks5_contract"]["target"].as_str().unwrap(),
        fixture["socks5_contract"]["target"].as_str().unwrap()
    );
    assert_eq!(
        json["socks5_contract"]["payload_ascii"].as_str().unwrap(),
        fixture["socks5_contract"]["payload_ascii"]
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
    assert_eq!(
        json["remaining_blockers"].as_array().unwrap().len(),
        fixture["remaining_blockers"].as_array().unwrap().len()
    );
}

#[test]
fn stage55_runtime_admission_blocks_unsafe_execution() {
    let blocked = run_with_args([
        "runtime",
        "stage55-socks5-outbound-true-dataplane-admission",
        "--execute-smoke",
    ]);
    assert_eq!(blocked.exit_code, 1);
    assert!(
        blocked
            .stdout
            .contains("stage55 root-gated smoke requires --ack-root-gate")
    );
}

#[test]
fn stage56_runtime_admission_fixture_matches() {
    let fixture = load("engine/runtime_stage56/socks5_udp_associate_dataplane_admission.json");
    let output = run_with_args([
        "runtime",
        "stage56-socks5-udp-associate-dataplane-admission",
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
        json["socks5_tcp_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["socks5_udp_smoke_passed"].as_bool().unwrap());
    assert!(!json["socks5_udp_associate_admitted"].as_bool().unwrap());
    assert!(
        !json["socks5_protocol_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["socks5_auth_observed"].as_bool().unwrap());
    assert!(
        !json["socks5_udp_associate_request_observed"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["socks5_udp_packet_wrap_unwrap_recorded"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["socks5_tcp_control_connection_retained"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        json["socks5_udp_contract"]["associate_target"]
            .as_str()
            .unwrap(),
        fixture["socks5_udp_contract"]["associate_target"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        json["socks5_udp_contract"]["packet_target"]
            .as_str()
            .unwrap(),
        fixture["socks5_udp_contract"]["packet_target"]
            .as_str()
            .unwrap()
    );
    assert!(
        json["socks5_udp_contract"]["unspecified_bind_falls_back_to_proxy_host"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        json["tcp_control_underlay"]["requested_mark"]
            .as_u64()
            .unwrap(),
        fixture["tcp_control_underlay"]["requested_mark"]
            .as_u64()
            .unwrap()
    );
    assert!(
        json["udp_underlay_socket"]["mptcp_not_applicable"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["outbound_true_dataplane_admitted"].as_bool().unwrap());
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
    assert!(!json["product_chain_switch_allowed"].as_bool().unwrap());
    assert!(!json["true_rust_default_daemon_admitted"].as_bool().unwrap());
    assert!(json["go_default_path_preserved"].as_bool().unwrap());
    assert!(json["go_fallback_required"].as_bool().unwrap());
    assert_eq!(
        json["remaining_blockers"].as_array().unwrap().len(),
        fixture["remaining_blockers"].as_array().unwrap().len()
    );
}

#[test]
fn stage56_runtime_admission_blocks_unsafe_execution() {
    let blocked = run_with_args([
        "runtime",
        "stage56-socks5-udp-associate-dataplane-admission",
        "--execute-smoke",
    ]);
    assert_eq!(blocked.exit_code, 1);
    assert!(
        blocked
            .stdout
            .contains("stage56 root-gated smoke requires --ack-root-gate")
    );
}

#[test]
fn stage57_runtime_admission_fixture_matches() {
    let fixture = load("engine/runtime_stage57/http_connect_dataplane_admission.json");
    let output = run_with_args(["runtime", "stage57-http-connect-dataplane-admission"]);
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
        json["socks5_protocol_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["http_connect_smoke_passed"].as_bool().unwrap());
    assert!(
        !json["http_connect_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["https_proxy_tls_underlay_admitted"].as_bool().unwrap());
    assert!(
        !json["http_proxy_protocol_partial_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["http_connect_request_observed"].as_bool().unwrap());
    assert!(!json["http_proxy_auth_observed"].as_bool().unwrap());
    assert!(
        !json["http_connect_payload_roundtrip_recorded"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        json["http_connect_contract"]["target"].as_str().unwrap(),
        fixture["http_connect_contract"]["target"].as_str().unwrap()
    );
    assert_eq!(
        json["http_connect_contract"]["host_override"]
            .as_str()
            .unwrap(),
        fixture["http_connect_contract"]["host_override"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        json["http_connect_contract"]["payload_ascii"]
            .as_str()
            .unwrap(),
        fixture["http_connect_contract"]["payload_ascii"]
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
    assert_eq!(
        json["remaining_blockers"].as_array().unwrap().len(),
        fixture["remaining_blockers"].as_array().unwrap().len()
    );
}

#[test]
fn stage57_runtime_admission_blocks_unsafe_execution() {
    let blocked = run_with_args([
        "runtime",
        "stage57-http-connect-dataplane-admission",
        "--execute-smoke",
    ]);
    assert_eq!(blocked.exit_code, 1);
    assert!(
        blocked
            .stdout
            .contains("stage57 root-gated smoke requires --ack-root-gate")
    );
}

#[test]
fn stage58_runtime_admission_fixture_matches() {
    let fixture = load("engine/runtime_stage58/shadowsocks_aead_tcp_dataplane_admission.json");
    let output = run_with_args([
        "runtime",
        "stage58-shadowsocks-aead-tcp-dataplane-admission",
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
        json["socks5_protocol_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        json["http_connect_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["shadowsocks_aead_tcp_smoke_passed"].as_bool().unwrap());
    assert!(
        !json["shadowsocks_aead_tcp_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["shadowsocks_protocol_partial_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["shadowsocks_protocol_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["ss2022_true_dataplane_admitted"].as_bool().unwrap());
    assert!(
        !json["shadowsocks_udp_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["sip003_plugin_transport_admitted"].as_bool().unwrap());
    assert_eq!(
        json["shadowsocks_contract"]["cipher"].as_str().unwrap(),
        fixture["shadowsocks_contract"]["cipher"].as_str().unwrap()
    );
    assert_eq!(
        json["shadowsocks_contract"]["target"].as_str().unwrap(),
        fixture["shadowsocks_contract"]["target"].as_str().unwrap()
    );
    assert_eq!(
        json["shadowsocks_contract"]["payload_ascii"]
            .as_str()
            .unwrap(),
        fixture["shadowsocks_contract"]["payload_ascii"]
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
    assert_eq!(
        json["remaining_blockers"].as_array().unwrap().len(),
        fixture["remaining_blockers"].as_array().unwrap().len()
    );
}

#[test]
fn stage58_runtime_admission_blocks_unsafe_execution() {
    let blocked = run_with_args([
        "runtime",
        "stage58-shadowsocks-aead-tcp-dataplane-admission",
        "--execute-smoke",
    ]);
    assert_eq!(blocked.exit_code, 1);
    assert!(
        blocked
            .stdout
            .contains("stage58 root-gated smoke requires --ack-root-gate")
    );
}

#[test]
fn stage59_runtime_admission_fixture_matches() {
    let fixture = load("engine/runtime_stage59/shadowsocks_aead_udp_dataplane_admission.json");
    let output = run_with_args([
        "runtime",
        "stage59-shadowsocks-aead-udp-dataplane-admission",
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
        json["shadowsocks_aead_tcp_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["shadowsocks_aead_udp_smoke_passed"].as_bool().unwrap());
    assert!(
        !json["shadowsocks_aead_udp_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !json["shadowsocks_aead_protocol_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["ss2022_true_dataplane_admitted"].as_bool().unwrap());
    assert_eq!(
        json["shadowsocks_udp_contract"]["target"].as_str().unwrap(),
        fixture["shadowsocks_udp_contract"]["target"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        json["shadowsocks_udp_contract"]["payload_ascii"]
            .as_str()
            .unwrap(),
        fixture["shadowsocks_udp_contract"]["payload_ascii"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        json["udp_underlay_socket"]["requested_mark"]
            .as_u64()
            .unwrap(),
        fixture["udp_underlay_socket"]["requested_mark"]
            .as_u64()
            .unwrap()
    );
    assert!(
        json["udp_underlay_socket"]["mptcp_not_applicable"]
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
fn stage59_runtime_admission_blocks_unsafe_execution() {
    let blocked = run_with_args([
        "runtime",
        "stage59-shadowsocks-aead-udp-dataplane-admission",
        "--execute-smoke",
    ]);
    assert_eq!(blocked.exit_code, 1);
    assert!(
        blocked
            .stdout
            .contains("stage59 root-gated smoke requires --ack-root-gate")
    );
}

#[test]
fn stage60_runtime_admission_fixture_matches() {
    let fixture = load("engine/runtime_stage60/trojan_tcp_dataplane_admission.json");
    let output = run_with_args(["runtime", "stage60-trojan-tcp-dataplane-admission"]);
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
        json["shadowsocks_aead_protocol_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["ss2022_true_dataplane_admitted"].as_bool().unwrap());
    assert!(!json["trojanc_tcp_smoke_passed"].as_bool().unwrap());
    assert!(
        !json["trojanc_tcp_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["trojan_protocol_partial_admitted"].as_bool().unwrap());
    assert!(
        !json["trojan_protocol_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["trojan_tls_underlay_admitted"].as_bool().unwrap());
    assert!(!json["trojan_udp_over_tcp_admitted"].as_bool().unwrap());
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
        json["trojan_contract"]["target"].as_str().unwrap(),
        fixture["trojan_contract"]["target"].as_str().unwrap()
    );
    assert_eq!(
        json["trojan_contract"]["payload_ascii"].as_str().unwrap(),
        fixture["trojan_contract"]["payload_ascii"]
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
fn stage60_runtime_admission_blocks_unsafe_execution() {
    let blocked = run_with_args([
        "runtime",
        "stage60-trojan-tcp-dataplane-admission",
        "--execute-smoke",
    ]);
    assert_eq!(blocked.exit_code, 1);
    assert!(
        blocked
            .stdout
            .contains("stage60 root-gated smoke requires --ack-root-gate")
    );
}

#[test]
fn stage61_runtime_admission_fixture_matches() {
    let fixture = load("engine/runtime_stage61/trojan_udp_over_tcp_dataplane_admission.json");
    let output = run_with_args(["runtime", "stage61-trojan-udp-over-tcp-dataplane-admission"]);
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
        json["trojanc_tcp_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["trojan_udp_over_tcp_smoke_passed"].as_bool().unwrap());
    assert!(!json["trojan_udp_over_tcp_admitted"].as_bool().unwrap());
    assert!(json["trojan_protocol_partial_admitted"].as_bool().unwrap());
    assert!(
        !json["trojan_protocol_true_dataplane_admitted"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["trojan_tls_underlay_admitted"].as_bool().unwrap());
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
        json["trojan_udp_over_tcp_contract"]["session_target"]
            .as_str()
            .unwrap(),
        fixture["trojan_udp_over_tcp_contract"]["session_target"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        json["trojan_udp_over_tcp_contract"]["packet_target"]
            .as_str()
            .unwrap(),
        fixture["trojan_udp_over_tcp_contract"]["packet_target"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        json["trojan_udp_over_tcp_contract"]["payload_ascii"]
            .as_str()
            .unwrap(),
        fixture["trojan_udp_over_tcp_contract"]["payload_ascii"]
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
fn stage61_runtime_admission_blocks_unsafe_execution() {
    let blocked = run_with_args([
        "runtime",
        "stage61-trojan-udp-over-tcp-dataplane-admission",
        "--execute-smoke",
    ]);
    assert_eq!(blocked.exit_code, 1);
    assert!(
        blocked
            .stdout
            .contains("stage61 root-gated smoke requires --ack-root-gate")
    );
}
