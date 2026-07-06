use super::*;

#[test]
fn case_hysteria2_underlay_contract_preserves_udp_mark_and_mptcp_field() {
    let contract =
        hysteria2::underlay_contract("tcp", "fixture.invalid:443,8443-8445", 1234, true, 30_000);

    assert_eq!(contract.input_network, "tcp");
    assert_eq!(contract.underlay_network, "udp");
    assert_eq!(contract.input_mark, 1234);
    assert_eq!(contract.underlay_mark, 1234);
    assert!(contract.input_mptcp);
    assert!(contract.underlay_mptcp_field);
    assert!(!contract.udp_mptcp_effective);
    assert_eq!(contract.route_cache_key_network, "udp");
    assert_eq!(contract.udp_hop_interval_ms, 30_000);
    assert_eq!(contract.server.host, "fixture.invalid");
    assert_eq!(contract.server.port, "443,8443-8445");
    assert!(contract.server.port_hopping);
}

#[test]
fn case_hysteria2_pin_sha256_matches_raw_cert_hash_only() {
    let raw_cert = b"fixture-hysteria2-raw-cert";
    let expected = hysteria2::raw_cert_sha256_hex(raw_cert);
    let configured = format!(
        "{}:{}-{}",
        &expected[0..2],
        &expected[2..4].to_uppercase(),
        &expected[4..]
    );
    let check = hysteria2::pin_sha256_matches_raw_cert(&configured, raw_cert);

    assert_eq!(check.configured_pin_normal, expected);
    assert_eq!(check.raw_cert_sha256_hex, expected);
    assert!(check.matched);

    let mismatch = hysteria2::pin_sha256_matches_raw_cert("00", raw_cert);
    assert!(!mismatch.matched);
}

#[test]
fn case_hysteria2_runtime_tls_uses_system_roots_without_pin() {
    assert!(hysteria2::build_hysteria2_runtime_client_config(false, String::new()).is_ok());
    assert!(hysteria2::build_hysteria2_runtime_client_config(false, "00".to_owned()).is_ok());
    assert!(hysteria2::build_hysteria2_runtime_client_config(true, String::new()).is_ok());
}
