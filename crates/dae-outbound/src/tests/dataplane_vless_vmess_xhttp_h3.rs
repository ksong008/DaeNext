use std::time::Duration;

use crate::shared_transport::{XHTTP_H3_ALPN, XHttpH3LoopbackOptions, XHttpLifecycleOptions};
use crate::{vless, vmess};

#[test]
fn case_vless_xhttp_h3_lifecycle_roundtrips_tcp_payload() {
    let key = vless::password_to_key("7c12c745-63a5-433d-9e60-022e469b5bd4").unwrap();
    let target = "fixture-vless-xhttp-h3-target.fixture.invalid:443";
    let payload = b"fixture-vless-xhttp-h3-ping".to_vec();
    let xhttp = case_xhttp_options("fixture-vless-xhttp-h3.fixture.invalid", 13701);

    let report = vless::tcp_exchange_over_xhttp_h3_loopback(
        "fixture-vless-xhttp-h3-proxy.fixture.invalid:443",
        &key,
        target,
        &xhttp,
        &payload,
        1,
        Duration::from_secs(8),
    )
    .unwrap();

    assert_eq!(report.target, target);
    assert_eq!(report.echoed_payload, payload);
    assert_eq!(report.command, vmess::VMessNetwork::Tcp.byte());
    assert_eq!(report.xhttp_mode, "packet-up");
    assert_eq!(report.xhttp_alpn, XHTTP_H3_ALPN);
    assert_eq!(report.client_selected_alpn, XHTTP_H3_ALPN);
    assert_eq!(report.server_selected_alpn, XHTTP_H3_ALPN);
    assert!(report.tls13_only_configured);
    assert!(report.quic_datagram_disabled);
    assert_eq!(report.h3_status, 200);
    assert_eq!(report.h3_request_count, 1);
    assert_eq!(report.h3_request_path_match_count, 1);
    assert_eq!(report.h3_request_body_match_count, 1);
    assert_eq!(report.h3_response_count, 1);
    assert!(
        report
            .xhttp_request_path
            .contains("dae-fixture-xhttp-h3-session")
    );
    assert!(report.xhttp_request_path.contains("seq=13701"));
    assert!(report.h3_request_response_validated);
    assert!(report.quic_handshake_validated);
    assert!(report.xhttp_h3_packet_up_validated);
    assert!(report.full_h3_tls_lifecycle);
    assert!(report.reality_h3_rejected);
    assert!(report.utls_deferred);
    assert!(report.vision_deferred);
    assert!(report.download_settings_deferred);
    assert!(report.stream_modes_deferred);
    assert!(report.true_dataplane);
}

#[test]
fn case_vmess_xhttp_h3_lifecycle_roundtrips_aead_tcp_payload() {
    let uuid = "7c12c745-63a5-433d-9e60-022e469b5bd4";
    let target = "fixture-vmess-xhttp-h3-target.fixture.invalid:443";
    let payload = b"fixture-vmess-xhttp-h3-ping".to_vec();
    let xhttp = case_xhttp_options("fixture-vmess-xhttp-h3.fixture.invalid", 13702);

    let report = vmess::aead_tcp_exchange_over_xhttp_h3_loopback(
        "fixture-vmess-xhttp-h3-proxy.fixture.invalid:443",
        uuid,
        target,
        &xhttp,
        &payload,
        1,
        Duration::from_secs(8),
    )
    .unwrap();

    assert_eq!(report.target, target);
    assert_eq!(report.echoed_payload, payload);
    assert_eq!(report.command, vmess::VMessNetwork::Tcp.byte());
    assert_eq!(report.security, vmess::VMESS_AEAD_SECURITY_AES_128_GCM);
    assert_eq!(report.xhttp_mode, "packet-up");
    assert_eq!(report.xhttp_alpn, XHTTP_H3_ALPN);
    assert_eq!(report.client_selected_alpn, XHTTP_H3_ALPN);
    assert_eq!(report.server_selected_alpn, XHTTP_H3_ALPN);
    assert!(report.tls13_only_configured);
    assert!(report.quic_datagram_disabled);
    assert_eq!(report.h3_status, 200);
    assert_eq!(report.h3_request_count, 1);
    assert_eq!(report.h3_request_path_match_count, 1);
    assert_eq!(report.h3_request_body_match_count, 1);
    assert_eq!(report.h3_response_count, 1);
    assert!(
        report
            .xhttp_request_path
            .contains("dae-fixture-xhttp-h3-session")
    );
    assert!(report.xhttp_request_path.contains("seq=13702"));
    assert!(report.h3_request_response_validated);
    assert!(report.quic_handshake_validated);
    assert!(report.xhttp_h3_packet_up_validated);
    assert!(report.full_h3_tls_lifecycle);
    assert!(report.reality_rejected_for_vmess);
    assert!(report.utls_deferred);
    assert!(report.download_settings_deferred);
    assert!(report.stream_modes_deferred);
    assert!(report.true_dataplane);
}

#[test]
fn case_xhttp_h3_gate_rejects_reality_and_non_h3_modes() {
    let reality_h3 = XHttpLifecycleOptions::new(
        "fixture-vless-xhttp-h3.fixture.invalid",
        "/dae-fixture-xhttp-h3",
        "packet-up",
        "reality",
        "h3",
        "dae-fixture-xhttp-h3-session",
        13703,
    )
    .unwrap_err();
    assert!(reality_h3.to_string().contains("reality with h3"));

    let h2_options = XHttpLifecycleOptions::new(
        "fixture-vless-xhttp-h3.fixture.invalid",
        "/dae-fixture-xhttp-h3",
        "packet-up",
        "tls",
        "h2",
        "dae-fixture-xhttp-h3-session",
        13704,
    )
    .unwrap();
    let h2_gate = XHttpH3LoopbackOptions::new(
        h2_options,
        b"fixture-request".to_vec(),
        b"fixture-response".to_vec(),
        1,
        Duration::from_secs(8),
    )
    .unwrap_err();
    assert!(h2_gate.to_string().contains("exact alpn=h3"));
}

fn case_xhttp_options(host: &str, seq: u64) -> XHttpLifecycleOptions {
    XHttpLifecycleOptions::new(
        host,
        "/dae-fixture-xhttp-h3",
        "packet-up",
        "tls",
        "h3",
        "dae-fixture-xhttp-h3-session",
        seq,
    )
    .unwrap()
}
