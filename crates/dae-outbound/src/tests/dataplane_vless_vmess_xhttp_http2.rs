use std::os::unix::net::UnixStream;
use std::thread;
use std::time::Duration;

use crate::shared_transport::XHttpLifecycleOptions;
use crate::{vless, vmess};

#[test]
fn case_vless_xhttp_http2_lifecycle_roundtrips_tcp_payload() {
    let key = vless::password_to_key("7c12c745-63a5-433d-9e60-022e469b5bd4").unwrap();
    let target = "fixture-vless-xhttp-h2-target.fixture.invalid:443";
    let payload = b"fixture-vless-xhttp-h2-ping".to_vec();
    let xhttp = case_xhttp_options("fixture-vless-xhttp-h2.fixture.invalid", 13601);
    let (mut client, mut server) = UnixStream::pair().unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    client
        .set_write_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    server
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    server
        .set_write_timeout(Some(Duration::from_secs(2)))
        .unwrap();

    let server_xhttp = xhttp.clone();
    let expected_payload = payload.clone();
    let expected_target = target.to_owned();
    let handle = thread::spawn(move || {
        let request = vless::read_tcp_request_from_xhttp_http2_stream(
            &mut server,
            expected_payload.len(),
            &server_xhttp,
        )
        .unwrap();
        assert_eq!(request.request.key, key);
        assert_eq!(request.request.command, vmess::VMessNetwork::Tcp.byte());
        assert_eq!(request.request.target, expected_target);
        assert_eq!(request.request.payload, expected_payload);
        assert!(request.http2_frames.http2_client_preface_validated);
        assert!(request.http2_frames.settings_frame_validated);
        assert!(request.http2_frames.headers_frame_validated);
        assert!(request.http2_frames.data_frame_validated);
        assert_eq!(request.http2_frames.alpn, "h2");
        assert!(!request.http2_frames.use_h3);
        let response = vless::response_payload_bytes(&request.request.payload);
        vless::write_xhttp_http2_payload_response(&mut server, &response).unwrap()
    });

    let report = vless::tcp_exchange_over_xhttp_http2_stream(
        &mut client,
        "fixture-vless-xhttp-h2-proxy.fixture.invalid:443",
        &key,
        target,
        &xhttp,
        &payload,
    )
    .unwrap();
    let response_frames = handle.join().unwrap();

    assert_eq!(report.target, target);
    assert_eq!(report.echoed_payload, payload);
    assert_eq!(report.command, vmess::VMessNetwork::Tcp.byte());
    assert_eq!(report.xhttp_mode, "packet-up");
    assert_eq!(report.xhttp_alpn, "h2");
    assert!(report.http2_lifecycle);
    assert!(report.h2_packet_up_validated);
    assert!(report.h3_deferred);
    assert!(report.tls_utls_reality_deferred);
    assert!(report.download_settings_deferred);
    assert!(report.stream_modes_deferred);
    assert!(report.http2_client_preface_validated);
    assert!(report.http2_settings_validated);
    assert!(report.http2_headers_validated);
    assert!(report.http2_data_validated);
    assert!(report.true_dataplane);
    assert!(!report.use_h3);
    assert!(response_frames.response_settings_ack_validated);
    assert!(response_frames.response_headers_validated);
    assert!(response_frames.response_data_validated);
}

#[test]
fn case_vmess_xhttp_http2_lifecycle_roundtrips_aead_tcp_payload() {
    let uuid = "7c12c745-63a5-433d-9e60-022e469b5bd4";
    let target = "fixture-vmess-xhttp-h2-target.fixture.invalid:443";
    let payload = b"fixture-vmess-xhttp-h2-ping".to_vec();
    let xhttp = case_xhttp_options("fixture-vmess-xhttp-h2.fixture.invalid", 13602);
    let (mut client, mut server) = UnixStream::pair().unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    client
        .set_write_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    server
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    server
        .set_write_timeout(Some(Duration::from_secs(2)))
        .unwrap();

    let server_xhttp = xhttp.clone();
    let expected_uuid = uuid.to_owned();
    let expected_payload = payload.clone();
    let expected_target = target.to_owned();
    let handle = thread::spawn(move || {
        let request = vmess::read_aead_tcp_request_from_xhttp_http2_stream(
            &mut server,
            &expected_uuid,
            &server_xhttp,
        )
        .unwrap();
        assert_eq!(request.request.command, vmess::VMessNetwork::Tcp.byte());
        assert_eq!(request.request.target, expected_target);
        assert_eq!(request.request.payload, expected_payload);
        assert!(request.http2_frames.http2_client_preface_validated);
        assert!(request.http2_frames.settings_frame_validated);
        assert!(request.http2_frames.headers_frame_validated);
        assert!(request.http2_frames.data_frame_validated);
        assert_eq!(request.http2_frames.alpn, "h2");
        assert!(!request.http2_frames.use_h3);
        vmess::write_aead_xhttp_http2_response(
            &mut server,
            &request.request,
            &request.request.payload,
        )
        .unwrap()
    });

    let report = vmess::aead_tcp_exchange_over_xhttp_http2_stream(
        &mut client,
        "fixture-vmess-xhttp-h2-proxy.fixture.invalid:443",
        uuid,
        target,
        &xhttp,
        &payload,
    )
    .unwrap();
    let response_frames = handle.join().unwrap();

    assert_eq!(report.target, target);
    assert_eq!(report.echoed_payload, payload);
    assert_eq!(report.command, vmess::VMessNetwork::Tcp.byte());
    assert_eq!(report.security, vmess::VMESS_AEAD_SECURITY_AES_128_GCM);
    assert_eq!(report.xhttp_mode, "packet-up");
    assert_eq!(report.xhttp_alpn, "h2");
    assert!(report.http2_lifecycle);
    assert!(report.h2_packet_up_validated);
    assert!(report.h3_deferred);
    assert!(report.tls_utls_deferred);
    assert!(report.reality_rejected_for_vmess);
    assert!(report.download_settings_deferred);
    assert!(report.stream_modes_deferred);
    assert!(report.http2_client_preface_validated);
    assert!(report.http2_settings_validated);
    assert!(report.http2_headers_validated);
    assert!(report.http2_data_validated);
    assert!(report.true_dataplane);
    assert!(!report.use_h3);
    assert!(response_frames.response_settings_ack_validated);
    assert!(response_frames.response_headers_validated);
    assert!(response_frames.response_data_validated);
}

fn case_xhttp_options(host: &str, seq: u64) -> XHttpLifecycleOptions {
    XHttpLifecycleOptions::new(
        host,
        "/dae-fixture-xhttp-h2",
        "packet-up",
        "tls",
        "h2",
        "dae-fixture-xhttp-h2-session",
        seq,
    )
    .unwrap()
}
