use std::os::unix::net::UnixStream;
use std::thread;
use std::time::Duration;

use crate::shared_transport::{GrpcHttp2LifecycleOptions, GrpcLifecycleOptions};
use crate::{vless, vmess};

#[test]
fn stage134_vless_grpc_http2_lifecycle_roundtrips_tcp_payload() {
    let key = vless::password_to_key("7c12c745-63a5-433d-9e60-022e469b5bd4").unwrap();
    let target = "stage134-vless-grpc-http2-target.example:443";
    let payload = b"stage134-vless-grpc-http2-ping".to_vec();
    let grpc = GrpcLifecycleOptions::new(
        "stage134-vless-grpc-http2-proxy.example:443",
        "",
        "stage134-vless-grpc-http2-sni.example",
        "stage134-vless-dialer",
        true,
        1340,
        true,
    );
    let http2 = GrpcHttp2LifecycleOptions {
        authority: grpc.address.clone(),
        service_name: grpc.service_name.clone(),
    };
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

    let expected_payload = payload.clone();
    let expected_target = target.to_owned();
    let handle = thread::spawn(move || {
        let request = vless::read_tcp_request_from_grpc_http2_stream(
            &mut server,
            &http2,
            expected_payload.len(),
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
        let response = vless::response_payload_bytes(&request.request.payload);
        vless::write_grpc_http2_hunk_response(&mut server, &response).unwrap()
    });

    let report = vless::tcp_exchange_over_grpc_http2_stream(
        &mut client,
        "stage134-vless-grpc-http2-proxy.example:443",
        &key,
        target,
        &grpc,
        &payload,
    )
    .unwrap();
    let response_frames = handle.join().unwrap();

    assert_eq!(report.target, target);
    assert_eq!(report.echoed_payload, payload);
    assert_eq!(report.grpc_service_name, "GunService");
    assert_eq!(report.command, vmess::VMessNetwork::Tcp.byte());
    assert!(report.http2_lifecycle);
    assert!(!report.full_tls_lifecycle);
    assert!(report.tls_utls_reality_deferred);
    assert!(report.http2_client_preface_validated);
    assert!(report.http2_settings_validated);
    assert!(report.http2_headers_validated);
    assert!(report.http2_data_validated);
    assert!(report.grpc_hunk_frame_validated);
    assert!(report.cache_key_route_context_validated);
    assert!(report.true_dataplane);
    assert!(response_frames.response_settings_ack_validated);
    assert!(response_frames.response_headers_validated);
    assert!(response_frames.response_data_validated);
    assert!(
        report
            .grpc_cache_key
            .contains("stage134-vless-grpc-http2-proxy.example:443")
    );
    assert!(
        report
            .grpc_cache_key
            .contains("stage134-vless-grpc-http2-sni.example")
    );
}

#[test]
fn stage134_vmess_grpc_http2_lifecycle_roundtrips_aead_tcp_payload() {
    let uuid = "7c12c745-63a5-433d-9e60-022e469b5bd4";
    let target = "stage134-vmess-grpc-http2-target.example:443";
    let payload = b"stage134-vmess-grpc-http2-ping".to_vec();
    let grpc = GrpcLifecycleOptions::new(
        "stage134-vmess-grpc-http2-proxy.example:443",
        "dae-stage134-grpc",
        "stage134-vmess-grpc-http2-sni.example",
        "stage134-vmess-dialer",
        true,
        1341,
        true,
    );
    let http2 = GrpcHttp2LifecycleOptions {
        authority: grpc.address.clone(),
        service_name: grpc.service_name.clone(),
    };
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

    let expected_payload = payload.clone();
    let expected_target = target.to_owned();
    let expected_uuid = uuid.to_owned();
    let handle = thread::spawn(move || {
        let request = vmess::read_aead_tcp_request_from_grpc_http2_stream(
            &mut server,
            &expected_uuid,
            &http2,
        )
        .unwrap();
        assert_eq!(request.request.command, vmess::VMessNetwork::Tcp.byte());
        assert_eq!(request.request.target, expected_target);
        assert_eq!(request.request.payload, expected_payload);
        assert!(request.http2_frames.http2_client_preface_validated);
        assert!(request.http2_frames.settings_frame_validated);
        assert!(request.http2_frames.headers_frame_validated);
        assert!(request.http2_frames.data_frame_validated);
        vmess::write_aead_grpc_http2_hunk_response(
            &mut server,
            &request.request,
            &request.request.payload,
        )
        .unwrap()
    });

    let report = vmess::aead_tcp_exchange_over_grpc_http2_stream(
        &mut client,
        "stage134-vmess-grpc-http2-proxy.example:443",
        uuid,
        target,
        &grpc,
        &payload,
    )
    .unwrap();
    let response_frames = handle.join().unwrap();

    assert_eq!(report.target, target);
    assert_eq!(report.echoed_payload, payload);
    assert_eq!(report.grpc_service_name, "dae-stage134-grpc");
    assert_eq!(report.command, vmess::VMessNetwork::Tcp.byte());
    assert_eq!(report.security, vmess::VMESS_AEAD_SECURITY_AES_128_GCM);
    assert!(report.http2_lifecycle);
    assert!(!report.full_tls_lifecycle);
    assert!(report.tls_utls_reality_deferred);
    assert!(report.http2_client_preface_validated);
    assert!(report.http2_settings_validated);
    assert!(report.http2_headers_validated);
    assert!(report.http2_data_validated);
    assert!(report.grpc_hunk_frame_validated);
    assert!(report.cache_key_route_context_validated);
    assert!(report.true_dataplane);
    assert!(response_frames.response_settings_ack_validated);
    assert!(response_frames.response_headers_validated);
    assert!(response_frames.response_data_validated);
    assert!(
        report
            .grpc_cache_key
            .contains("stage134-vmess-grpc-http2-proxy.example:443")
    );
    assert!(
        report
            .grpc_cache_key
            .contains("stage134-vmess-grpc-http2-sni.example")
    );
}
