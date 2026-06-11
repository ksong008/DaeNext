use std::os::unix::net::UnixStream;
use std::thread;
use std::time::Duration;

use crate::shared_transport::{
    GrpcHttp2LifecycleOptions, GrpcLifecycleOptions, HTTP2_CLIENT_PREFACE, HTTP2_FLAG_END_HEADERS,
    HTTP2_FRAME_DATA, HTTP2_FRAME_HEADERS, HTTP2_FRAME_SETTINGS, http2_frame, read_http2_frame,
};
use crate::trojan::{self, TrojanNetwork};

#[test]
fn case_grpc_http2_frame_helpers_encode_preface_settings_headers_and_data() {
    let frame = http2_frame(HTTP2_FRAME_DATA, 0, 1, b"abc").unwrap();
    assert_eq!(&frame[..3], &[0, 0, 3]);
    assert_eq!(frame[3], HTTP2_FRAME_DATA);
    assert_eq!(frame[4], 0);
    assert_eq!(&frame[5..9], &[0, 0, 0, 1]);
    assert_eq!(&frame[9..], b"abc");

    let settings = http2_frame(HTTP2_FRAME_SETTINGS, 0, 0, &[]).unwrap();
    let headers = http2_frame(HTTP2_FRAME_HEADERS, HTTP2_FLAG_END_HEADERS, 1, b"headers").unwrap();
    let mut stream = std::io::Cursor::new([settings, headers].concat());
    let decoded_settings = read_http2_frame(&mut stream).unwrap();
    assert_eq!(decoded_settings.frame_type, HTTP2_FRAME_SETTINGS);
    assert_eq!(decoded_settings.stream_id, 0);
    let decoded_headers = read_http2_frame(&mut stream).unwrap();
    assert_eq!(decoded_headers.frame_type, HTTP2_FRAME_HEADERS);
    assert_eq!(decoded_headers.flags, HTTP2_FLAG_END_HEADERS);
    assert_eq!(decoded_headers.stream_id, 1);
    assert_eq!(decoded_headers.payload, b"headers");
    assert_eq!(HTTP2_CLIENT_PREFACE.len(), 24);
}

#[test]
fn case_trojan_grpc_http2_lifecycle_roundtrips_trojanc_payload() {
    let password = "fixture-trojan-password";
    let target = "fixture-trojan-grpc-http2.fixture.invalid:443";
    let payload = b"fixture-trojan-grpc-http2-ping".to_vec();
    let grpc = GrpcLifecycleOptions::new(
        "fixture-grpc-proxy.fixture.invalid:443",
        "dae-fixture-grpc",
        "fixture-grpc-sni.fixture.invalid",
        "fixture-dialer",
        true,
        1234,
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
    let expected_password = password.to_owned();
    let handle = thread::spawn(move || {
        let request = trojan::read_tcp_request_from_grpc_http2_stream(
            &mut server,
            &http2,
            expected_payload.len(),
        )
        .unwrap();
        assert_eq!(
            request.request.password_sha224_hex,
            trojan::packet::password_sha224_hex(&expected_password)
        );
        assert_eq!(request.request.command, TrojanNetwork::Tcp.byte());
        assert_eq!(request.request.target, expected_target);
        assert_eq!(request.request.payload, expected_payload);
        assert!(request.http2_frames.http2_client_preface_validated);
        assert!(request.http2_frames.settings_frame_validated);
        assert!(request.http2_frames.headers_frame_validated);
        assert!(request.http2_frames.data_frame_validated);
        trojan::write_grpc_http2_hunk_response(&mut server, &request.request.payload).unwrap()
    });

    let report = trojan::tcp_exchange_over_grpc_http2_stream(
        &mut client,
        "fixture-grpc-proxy.fixture.invalid:443",
        password,
        target,
        &grpc,
        &payload,
    )
    .unwrap();
    let response_frames = handle.join().unwrap();

    assert_eq!(report.target, target);
    assert_eq!(report.echoed_payload, payload);
    assert_eq!(report.command, TrojanNetwork::Tcp.byte());
    assert!(report.http2_tls_lifecycle);
    assert!(!report.outer_tls_wrapped);
    assert!(report.grpc_contains_tls_boundary);
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
            .contains("fixture-grpc-proxy.fixture.invalid:443")
    );
    assert!(
        report
            .grpc_cache_key
            .contains("fixture-grpc-sni.fixture.invalid")
    );
}
