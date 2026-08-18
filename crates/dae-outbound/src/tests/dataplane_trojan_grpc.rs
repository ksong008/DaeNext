use super::*;

#[test]
fn case_trojan_grpc_hunk_does_not_wrap_outer_tls_and_echoes_payload() {
    let password = "fixture-password";
    let target = "fixture-trojan-grpc.fixture.invalid:443";
    let service_name = "dae-fixture-grpc";
    let payload = b"fixture-trojan-grpc-ping".to_vec();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = listener.local_addr().unwrap().to_string();
    let server_payload = payload.clone();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let expected_preface = shared_transport::grpc_stream_preface(service_name).unwrap();
        let mut preface = vec![0_u8; expected_preface.len()];
        stream.read_exact(&mut preface).unwrap();
        assert_eq!(preface, expected_preface);
        let request =
            trojan::read_tcp_request_from_grpc_hunk_stream(&mut stream, server_payload.len())
                .unwrap();
        assert_eq!(
            request.request.password_sha224_hex,
            trojan::packet::password_sha224_hex(password)
        );
        assert_eq!(request.request.command, trojan::TrojanNetwork::Tcp.byte());
        assert_eq!(request.request.target, target);
        assert_eq!(request.request.payload, server_payload);
        let response = shared_transport::grpc_hunk_frame(&request.request.payload).unwrap();
        stream.write_all(&response).unwrap();
        request
    });
    let grpc_options = shared_transport::GrpcLifecycleOptions::new(
        &endpoint,
        service_name,
        "fixture-trojan-grpc-sni.fixture.invalid",
        "fixture-trojan-grpc-dialer",
        true,
        1234,
        true,
    );
    let without_mptcp = shared_transport::GrpcLifecycleOptions {
        mptcp: false,
        ..grpc_options.clone()
    };

    let report = trojan::tcp_exchange_over_grpc_hunk_stream(
        &mut TcpStream::connect(&endpoint).unwrap(),
        &endpoint,
        password,
        target,
        &grpc_options,
        &payload,
    )
    .unwrap();
    let accepted = handle.join().unwrap();

    assert!(report.true_dataplane);
    assert!(report.trojan_grpc);
    assert!(!report.outer_tls_wrapped);
    assert!(report.grpc_contains_tls_boundary);
    assert!(!report.full_grpc_http2_stack);
    assert_eq!(report.command, trojan::TrojanNetwork::Tcp.byte());
    assert_eq!(
        report.password_sha224_hex,
        trojan::packet::password_sha224_hex(password)
    );
    assert_eq!(report.target, target);
    assert_eq!(report.grpc_service_name, service_name);
    assert_eq!(report.grpc_cache_key, grpc_options.cache_key());
    assert_ne!(report.grpc_cache_key, without_mptcp.cache_key());
    assert_eq!(report.payload_len, payload.len());
    assert_eq!(report.echoed_payload, payload);
    assert!(report.grpc_stream_preface_validated);
    assert!(report.grpc_hunk_frame_validated);
    assert!(report.cache_key_route_context_validated);
    assert!(report.grpc_preface_len > service_name.len());
    assert!(report.grpc_request_hunk_len > report.request_header_len);
    assert!(report.grpc_response_hunk_len > payload.len());
    assert_eq!(accepted.request.payload, payload);
    assert!(accepted.grpc_request_hunk_len > accepted.request.header_len);
}

#[test]
fn case_trojan_grpc_service_name_matches_native_fallbacks() {
    assert_eq!(
        trojan::trojan_grpc_service_name("explicit-service", "path-service"),
        "explicit-service"
    );
    assert_eq!(
        trojan::trojan_grpc_service_name("", "path-service"),
        "path-service"
    );
    assert_eq!(
        trojan::trojan_grpc_service_name("", ""),
        trojan::TROJAN_GRPC_DEFAULT_SERVICE_NAME
    );
}
