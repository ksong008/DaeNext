use super::*;

#[test]
fn case_tls_options_reject_empty_server_name_or_alpn() {
    assert!(shared_transport::TlsUnderlayOptions::new("", "http/1.1").is_err());
    assert!(shared_transport::TlsUnderlayOptions::new("fixture.fixture.invalid", "").is_err());
}

#[test]
fn case_shared_tls_underlay_echoes_payload_and_validates_alpn() {
    let options = shared_transport::TlsUnderlayOptions::new(
        shared_transport::DEFAULT_TLS_SERVER_NAME,
        shared_transport::DEFAULT_TLS_ALPN,
    )
    .unwrap();
    let material = shared_transport::tls_loopback_material(&options).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = listener.local_addr().unwrap();
    let server_acceptor = material.server_acceptor.clone();
    let payload = b"fixture-shared-tls-underlay-ping".to_vec();
    let expected_payload_len = payload.len();
    let handle = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        shared_transport::tls_server_echo(stream, server_acceptor, expected_payload_len).unwrap()
    });

    let report = shared_transport::tls_client_echo_exchange(
        TcpStream::connect(endpoint).unwrap(),
        &material,
        &options,
        &payload,
    )
    .unwrap();
    let server = handle.join().unwrap();

    assert!(report.true_dataplane);
    assert!(report.boringssl_underlay);
    assert_eq!(
        report.server_name,
        shared_transport::DEFAULT_TLS_SERVER_NAME
    );
    assert_eq!(report.alpn_protocol, shared_transport::DEFAULT_TLS_ALPN);
    assert_eq!(report.selected_alpn, shared_transport::DEFAULT_TLS_ALPN);
    assert_eq!(report.echoed_payload, payload);
    assert!(report.tls_handshake_validated);
    assert!(report.certificate_chain_validated);
    assert!(report.server_name_validated);
    assert!(report.alpn_validated);
    assert!(!report.allow_insecure);
    assert!(report.full_utls_deferred);
    assert!(report.reality_deferred);
    assert!(report.tls_fragment_deferred);
    assert!(report.passthrough_udp_deferred);
    assert_eq!(server.selected_alpn, shared_transport::DEFAULT_TLS_ALPN);
    assert_eq!(server.payload_len, expected_payload_len);
    assert_eq!(server.echoed_payload, payload);
    assert!(server.tls_handshake_validated);
    assert!(server.payload_roundtrip_validated);
    assert!(material.certificate_der_len > 0);
}
