use super::*;

#[test]
fn case_trojan_tls_tcp_dataplane_echoes_payload() {
    let tls_options = shared_transport::TlsUnderlayOptions::new(
        "fixture-trojan-tls.fixture.invalid",
        shared_transport::DEFAULT_TLS_ALPN,
    )
    .unwrap();
    let material = shared_transport::tls_loopback_material(&tls_options).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = listener.local_addr().unwrap();
    let server_acceptor = material.server_acceptor.clone();
    let password = "fixture-password";
    let target = "fixture-trojan.fixture.invalid:443";
    let payload = b"fixture-trojan-tls-ping".to_vec();
    let server_payload = payload.clone();
    let handle = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut tls = server_acceptor.accept(stream).unwrap();
        let request = trojan::read_tcp_request_from_stream(&mut tls, server_payload.len()).unwrap();
        assert_eq!(
            request.password_sha224_hex,
            trojan::packet::password_sha224_hex(password)
        );
        assert_eq!(request.command, trojan::TrojanNetwork::Tcp.byte());
        assert_eq!(request.target, target);
        assert_eq!(request.payload, server_payload);
        tls.write_all(&request.payload).unwrap();
        shared_transport::test_support::selected_tls_alpn(tls.ssl())
    });

    let report = trojan::tcp_exchange_over_tls_stream(
        TcpStream::connect(endpoint).unwrap(),
        &material,
        &tls_options,
        &endpoint.to_string(),
        password,
        target,
        &payload,
    )
    .unwrap();
    let server_alpn = handle.join().unwrap();

    assert!(report.true_dataplane);
    assert!(report.trojan_tls_underlay);
    assert_eq!(report.command, trojan::TrojanNetwork::Tcp.byte());
    assert_eq!(
        report.password_sha224_hex,
        trojan::packet::password_sha224_hex(password)
    );
    assert_eq!(report.target, target);
    assert_eq!(report.echoed_payload, payload);
    assert_eq!(report.selected_alpn, shared_transport::DEFAULT_TLS_ALPN);
    assert_eq!(server_alpn, shared_transport::DEFAULT_TLS_ALPN);
    assert!(report.tls_handshake_validated);
    assert!(report.certificate_chain_validated);
    assert!(report.server_name_validated);
    assert!(report.alpn_validated);
}
