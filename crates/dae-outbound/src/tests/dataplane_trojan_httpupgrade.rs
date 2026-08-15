use super::*;

#[test]
fn case_trojan_httpupgrade_tcp_dataplane_echoes_payload() {
    let tls_options = shared_transport::TlsUnderlayOptions::new(
        "fixture-trojan-httpupgrade.fixture.invalid",
        shared_transport::DEFAULT_TLS_ALPN,
    )
    .unwrap();
    let material = shared_transport::tls_loopback_material(&tls_options).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = listener.local_addr().unwrap();
    let server_acceptor = material.server_acceptor.clone();
    let password = "fixture-password";
    let target = "fixture-trojan.fixture.invalid:443";
    let httpupgrade_host = "fixture-upgrade-host.fixture.invalid";
    let httpupgrade_path = "/trojan-go-upgrade";
    let payload = b"fixture-trojan-httpupgrade-ping".to_vec();
    let server_payload = payload.clone();
    let handle = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut tls = server_acceptor.accept(stream).unwrap();
        let request_head = shared_transport::read_http_head(&mut tls).unwrap();
        let request_head = String::from_utf8(request_head).unwrap();
        assert!(request_head.starts_with(&format!("GET {httpupgrade_path} HTTP/1.1\r\n")));
        assert!(request_head.contains(&format!("Host: {httpupgrade_host}\r\n")));
        assert!(request_head.contains("Upgrade: websocket\r\n"));
        tls.write_all(
            b"HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\n",
        )
        .unwrap();
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

    let report = trojan::tcp_exchange_over_httpupgrade_tls_stream(
        TcpStream::connect(endpoint).unwrap(),
        &material,
        &tls_options,
        &endpoint.to_string(),
        password,
        target,
        httpupgrade_host,
        httpupgrade_path,
        &payload,
    )
    .unwrap();
    let server_alpn = handle.join().unwrap();

    assert!(report.true_dataplane);
    assert!(report.trojan_httpupgrade);
    assert_eq!(report.command, trojan::TrojanNetwork::Tcp.byte());
    assert_eq!(
        report.password_sha224_hex,
        trojan::packet::password_sha224_hex(password)
    );
    assert_eq!(report.target, target);
    assert_eq!(report.httpupgrade_host, httpupgrade_host);
    assert_eq!(report.httpupgrade_path, httpupgrade_path);
    assert_eq!(report.echoed_payload, payload);
    assert_eq!(report.selected_alpn, shared_transport::DEFAULT_TLS_ALPN);
    assert_eq!(server_alpn, shared_transport::DEFAULT_TLS_ALPN);
    assert!(report.httpupgrade_request_len > httpupgrade_path.len());
    assert!(report.tls_handshake_validated);
    assert!(report.certificate_chain_validated);
    assert!(report.server_name_validated);
    assert!(report.alpn_validated);
    assert!(report.httpupgrade_handshake_validated);
}
