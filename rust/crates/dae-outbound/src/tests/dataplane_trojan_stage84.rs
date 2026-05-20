use super::*;

#[test]
fn stage84_trojan_go_wss_tcp_dataplane_echoes_payload() {
    let tls_options = shared_transport::TlsUnderlayOptions::new(
        "stage84-trojan-go-wss.example",
        shared_transport::DEFAULT_TLS_ALPN,
    )
    .unwrap();
    let material = shared_transport::tls_loopback_material(&tls_options).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = listener.local_addr().unwrap();
    let server_config = material.server_config.clone();
    let password = "stage84-password";
    let target = "stage84-trojan-go.example:443";
    let ws_host = "stage84-ws-host.example";
    let ws_path = "/trojan-go-ws";
    let payload = b"stage84-trojan-go-wss-ping".to_vec();
    let server_payload = payload.clone();
    let handle = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let conn = rustls::ServerConnection::new(server_config).unwrap();
        let mut tls = rustls::StreamOwned::new(conn, stream);
        let request_head = shared_transport::read_http_head(&mut tls).unwrap();
        let request_head = String::from_utf8(request_head).unwrap();
        assert!(request_head.starts_with(&format!("GET {ws_path} HTTP/1.1\r\n")));
        assert!(request_head.contains(&format!("Host: {ws_host}\r\n")));
        assert!(request_head.contains("Upgrade: websocket\r\n"));
        tls.write_all(
            format!(
                "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: {}\r\n\r\n",
                shared_transport::WS_ACCEPT_SAMPLE
            )
            .as_bytes(),
        )
        .unwrap();
        let request =
            trojan::read_tcp_request_from_websocket_stream(&mut tls, server_payload.len()).unwrap();
        assert_eq!(
            request.request.password_sha224_hex,
            trojan::packet::password_sha224_hex(password)
        );
        assert_eq!(request.request.command, trojan::TrojanNetwork::Tcp.byte());
        assert_eq!(request.request.target, target);
        assert_eq!(request.request.payload, server_payload);
        let response =
            shared_transport::websocket_server_binary_frame(&request.request.payload).unwrap();
        tls.write_all(&response).unwrap();
        (
            tls.conn
                .alpn_protocol()
                .map(|value| String::from_utf8_lossy(value).to_string())
                .unwrap_or_default(),
            request.websocket_request_frame_len,
        )
    });

    let report = trojan::tcp_exchange_over_wss_stream(
        TcpStream::connect(endpoint).unwrap(),
        &material,
        &tls_options,
        &endpoint.to_string(),
        password,
        target,
        ws_host,
        ws_path,
        &payload,
    )
    .unwrap();
    let (server_alpn, server_request_frame_len) = handle.join().unwrap();

    assert!(report.true_dataplane);
    assert!(report.default_go_path);
    assert!(report.trojan_go_wss);
    assert_eq!(report.command, trojan::TrojanNetwork::Tcp.byte());
    assert_eq!(
        report.password_sha224_hex,
        trojan::packet::password_sha224_hex(password)
    );
    assert_eq!(report.target, target);
    assert_eq!(report.ws_host, ws_host);
    assert_eq!(report.ws_path, ws_path);
    assert_eq!(report.echoed_payload, payload);
    assert_eq!(report.selected_alpn, shared_transport::DEFAULT_TLS_ALPN);
    assert_eq!(server_alpn, shared_transport::DEFAULT_TLS_ALPN);
    assert!(report.websocket_request_frame_len > payload.len());
    assert_eq!(
        report.websocket_request_frame_len - 6,
        server_request_frame_len
    );
    assert_eq!(report.websocket_response_frame_len, payload.len());
    assert!(report.tls_handshake_validated);
    assert!(report.certificate_chain_validated);
    assert!(report.server_name_validated);
    assert!(report.alpn_validated);
    assert!(report.websocket_handshake_validated);
    assert!(report.websocket_binary_frame_validated);
}
