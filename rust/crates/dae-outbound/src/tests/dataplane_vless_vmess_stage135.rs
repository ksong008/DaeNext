use super::*;

#[test]
fn stage135_vless_wss_tls_lifecycle_roundtrips_tcp_payload() {
    let key = vless::password_to_key("7c12c745-63a5-433d-9e60-022e469b5bd4").unwrap();
    let target = "stage135-vless-wss.example:443";
    let ws_host = "stage135-vless-wss-host.example";
    let ws_path = "/dae-stage135-vless-wss";
    let payload = b"stage135-vless-wss-ping".to_vec();
    let tls_options = stage135_tls_options("stage135-vless-wss-tls.example");
    let material = shared_transport::tls_loopback_material(&tls_options).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = listener.local_addr().unwrap();
    let server_config = material.server_config.clone();
    let server_payload = payload.clone();
    let handle = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let conn = rustls::ServerConnection::new(server_config).unwrap();
        let mut tls = rustls::StreamOwned::new(conn, stream);
        validate_stage135_ws_upgrade(&mut tls, ws_host, ws_path);
        let request =
            vless::read_tcp_request_from_websocket_stream(&mut tls, server_payload.len()).unwrap();
        assert_eq!(request.request.key, key);
        assert_eq!(request.request.command, vmess::VMessNetwork::Tcp.byte());
        assert_eq!(request.request.target, target);
        assert_eq!(request.request.payload, server_payload);
        let response = vless::response_payload_bytes(&request.request.payload);
        let response = shared_transport::websocket_server_binary_frame(&response).unwrap();
        tls.write_all(&response).unwrap();
        selected_alpn(tls.conn.alpn_protocol())
    });

    let report = vless::tcp_exchange_over_wss_tls_stream(
        TcpStream::connect(endpoint).unwrap(),
        &material,
        &tls_options,
        &endpoint.to_string(),
        &key,
        target,
        ws_host,
        ws_path,
        &payload,
    )
    .unwrap();
    let server_alpn = handle.join().unwrap();

    assert!(report.true_dataplane);
    assert!(report.rustls_tls_lifecycle);
    assert!(report.full_utls_deferred);
    assert!(report.reality_deferred);
    assert!(report.tls_fragment_deferred);
    assert_eq!(report.command, vmess::VMessNetwork::Tcp.byte());
    assert_eq!(report.target, target);
    assert_eq!(report.ws_host, ws_host);
    assert_eq!(report.ws_path, ws_path);
    assert_eq!(report.echoed_payload, payload);
    assert_eq!(report.selected_alpn, shared_transport::DEFAULT_TLS_ALPN);
    assert_eq!(server_alpn, shared_transport::DEFAULT_TLS_ALPN);
    assert!(report.tls_handshake_validated);
    assert!(report.certificate_chain_validated);
    assert!(report.server_name_validated);
    assert!(report.alpn_validated);
    assert!(report.websocket_handshake_validated);
    assert!(report.websocket_binary_frame_validated);
}

#[test]
fn stage135_vless_https_httpupgrade_tls_lifecycle_roundtrips_tcp_payload() {
    let key = vless::password_to_key("7c12c745-63a5-433d-9e60-022e469b5bd4").unwrap();
    let target = "stage135-vless-httpupgrade.example:443";
    let host = "stage135-vless-httpupgrade-host.example";
    let path = "/dae-stage135-vless-httpupgrade";
    let payload = b"stage135-vless-httpupgrade-ping".to_vec();
    let tls_options = stage135_tls_options("stage135-vless-httpupgrade-tls.example");
    let material = shared_transport::tls_loopback_material(&tls_options).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = listener.local_addr().unwrap();
    let server_config = material.server_config.clone();
    let server_payload = payload.clone();
    let handle = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let conn = rustls::ServerConnection::new(server_config).unwrap();
        let mut tls = rustls::StreamOwned::new(conn, stream);
        validate_stage135_httpupgrade(&mut tls, host, path);
        let request = vless::read_tcp_request_from_stream(&mut tls, server_payload.len()).unwrap();
        assert_eq!(request.key, key);
        assert_eq!(request.command, vmess::VMessNetwork::Tcp.byte());
        assert_eq!(request.target, target);
        assert_eq!(request.payload, server_payload);
        let response = vless::response_payload_bytes(&request.payload);
        tls.write_all(&response).unwrap();
        selected_alpn(tls.conn.alpn_protocol())
    });

    let report = vless::tcp_exchange_over_https_httpupgrade_tls_stream(
        TcpStream::connect(endpoint).unwrap(),
        &material,
        &tls_options,
        &endpoint.to_string(),
        &key,
        target,
        host,
        path,
        &payload,
    )
    .unwrap();
    let server_alpn = handle.join().unwrap();

    assert!(report.true_dataplane);
    assert!(report.rustls_tls_lifecycle);
    assert_eq!(report.command, vmess::VMessNetwork::Tcp.byte());
    assert_eq!(report.target, target);
    assert_eq!(report.httpupgrade_host, host);
    assert_eq!(report.httpupgrade_path, path);
    assert_eq!(report.echoed_payload, payload);
    assert_eq!(report.selected_alpn, shared_transport::DEFAULT_TLS_ALPN);
    assert_eq!(server_alpn, shared_transport::DEFAULT_TLS_ALPN);
    assert!(report.httpupgrade_handshake_validated);
    assert!(report.alpn_validated);
}

#[test]
fn stage135_vmess_wss_tls_lifecycle_roundtrips_aead_tcp_payload() {
    let uuid = "7c12c745-63a5-433d-9e60-022e469b5bd4";
    let target = "stage135-vmess-wss.example:443";
    let ws_host = "stage135-vmess-wss-host.example";
    let ws_path = "/dae-stage135-vmess-wss";
    let payload = b"stage135-vmess-wss-ping".to_vec();
    let tls_options = stage135_tls_options("stage135-vmess-wss-tls.example");
    let material = shared_transport::tls_loopback_material(&tls_options).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = listener.local_addr().unwrap();
    let server_config = material.server_config.clone();
    let server_payload = payload.clone();
    let server_uuid = uuid.to_owned();
    let handle = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let conn = rustls::ServerConnection::new(server_config).unwrap();
        let mut tls = rustls::StreamOwned::new(conn, stream);
        validate_stage135_ws_upgrade(&mut tls, ws_host, ws_path);
        let request =
            vmess::read_aead_tcp_request_from_websocket_stream(&mut tls, &server_uuid).unwrap();
        assert_eq!(request.request.command, vmess::VMessNetwork::Tcp.byte());
        assert_eq!(request.request.target, target);
        assert_eq!(request.request.payload, server_payload);
        let response =
            vmess::aead_tcp_response_packet(&request.request, &request.request.payload).unwrap();
        let response = shared_transport::websocket_server_binary_frame(&response).unwrap();
        tls.write_all(&response).unwrap();
        selected_alpn(tls.conn.alpn_protocol())
    });

    let report = vmess::aead_tcp_exchange_over_wss_tls_stream(
        TcpStream::connect(endpoint).unwrap(),
        &material,
        &tls_options,
        &endpoint.to_string(),
        uuid,
        target,
        ws_host,
        ws_path,
        &payload,
    )
    .unwrap();
    let server_alpn = handle.join().unwrap();

    assert!(report.true_dataplane);
    assert!(report.rustls_tls_lifecycle);
    assert!(report.full_utls_deferred);
    assert!(report.reality_rejected_for_vmess);
    assert_eq!(report.security, vmess::VMESS_AEAD_SECURITY_AES_128_GCM);
    assert_eq!(report.target, target);
    assert_eq!(report.ws_host, ws_host);
    assert_eq!(report.ws_path, ws_path);
    assert_eq!(report.echoed_payload, payload);
    assert_eq!(report.selected_alpn, shared_transport::DEFAULT_TLS_ALPN);
    assert_eq!(server_alpn, shared_transport::DEFAULT_TLS_ALPN);
    assert!(report.websocket_handshake_validated);
    assert!(report.websocket_binary_frame_validated);
}

#[test]
fn stage135_vmess_https_httpupgrade_tls_lifecycle_roundtrips_aead_tcp_payload() {
    let uuid = "7c12c745-63a5-433d-9e60-022e469b5bd4";
    let target = "stage135-vmess-httpupgrade.example:443";
    let host = "stage135-vmess-httpupgrade-host.example";
    let path = "/dae-stage135-vmess-httpupgrade";
    let payload = b"stage135-vmess-httpupgrade-ping".to_vec();
    let tls_options = stage135_tls_options("stage135-vmess-httpupgrade-tls.example");
    let material = shared_transport::tls_loopback_material(&tls_options).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = listener.local_addr().unwrap();
    let server_config = material.server_config.clone();
    let server_payload = payload.clone();
    let server_uuid = uuid.to_owned();
    let handle = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let conn = rustls::ServerConnection::new(server_config).unwrap();
        let mut tls = rustls::StreamOwned::new(conn, stream);
        validate_stage135_httpupgrade(&mut tls, host, path);
        let request = vmess::read_aead_tcp_request_from_stream(&mut tls, &server_uuid).unwrap();
        assert_eq!(request.command, vmess::VMessNetwork::Tcp.byte());
        assert_eq!(request.target, target);
        assert_eq!(request.payload, server_payload);
        let response = vmess::aead_tcp_response_packet(&request, &request.payload).unwrap();
        tls.write_all(&response).unwrap();
        selected_alpn(tls.conn.alpn_protocol())
    });

    let report = vmess::aead_tcp_exchange_over_https_httpupgrade_tls_stream(
        TcpStream::connect(endpoint).unwrap(),
        &material,
        &tls_options,
        &endpoint.to_string(),
        uuid,
        target,
        host,
        path,
        &payload,
    )
    .unwrap();
    let server_alpn = handle.join().unwrap();

    assert!(report.true_dataplane);
    assert!(report.rustls_tls_lifecycle);
    assert_eq!(report.security, vmess::VMESS_AEAD_SECURITY_AES_128_GCM);
    assert_eq!(report.target, target);
    assert_eq!(report.httpupgrade_host, host);
    assert_eq!(report.httpupgrade_path, path);
    assert_eq!(report.echoed_payload, payload);
    assert_eq!(report.selected_alpn, shared_transport::DEFAULT_TLS_ALPN);
    assert_eq!(server_alpn, shared_transport::DEFAULT_TLS_ALPN);
    assert!(report.httpupgrade_handshake_validated);
    assert!(report.alpn_validated);
}

fn stage135_tls_options(server_name: &str) -> shared_transport::TlsUnderlayOptions {
    shared_transport::TlsUnderlayOptions::new(server_name, shared_transport::DEFAULT_TLS_ALPN)
        .unwrap()
}

fn validate_stage135_ws_upgrade<S>(stream: &mut S, host: &str, path: &str)
where
    S: Read + Write,
{
    let request_head = shared_transport::read_http_head(stream).unwrap();
    let request_head = String::from_utf8(request_head).unwrap();
    assert!(request_head.starts_with(&format!("GET {path} HTTP/1.1\r\n")));
    assert!(request_head.contains(&format!("Host: {host}\r\n")));
    assert!(request_head.contains("Upgrade: websocket\r\n"));
    stream
        .write_all(
            format!(
                "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: {}\r\n\r\n",
                shared_transport::WS_ACCEPT_SAMPLE
            )
            .as_bytes(),
        )
        .unwrap();
}

fn validate_stage135_httpupgrade<S>(stream: &mut S, host: &str, path: &str)
where
    S: Read + Write,
{
    let request_head = shared_transport::read_http_head(stream).unwrap();
    let request_head = String::from_utf8(request_head).unwrap();
    assert!(request_head.starts_with(&format!("GET {path} HTTP/1.1\r\n")));
    assert!(request_head.contains(&format!("Host: {host}\r\n")));
    assert!(request_head.contains("Connection: upgrade\r\n"));
    assert!(request_head.contains("Upgrade: websocket\r\n"));
    stream
        .write_all(
            b"HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\n",
        )
        .unwrap();
}

fn selected_alpn(protocol: Option<&[u8]>) -> String {
    protocol
        .map(|value| String::from_utf8_lossy(value).to_string())
        .unwrap_or_default()
}
