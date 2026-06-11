use super::*;

#[test]
fn case_sip003_simple_obfs_http_wraps_shadowsocks_aead_tcp() {
    let cipher = "aes-128-gcm";
    let password = "fixture-password";
    let target = "fixture-sip003-simple-obfs.fixture.invalid:8443";
    let payload = b"fixture-sip003-simple-obfs-http-ping".to_vec();
    let client_salt = hex_decode("202122232425262728292a2b2c2d2e2f");
    let server_salt = hex_decode("606162636465666768696a6b6c6d6e6f");
    let options = shadowsocks::Sip003SimpleObfsHttpOptions::new("front.fixture.invalid", "abc/");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = listener.local_addr().unwrap().to_string();
    let payload_for_server = payload.clone();
    let server_salt_for_thread = server_salt.clone();
    let options_for_thread = options.clone();

    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let request = shadowsocks::read_simple_obfs_http_request(&mut stream).unwrap();
        assert_eq!(request.request_line, "GET /abc/ HTTP/1.1");
        assert_eq!(request.host, options_for_thread.host);
        assert_eq!(request.path, options_for_thread.path);
        assert_eq!(request.content_length, request.inner_payload.len());
        let (accepted_target, accepted_payload) =
            shadowsocks::decode_simple_obfs_http_shadowsocks_request(&request, cipher, password)
                .unwrap();
        assert_eq!(accepted_target, target);
        assert_eq!(accepted_payload, payload_for_server);
        let response = shadowsocks::encode_simple_obfs_http_shadowsocks_response(
            cipher,
            password,
            &server_salt_for_thread,
            &accepted_payload,
        )
        .unwrap();
        stream.write_all(&response).unwrap();
        request
    });

    let report = shadowsocks::simple_obfs_http_shadowsocks_aead_exchange_over_stream(
        &mut TcpStream::connect(&endpoint).unwrap(),
        &endpoint,
        cipher,
        password,
        target,
        &payload,
        shadowsocks::AeadTcpSalts {
            client: &client_salt,
            server: &server_salt,
        },
        &options,
    )
    .unwrap();
    let request = handle.join().unwrap();

    assert_eq!(report.plugin_name, "simple-obfs");
    assert_eq!(report.obfs, "http");
    assert_eq!(report.host, "front.fixture.invalid");
    assert_eq!(report.path, "/abc/");
    assert!(report.request_line_validated);
    assert!(report.host_validated);
    assert!(report.content_length_validated);
    assert!(report.inner.true_dataplane);
    assert_eq!(report.inner.target, target);
    assert_eq!(report.inner.client_salt_len, client_salt.len());
    assert_eq!(report.inner.server_salt_len, server_salt.len());
    assert_eq!(report.inner.payload_len, payload.len());
    assert_eq!(report.inner.echoed_payload, payload);
    assert!(request.inner_payload.len() > payload.len());
}

#[test]
fn case_sip003_simple_obfs_http_options_keep_native_baseline() {
    let defaults = shadowsocks::Sip003SimpleObfsHttpOptions::new("", "");
    assert_eq!(defaults.host, "cloudflare.com");
    assert_eq!(defaults.path, "/");

    let request = shadowsocks::simple_obfs_http_request_with_body(&defaults, b"inner-bytes");
    let request_text = String::from_utf8(request).unwrap();
    assert!(request_text.starts_with("GET / HTTP/1.1\r\n"));
    assert!(request_text.contains("Host: cloudflare.com\r\n"));
    assert!(request_text.contains("Upgrade: websocket\r\n"));
    assert!(request_text.contains("Connection: Upgrade\r\n"));
    assert!(request_text.contains("Content-Length: 11\r\n\r\ninner-bytes"));
}
