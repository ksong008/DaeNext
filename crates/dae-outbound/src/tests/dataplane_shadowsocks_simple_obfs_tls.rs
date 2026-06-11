use super::*;

#[test]
fn case_sip003_simple_obfs_tls_wraps_shadowsocks_aead_tcp() {
    let cipher = "aes-128-gcm";
    let password = "fixture-password";
    let target = "fixture-sip003-simple-obfs-tls.fixture.invalid:8443";
    let payload = b"fixture-sip003-simple-obfs-tls-ping".to_vec();
    let client_salt = hex_decode("303132333435363738393a3b3c3d3e3f");
    let server_salt = hex_decode("707172737475767778797a7b7c7d7e7f");
    let options = shadowsocks::Sip003SimpleObfsTlsOptions::new("tls-front.fixture.invalid");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = listener.local_addr().unwrap().to_string();
    let payload_for_server = payload.clone();
    let server_salt_for_thread = server_salt.clone();
    let options_for_thread = options.clone();

    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let request = shadowsocks::read_simple_obfs_tls_client_hello(&mut stream).unwrap();
        assert_eq!(request.record_type, 0x16);
        assert_eq!(request.record_version, [0x03, 0x01]);
        assert_eq!(request.handshake_version, [0x03, 0x03]);
        assert_eq!(request.server_name, options_for_thread.server_name);
        assert_eq!(request.session_ticket_len, request.inner_payload.len());
        let (accepted_target, accepted_payload) =
            shadowsocks::decode_simple_obfs_tls_shadowsocks_request(&request, cipher, password)
                .unwrap();
        assert_eq!(accepted_target, target);
        assert_eq!(accepted_payload, payload_for_server);
        let response = shadowsocks::encode_simple_obfs_tls_shadowsocks_response(
            cipher,
            password,
            &server_salt_for_thread,
            &accepted_payload,
        )
        .unwrap();
        stream.write_all(&response).unwrap();
        request
    });

    let report = shadowsocks::simple_obfs_tls_shadowsocks_aead_exchange_over_stream(
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
    assert_eq!(report.obfs, "tls");
    assert_eq!(report.server_name, "tls-front.fixture.invalid");
    assert!(report.client_hello_validated);
    assert!(report.sni_validated);
    assert!(report.session_ticket_validated);
    assert!(report.inner.true_dataplane);
    assert_eq!(report.inner.target, target);
    assert_eq!(report.inner.client_salt_len, client_salt.len());
    assert_eq!(report.inner.server_salt_len, server_salt.len());
    assert_eq!(report.inner.payload_len, payload.len());
    assert_eq!(report.inner.echoed_payload, payload);
    assert!(request.client_hello_len > request.inner_payload.len());
}

#[test]
fn case_sip003_simple_obfs_tls_options_keep_native_host_baseline() {
    let defaults = shadowsocks::Sip003SimpleObfsTlsOptions::new("");
    assert_eq!(defaults.server_name, "cloudflare.com");

    let hello =
        shadowsocks::simple_obfs_tls_client_hello_with_body(&defaults, b"inner-bytes").unwrap();
    assert_eq!(hello[0], 0x16);
    assert_eq!(&hello[1..3], &[0x03, 0x01]);
    assert!(
        hello
            .windows("cloudflare.com".len())
            .any(|window| { window == "cloudflare.com".as_bytes() })
    );
    assert!(
        hello
            .windows("inner-bytes".len())
            .any(|window| { window == b"inner-bytes" })
    );
}
