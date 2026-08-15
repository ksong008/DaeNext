use super::*;

#[test]
fn https_proxy_link_normalizes_to_http1() {
    for link in [
        "https://proxy.fixture.invalid:443",
        "https://proxy.fixture.invalid:443?alpn=http%2F1.1",
        "https://proxy.fixture.invalid:443?alpn=h2,http%2F1.1",
    ] {
        let parsed = http_proxy::HttpProxyLink::parse(link).unwrap();
        assert_eq!(parsed.alpn, http_proxy::HTTP_1_1_ALPN, "{link}");
    }
}

#[test]
fn https_proxy_link_rejects_alpn_without_http1() {
    for link in [
        "https://proxy.fixture.invalid:443?alpn=h2",
        "https://proxy.fixture.invalid:443?alpn=",
        "https://proxy.fixture.invalid:443?alpn=h3,h2",
    ] {
        let error = http_proxy::HttpProxyLink::parse(link)
            .unwrap_err()
            .to_string();
        assert!(error.contains("no supported ALPN"), "{link}: {error}");
    }
}

#[test]
fn https_proxy_rejects_negotiated_h2_before_connect_bytes() {
    let tls_options =
        shared_transport::TlsUnderlayOptions::new("fixture-https-proxy.fixture.invalid", "h2")
            .unwrap();
    let material = shared_transport::tls_loopback_material(&tls_options).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = listener.local_addr().unwrap();
    let server_acceptor = material.server_acceptor.clone();
    let handle = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut tls = server_acceptor.accept(stream).unwrap();
        let mut application_byte = [0_u8; 1];
        let application_bytes = tls.read(&mut application_byte).unwrap_or_default();
        let selected = shared_transport::test_support::selected_tls_alpn(tls.ssl());
        (selected, application_bytes)
    });

    let options = http_proxy::HttpConnectOptions::connect("target.fixture.invalid:443");
    let error = http_proxy::connect_exchange_over_tls_stream(
        TcpStream::connect(endpoint).unwrap(),
        &material,
        &tls_options,
        &endpoint.to_string(),
        &options,
        b"payload-must-not-be-written",
    )
    .unwrap_err()
    .to_string();
    let (server_alpn, application_bytes) = handle.join().unwrap();

    assert!(
        error.contains("unsupported application protocol"),
        "{error}"
    );
    assert_eq!(server_alpn, "h2");
    assert_eq!(application_bytes, 0);
}
