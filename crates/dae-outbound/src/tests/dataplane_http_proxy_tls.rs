use super::*;

#[test]
fn case_https_proxy_tls_connect_dataplane_echoes_payload() {
    let tls_options = shared_transport::TlsUnderlayOptions::new(
        "fixture-https-proxy.fixture.invalid",
        shared_transport::DEFAULT_TLS_ALPN,
    )
    .unwrap();
    let material = shared_transport::tls_loopback_material(&tls_options).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = listener.local_addr().unwrap();
    let server_acceptor = material.server_acceptor.clone();
    let target = "fixture-target.fixture.invalid:443";
    let authority = "front.fixture.fixture.invalid:443";
    let expected_auth = http_proxy::request::basic_auth_header("user", "pass").unwrap();
    let payload = b"fixture-https-proxy-tls-ping".to_vec();
    let server_payload = payload.clone();
    let handle = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut tls = server_acceptor.accept(stream).unwrap();
        handle_https_connect_proxy(&mut tls, authority, &expected_auth, &server_payload).unwrap();
        shared_transport::test_support::selected_tls_alpn(tls.ssl())
    });
    let mut options = http_proxy::HttpConnectOptions::connect(target);
    options.host_override = authority.to_owned();
    options.username = "user".to_owned();
    options.password = "pass".to_owned();

    let report = http_proxy::connect_exchange_over_tls_stream(
        TcpStream::connect(endpoint).unwrap(),
        &material,
        &tls_options,
        &endpoint.to_string(),
        &options,
        &payload,
    )
    .unwrap();
    let server_alpn = handle.join().unwrap();

    assert!(report.true_dataplane);
    assert!(report.https_proxy_tls_underlay);
    assert_eq!(report.status, 200);
    assert_eq!(report.target, target);
    assert_eq!(report.echoed_payload, payload);
    assert_eq!(report.selected_alpn, shared_transport::DEFAULT_TLS_ALPN);
    assert_eq!(server_alpn, shared_transport::DEFAULT_TLS_ALPN);
    assert!(report.tls_handshake_validated);
    assert!(report.certificate_chain_validated);
    assert!(report.server_name_validated);
    assert!(report.alpn_validated);
}

fn handle_https_connect_proxy(
    stream: &mut impl ReadWrite,
    expected_authority: &str,
    expected_auth: &str,
    payload: &[u8],
) -> Result<(), String> {
    let head = read_http_head(stream)?;
    let text = std::str::from_utf8(&head)
        .map_err(|err| format!("fixture http request is not utf8: {err}"))?;
    let (first_line, headers) = parse_http_head(text)?;
    let mut first = first_line.split_whitespace();
    let method = first.next().unwrap_or_default();
    let authority = first.next().unwrap_or_default();
    let version = first.next().unwrap_or_default();
    if method != "CONNECT" || authority != expected_authority || version != "HTTP/1.1" {
        return Err(format!("fixture bad CONNECT line: {first_line}"));
    }
    let host = header_value(&headers, "host").unwrap_or_default();
    if host != expected_authority {
        return Err(format!(
            "fixture host header mismatch: got {host}, want {expected_authority}"
        ));
    }
    let auth = header_value(&headers, "proxy-authorization").unwrap_or_default();
    if auth != expected_auth {
        return Err(format!(
            "fixture proxy auth mismatch: got {auth}, want {expected_auth}"
        ));
    }
    stream
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .map_err(|err| format!("fixture write 200 failed: {err}"))?;
    let mut got_payload = vec![0_u8; payload.len()];
    stream
        .read_exact(&mut got_payload)
        .map_err(|err| format!("fixture payload read failed: {err}"))?;
    if got_payload != payload {
        return Err("fixture https proxy payload mismatch".to_owned());
    }
    stream
        .write_all(payload)
        .map_err(|err| format!("fixture payload response failed: {err}"))?;
    Ok(())
}

trait ReadWrite: std::io::Read + std::io::Write {}

impl<T> ReadWrite for T where T: std::io::Read + std::io::Write {}

fn read_http_head(stream: &mut impl std::io::Read) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let mut buf = [0_u8; 512];
    loop {
        let n = stream
            .read(&mut buf)
            .map_err(|err| format!("fixture read http head failed: {err}"))?;
        if n == 0 {
            return Err("fixture incomplete http request head".to_owned());
        }
        out.extend_from_slice(&buf[..n]);
        if out.windows(4).any(|window| window == b"\r\n\r\n") {
            return Ok(out);
        }
        if out.len() > 8192 {
            return Err("fixture http request head too large".to_owned());
        }
    }
}

type HttpHead<'a> = (&'a str, Vec<(String, String)>);

fn parse_http_head(text: &str) -> Result<HttpHead<'_>, String> {
    let (head, _) = text
        .split_once("\r\n\r\n")
        .ok_or_else(|| "fixture missing http header terminator".to_owned())?;
    let mut lines = head.split("\r\n");
    let first = lines
        .next()
        .ok_or_else(|| "fixture missing request line".to_owned())?;
    let headers = lines
        .filter_map(|line| {
            line.split_once(':')
                .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_owned()))
        })
        .collect::<Vec<_>>();
    Ok((first, headers))
}

fn header_value(headers: &[(String, String)], name: &str) -> Option<String> {
    headers
        .iter()
        .find(|(header, _)| header == name)
        .map(|(_, value)| value.clone())
}
