use super::*;

#[derive(Debug, Default)]
pub(super) struct HttpsProxyServerSummary {
    pub(super) accepted: usize,
    pub(super) tls_handshake_count: usize,
    pub(super) alpn_validated_count: usize,
    pub(super) connect_count: usize,
    pub(super) auth_count: usize,
    pub(super) payload_roundtrip_count: usize,
    pub(super) selected_alpns: Vec<String>,
    pub(super) connect_authorities: Vec<String>,
    pub(super) host_headers: Vec<String>,
    pub(super) payload_ascii: Vec<String>,
    pub(super) response_ascii: Vec<String>,
}

pub(super) fn spawn_https_proxy(
    opts: &Stage82Options,
    material: &shared_transport::TlsLoopbackMaterial,
) -> Result<
    (
        SocketAddrV4,
        TcpLoopbackListenerReport,
        thread::JoinHandle<Result<HttpsProxyServerSummary, String>>,
    ),
    String,
> {
    let (listener, listener_report) = bind_loopback_tcp_listener(opts.mptcp)
        .map_err(|err| format!("stage82 bind loopback https proxy failed: {err}"))?;
    let local_addr = listener
        .local_addr()
        .map_err(|err| format!("stage82 https proxy local_addr failed: {err}"))?;
    let proxy_addr = match local_addr {
        SocketAddr::V4(addr) => addr,
        SocketAddr::V6(addr) => {
            return Err(format!("stage82 https proxy listener is not IPv4: {addr}"));
        }
    };
    listener
        .set_nonblocking(true)
        .map_err(|err| format!("stage82 https proxy nonblocking failed: {err}"))?;

    let iterations = opts.benchmark_iters;
    let expected_authority = if opts.host_override.is_empty() {
        opts.target.clone()
    } else {
        opts.host_override.clone()
    };
    let expected_auth = http_request::basic_auth_header(&opts.username, &opts.password)
        .ok_or_else(|| "stage82 expected basic auth header is empty".to_owned())?;
    let expected_alpn = opts.alpn_protocol.clone();
    let payload = opts.payload.clone();
    let response = opts.response.clone();
    let timeout = opts.timeout;
    let server_config = material.server_config.clone();
    let handle = thread::spawn(move || {
        accept_https_proxy_connects(
            listener,
            iterations,
            &expected_authority,
            &expected_auth,
            &expected_alpn,
            &payload,
            &response,
            timeout,
            server_config,
        )
    });
    Ok((proxy_addr, listener_report, handle))
}

fn accept_https_proxy_connects(
    listener: TcpListener,
    iterations: usize,
    expected_authority: &str,
    expected_auth: &str,
    expected_alpn: &str,
    payload: &[u8],
    response: &[u8],
    timeout: Duration,
    server_config: std::sync::Arc<rustls::ServerConfig>,
) -> Result<HttpsProxyServerSummary, String> {
    let mut summary = HttpsProxyServerSummary::default();
    let deadline = Instant::now() + timeout.saturating_mul(iterations as u32 + 2);
    while summary.accepted < iterations {
        match listener.accept() {
            Ok((stream, _)) => {
                stream
                    .set_read_timeout(Some(timeout))
                    .map_err(|err| format!("stage82 server set read timeout failed: {err}"))?;
                stream
                    .set_write_timeout(Some(timeout))
                    .map_err(|err| format!("stage82 server set write timeout failed: {err}"))?;
                let conn = rustls::ServerConnection::new(server_config.clone())
                    .map_err(|err| format!("stage82 server tls accept failed: {err}"))?;
                let mut tls = rustls::StreamOwned::new(conn, stream);
                handle_https_connect(
                    &mut tls,
                    expected_authority,
                    expected_auth,
                    payload,
                    response,
                    &mut summary,
                )?;
                let selected_alpn = tls
                    .conn
                    .alpn_protocol()
                    .map(|value| String::from_utf8_lossy(value).to_string())
                    .unwrap_or_default();
                if selected_alpn == expected_alpn {
                    summary.alpn_validated_count += 1;
                }
                summary.selected_alpns.push(selected_alpn);
                summary.tls_handshake_count += 1;
                summary.accepted += 1;
            }
            Err(err) if err.kind() == ErrorKind::WouldBlock && Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(5));
            }
            Err(err) if err.kind() == ErrorKind::WouldBlock => {
                return Err(format!(
                    "stage82 https proxy timed out after accepting {} of {} connections",
                    summary.accepted, iterations
                ));
            }
            Err(err) => return Err(format!("stage82 https proxy accept failed: {err}")),
        }
    }
    Ok(summary)
}

fn handle_https_connect<S>(
    stream: &mut S,
    expected_authority: &str,
    expected_auth: &str,
    payload: &[u8],
    response: &[u8],
    summary: &mut HttpsProxyServerSummary,
) -> Result<(), String>
where
    S: Read + Write,
{
    let head = read_http_head(stream)?;
    let text = std::str::from_utf8(&head)
        .map_err(|err| format!("stage82 http request is not utf8: {err}"))?;
    let (first_line, headers) = parse_http_head(text)?;
    let mut first = first_line.split_whitespace();
    let method = first.next().unwrap_or_default();
    let authority = first.next().unwrap_or_default();
    let version = first.next().unwrap_or_default();
    if method != "CONNECT" || authority != expected_authority || version != "HTTP/1.1" {
        return Err(format!("stage82 bad CONNECT line: {first_line}"));
    }
    let host = header_value(&headers, "host").unwrap_or_default();
    if host != expected_authority {
        return Err(format!(
            "stage82 host header mismatch: got {host}, want {expected_authority}"
        ));
    }
    let auth = header_value(&headers, "proxy-authorization").unwrap_or_default();
    if auth != expected_auth {
        return Err(format!(
            "stage82 proxy auth mismatch: got {auth}, want {expected_auth}"
        ));
    }
    summary.connect_count += 1;
    summary.auth_count += 1;
    summary.connect_authorities.push(authority.to_owned());
    summary.host_headers.push(host);

    stream
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .map_err(|err| format!("stage82 write 200 failed: {err}"))?;
    let mut got_payload = vec![0_u8; payload.len()];
    stream
        .read_exact(&mut got_payload)
        .map_err(|err| format!("stage82 payload read failed: {err}"))?;
    if got_payload != payload {
        return Err("stage82 https proxy payload mismatch".to_owned());
    }
    stream
        .write_all(response)
        .map_err(|err| format!("stage82 payload response failed: {err}"))?;
    summary.payload_roundtrip_count += 1;
    summary
        .payload_ascii
        .push(String::from_utf8_lossy(&got_payload).to_string());
    summary
        .response_ascii
        .push(String::from_utf8_lossy(response).to_string());
    Ok(())
}

fn read_http_head(stream: &mut impl Read) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let mut buf = [0_u8; 512];
    loop {
        let n = stream
            .read(&mut buf)
            .map_err(|err| format!("stage82 read http head failed: {err}"))?;
        if n == 0 {
            return Err("stage82 incomplete http request head".to_owned());
        }
        out.extend_from_slice(&buf[..n]);
        if out.windows(4).any(|window| window == b"\r\n\r\n") {
            return Ok(out);
        }
        if out.len() > 8192 {
            return Err("stage82 http request head too large".to_owned());
        }
    }
}

fn parse_http_head(text: &str) -> Result<(&str, Vec<(String, String)>), String> {
    let (head, _) = text
        .split_once("\r\n\r\n")
        .ok_or_else(|| "stage82 missing http header terminator".to_owned())?;
    let mut lines = head.split("\r\n");
    let first = lines
        .next()
        .ok_or_else(|| "stage82 missing request line".to_owned())?;
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
