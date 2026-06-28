use super::super::*;

pub(super) async fn open_dns_tcp_stream_async(
    upstream: &ResidentDnsUpstream,
    target: SocketAddr,
    mark: u32,
) -> Result<TokioTcpStream, String> {
    let connected = open_direct_tcp_connection_async(target.to_string(), mark, false)
        .await
        .map_err(|err| {
            format!(
                "connect DNS upstream {} {}: {err}",
                upstream.tag, upstream.target.authority
            )
        })?;
    TokioTcpStream::from_std(connected.stream).map_err(|err| format!("adopt DNS TCP stream: {err}"))
}

pub(super) async fn forward_dns_framed_stream_async<S>(
    stream: &mut S,
    payload: &[u8],
) -> Result<Vec<u8>, String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    write_dns_tcp_message_async(stream, payload).await?;
    stream
        .flush()
        .await
        .map_err(|err| format!("flush DNS framed request: {err}"))?;
    read_dns_tcp_message_async(stream).await
}

pub(super) async fn write_dns_tcp_message_async<S>(
    stream: &mut S,
    payload: &[u8],
) -> Result<(), String>
where
    S: AsyncWrite + Unpin,
{
    let len = u16::try_from(payload.len())
        .map_err(|_| format!("DNS request exceeds TCP frame limit: {}", payload.len()))?;
    stream
        .write_all(&len.to_be_bytes())
        .await
        .map_err(|err| format!("write DNS TCP frame length: {err}"))?;
    stream
        .write_all(payload)
        .await
        .map_err(|err| format!("write DNS TCP frame payload: {err}"))
}

pub(super) async fn read_dns_tcp_message_async<S>(stream: &mut S) -> Result<Vec<u8>, String>
where
    S: AsyncRead + Unpin,
{
    let mut len = [0_u8; 2];
    stream
        .read_exact(&mut len)
        .await
        .map_err(|err| format!("read DNS TCP response length: {err}"))?;
    let len = u16::from_be_bytes(len) as usize;
    if len > DNS_TCP_MESSAGE_READ_LIMIT {
        return Err(format!("DNS TCP response length {len} exceeds read limit"));
    }
    let mut response = vec![0_u8; len];
    stream
        .read_exact(&mut response)
        .await
        .map_err(|err| format!("read DNS TCP response payload: {err}"))?;
    Ok(response)
}

pub(super) fn resident_dns_tls_client_config(alpn: &[&str]) -> Result<Arc<ClientConfig>, String> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = alpn
        .iter()
        .map(|protocol| protocol.as_bytes().to_vec())
        .collect();
    Ok(Arc::new(config))
}

pub(super) fn resident_dns_quic_client_config(alpn: &str) -> Result<quinn::ClientConfig, String> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut crypto = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_root_certificates(roots)
        .with_no_client_auth();
    crypto.alpn_protocols = vec![alpn.as_bytes().to_vec()];
    Ok(quinn::ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(crypto)
            .map_err(|err| format!("build DNS QUIC client TLS config: {err}"))?,
    )))
}

pub(super) fn http1_doh_request_bytes(doh: &dae_dns::DohRequest, target: &str) -> Vec<u8> {
    let mut request = Vec::new();
    request.extend_from_slice(doh.method.as_bytes());
    request.extend_from_slice(b" ");
    request.extend_from_slice(target.as_bytes());
    request.extend_from_slice(b" HTTP/1.1\r\nHost: ");
    request.extend_from_slice(doh.host.as_bytes());
    request.extend_from_slice(b"\r\nAccept: ");
    request.extend_from_slice(doh.accept.as_bytes());
    request.extend_from_slice(b"\r\nConnection: close\r\n");
    if !doh.content_type.is_empty() {
        request.extend_from_slice(b"Content-Type: ");
        request.extend_from_slice(doh.content_type.as_bytes());
        request.extend_from_slice(b"\r\n");
    }
    if !doh.body.is_empty() {
        request.extend_from_slice(b"Content-Length: ");
        request.extend_from_slice(doh.body.len().to_string().as_bytes());
        request.extend_from_slice(b"\r\n");
    }
    request.extend_from_slice(b"\r\n");
    request.extend_from_slice(&doh.body);
    request
}

pub(super) fn doh_request_target(path: &str, dns_query: Option<&str>) -> String {
    match dns_query {
        Some(query) if path.contains('?') => format!("{path}&dns={query}"),
        Some(query) => format!("{path}?dns={query}"),
        None => path.to_owned(),
    }
}

pub(super) async fn read_to_end_capped_async<S>(
    stream: &mut S,
    limit: usize,
) -> Result<Vec<u8>, String>
where
    S: AsyncRead + Unpin,
{
    let mut out = Vec::new();
    let mut buf = [0_u8; 8192];
    loop {
        let read = stream
            .read(&mut buf)
            .await
            .map_err(|err| format!("read HTTP response: {err}"))?;
        if read == 0 {
            return Ok(out);
        }
        if out.len().saturating_add(read) > limit {
            return Err(format!("HTTP response exceeds read limit {limit}"));
        }
        out.extend_from_slice(&buf[..read]);
    }
}

pub(in crate::production_runtime_owner::resident_dataplane::dns) fn parse_doh_http_response(
    request: &[u8],
    raw: &[u8],
) -> Result<Vec<u8>, String> {
    let header_end = find_http_header_end(raw).ok_or("DoH response has no header end")?;
    let headers = &raw[..header_end];
    let mut body = raw[header_end + 4..].to_vec();
    let header_text = std::str::from_utf8(headers)
        .map_err(|err| format!("DoH response headers are not UTF-8: {err}"))?;
    let mut lines = header_text.split("\r\n");
    let status = lines
        .next()
        .ok_or_else(|| "DoH response has no status line".to_owned())?;
    let status_code = status
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| format!("DoH response status line is malformed: {status}"))?
        .parse::<u16>()
        .map_err(|err| format!("parse DoH response status code: {err}"))?;
    let mut content_type = Vec::new();
    let mut chunked = false;
    let mut content_length = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim();
        match name.as_str() {
            "content-type" => content_type = value.as_bytes().to_vec(),
            "content-length" => {
                content_length = Some(
                    value
                        .parse::<usize>()
                        .map_err(|err| format!("parse DoH content-length: {err}"))?,
                );
            }
            "transfer-encoding" if value.to_ascii_lowercase().contains("chunked") => chunked = true,
            _ => {}
        }
    }
    validate_doh_response(status_code, status, &content_type).map_err(|err| err.to_string())?;
    if chunked {
        body = decode_http_chunked_body(&body)?;
    } else if let Some(len) = content_length {
        if body.len() < len {
            return Err(format!(
                "DoH response body shorter than content-length: {} < {len}",
                body.len()
            ));
        }
        body.truncate(len);
    }
    restore_dns_response_id(request, &body)
}

fn find_http_header_end(raw: &[u8]) -> Option<usize> {
    raw.windows(4).position(|window| window == b"\r\n\r\n")
}

fn decode_http_chunked_body(raw: &[u8]) -> Result<Vec<u8>, String> {
    let mut offset = 0_usize;
    let mut out = Vec::new();
    loop {
        let line_end = raw[offset..]
            .windows(2)
            .position(|window| window == b"\r\n")
            .map(|index| offset + index)
            .ok_or_else(|| "chunked DoH body has no chunk-size line end".to_owned())?;
        let line = std::str::from_utf8(&raw[offset..line_end])
            .map_err(|err| format!("chunked DoH size line is not UTF-8: {err}"))?;
        let size_hex = line.split(';').next().unwrap_or_default().trim();
        let size = usize::from_str_radix(size_hex, 16)
            .map_err(|err| format!("parse chunked DoH size {size_hex:?}: {err}"))?;
        offset = line_end + 2;
        if size == 0 {
            return Ok(out);
        }
        let end = offset
            .checked_add(size)
            .ok_or_else(|| "chunked DoH body size overflow".to_owned())?;
        if raw.len() < end + 2 {
            return Err("chunked DoH body is truncated".to_owned());
        }
        out.extend_from_slice(&raw[offset..end]);
        if &raw[end..end + 2] != b"\r\n" {
            return Err("chunked DoH chunk missing trailing CRLF".to_owned());
        }
        offset = end + 2;
    }
}

pub(super) fn restore_dns_response_id(request: &[u8], response: &[u8]) -> Result<Vec<u8>, String> {
    if request.len() < 2 {
        return Err("DNS request is too short to restore response id".to_owned());
    }
    let request_id = u16::from_be_bytes([request[0], request[1]]);
    restore_packed_response_request_id(response, request_id)
        .ok_or_else(|| "DNS response is too short to restore request id".to_owned())
}

pub(super) fn dns_response_truncated(response: &[u8]) -> bool {
    response
        .get(2..4)
        .map(|flags| u16::from_be_bytes([flags[0], flags[1]]) & 0x0200 != 0)
        .unwrap_or(false)
}
