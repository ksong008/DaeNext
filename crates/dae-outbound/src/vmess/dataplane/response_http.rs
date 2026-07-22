use super::*;

pub fn aead_tcp_response_packet(
    request: &VMessAeadTcpRequest,
    payload: &[u8],
) -> Result<Vec<u8>, OutboundError> {
    aead_tcp_response_packet_chunks(request, &[payload])
}

pub fn aead_tcp_response_packet_chunks(
    request: &VMessAeadTcpRequest,
    payloads: &[&[u8]],
) -> Result<Vec<u8>, OutboundError> {
    let mut response = encrypt_response_header(request)?;
    let mut codec = BodyCodec::new(
        request.response_body_key,
        request.response_body_iv,
        request.security,
        request.request_options,
    )?;
    for payload in payloads {
        response.extend_from_slice(&codec.seal_chunk(payload)?);
    }
    Ok(response)
}

pub(super) fn read_http_message<S: Read>(
    stream: &mut S,
    context: &str,
) -> Result<(Vec<u8>, Vec<u8>), OutboundError> {
    let head_with_leftover = read_http_head(stream)?;
    let Some(index) = head_with_leftover
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
    else {
        return Err(OutboundError::BadSharedTransport(format!(
            "incomplete {context} header"
        )));
    };
    let body_start = index + 4;
    let head = head_with_leftover[..body_start].to_vec();
    let mut body = head_with_leftover[body_start..].to_vec();
    let content_length = http_content_length(&head)?;
    while body.len() < content_length {
        let mut buf = vec![0_u8; content_length - body.len()];
        let n = stream
            .read(&mut buf)
            .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&buf[..n]);
    }
    if body.len() < content_length {
        return Err(OutboundError::BadSharedTransport(format!(
            "incomplete {context} body"
        )));
    }
    body.truncate(content_length);
    Ok((head, body))
}

pub(super) fn validate_meek_request_head(
    request_head: &[u8],
    meek_options: &MeekRoundTripOptions,
) -> Result<(), OutboundError> {
    let text = std::str::from_utf8(request_head)
        .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
    let mut lines = text.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| OutboundError::BadSharedTransport("empty meek request".to_owned()))?;
    let want = format!("POST {} HTTP/1.1", meek_options.path);
    if request_line != want {
        return Err(OutboundError::BadSharedTransport(format!(
            "unexpected meek request line: {request_line}"
        )));
    }
    let host = http_header_value(text, "host")
        .ok_or_else(|| OutboundError::BadSharedTransport("missing meek Host header".to_owned()))?;
    if host != meek_options.host {
        return Err(OutboundError::BadSharedTransport(format!(
            "unexpected meek Host header: {host}"
        )));
    }
    let session = http_header_value(text, "x-session-id").ok_or_else(|| {
        OutboundError::BadSharedTransport("missing meek X-Session-ID header".to_owned())
    })?;
    if session != meek_options.session_id() {
        return Err(OutboundError::BadSharedTransport(format!(
            "unexpected meek X-Session-ID header: {session}"
        )));
    }
    Ok(())
}

pub(super) fn validate_http_transport_request_head(
    request_head: &[u8],
    http_options: &HttpConnectOptions,
) -> Result<VMessHttpTransportRequestHead, OutboundError> {
    let text = std::str::from_utf8(request_head)
        .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
    let mut lines = text.split("\r\n");
    let request_line = lines.next().ok_or_else(|| {
        OutboundError::BadSharedTransport("empty http transport request".to_owned())
    })?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let request_uri = parts.next().unwrap_or_default();
    let version = parts.next().unwrap_or_default();
    if method != "PUT" || version != "HTTP/1.1" {
        return Err(OutboundError::BadSharedTransport(format!(
            "unexpected http transport request line: {request_line}"
        )));
    }
    let host = http_transport_host(http_options);
    let path = http_transport_path(http_options);
    let want_uri = format!("http://{host}{path}");
    if request_uri != want_uri {
        return Err(OutboundError::BadSharedTransport(format!(
            "unexpected http transport uri: {request_uri}"
        )));
    }
    let got_host = http_header_value(text, "host").ok_or_else(|| {
        OutboundError::BadSharedTransport("missing http transport Host header".to_owned())
    })?;
    if got_host != host {
        return Err(OutboundError::BadSharedTransport(format!(
            "unexpected http transport Host header: {got_host}"
        )));
    }
    let content_length = http_header_value(text, "content-length").ok_or_else(|| {
        OutboundError::BadSharedTransport("missing http transport Content-Length header".to_owned())
    })?;
    if content_length != "0" {
        return Err(OutboundError::BadSharedTransport(format!(
            "unexpected http transport Content-Length: {content_length}"
        )));
    }
    Ok(VMessHttpTransportRequestHead {
        method: method.to_owned(),
        request_uri: request_uri.to_owned(),
        host,
        path,
        request_head_len: request_head.len(),
        transport_enabled: true,
    })
}

pub(super) fn http_content_length(head: &[u8]) -> Result<usize, OutboundError> {
    let text = std::str::from_utf8(head)
        .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
    http_header_value(text, "content-length")
        .unwrap_or("0")
        .parse::<usize>()
        .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))
}

pub(super) fn http_header_value<'a>(head: &'a str, key: &str) -> Option<&'a str> {
    for line in head.split("\r\n") {
        let Some((got_key, value)) = line.split_once(':') else {
            continue;
        };
        if got_key.eq_ignore_ascii_case(key) {
            return Some(value.trim());
        }
    }
    None
}

pub(super) fn http_transport_host(options: &HttpConnectOptions) -> String {
    if options.host_override.is_empty() {
        "www.fixture.invalid".to_owned()
    } else {
        options.host_override.clone()
    }
}

pub(super) fn http_transport_path(options: &HttpConnectOptions) -> String {
    if options.transport.path.is_empty() {
        "/".to_owned()
    } else {
        options.transport.path.clone()
    }
}
