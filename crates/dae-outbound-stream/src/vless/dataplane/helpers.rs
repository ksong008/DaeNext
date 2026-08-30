use super::*;

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
) -> Result<VlessHttpTransportRequestHead, OutboundError> {
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
    Ok(VlessHttpTransportRequestHead {
        method: method.to_owned(),
        request_uri: request_uri.to_owned(),
        host,
        path,
        request_head_len: request_head.len(),
        transport_enabled: true,
    })
}

pub(super) fn validate_xhttp_packet_request_head(
    request_head: &[u8],
    body_len: usize,
    xhttp_options: &XHttpLifecycleOptions,
) -> Result<String, OutboundError> {
    let text = std::str::from_utf8(request_head)
        .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
    let mut lines = text.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| OutboundError::BadSharedTransport("empty xhttp request".to_owned()))?;
    let request_path = xhttp_request_path(xhttp_options);
    let want = format!("POST {request_path} HTTP/1.1");
    if request_line != want {
        return Err(OutboundError::BadSharedTransport(format!(
            "unexpected xhttp request line: {request_line}"
        )));
    }
    let host = http_header_value(text, "host")
        .ok_or_else(|| OutboundError::BadSharedTransport("missing xhttp Host header".to_owned()))?;
    if host != xhttp_options.host {
        return Err(OutboundError::BadSharedTransport(format!(
            "unexpected xhttp Host header: {host}"
        )));
    }
    let mode = http_header_value(text, "x-dae-xhttp-mode")
        .ok_or_else(|| OutboundError::BadSharedTransport("missing xhttp mode header".to_owned()))?;
    if mode != xhttp_options.mode {
        return Err(OutboundError::BadSharedTransport(format!(
            "unexpected xhttp mode header: {mode}"
        )));
    }
    let alpn = http_header_value(text, "x-dae-xhttp-alpn")
        .ok_or_else(|| OutboundError::BadSharedTransport("missing xhttp alpn header".to_owned()))?;
    if alpn != xhttp_options.alpn {
        return Err(OutboundError::BadSharedTransport(format!(
            "unexpected xhttp alpn header: {alpn}"
        )));
    }
    let content_length = http_header_value(text, "content-length").ok_or_else(|| {
        OutboundError::BadSharedTransport("missing xhttp Content-Length header".to_owned())
    })?;
    if content_length != body_len.to_string() {
        return Err(OutboundError::BadSharedTransport(format!(
            "unexpected xhttp Content-Length: {content_length}"
        )));
    }
    Ok(request_path)
}

pub(super) fn read_request_header(
    stream: &mut impl Read,
) -> Result<VlessRequestHeader, OutboundError> {
    let mut version = [0_u8; 1];
    read_exact(stream, &mut version, "vless version")?;
    if version[0] != VLESS_VERSION {
        return Err(OutboundError::BadVless(format!(
            "unexpected VLESS version: {}",
            version[0]
        )));
    }

    let mut key = [0_u8; 16];
    read_exact(stream, &mut key, "vless key")?;

    let mut addons_len = [0_u8; 1];
    read_exact(stream, &mut addons_len, "vless addons length")?;
    let addons_len = addons_len[0] as usize;
    let mut addons = vec![0_u8; addons_len];
    read_exact(stream, &mut addons, "vless addons")?;

    let mut command = [0_u8; 1];
    read_exact(stream, &mut command, "vless command")?;

    let mut port = [0_u8; 2];
    read_exact(stream, &mut port, "vless target port")?;
    let port = u16::from_be_bytes(port);

    let mut atyp = [0_u8; 1];
    read_exact(stream, &mut atyp, "vless target address type")?;
    let (host, addr_len) = read_vless_host(stream, atyp[0])?;
    let target = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };

    Ok(VlessRequestHeader {
        version: version[0],
        key,
        key_hex: hex_encode(&key),
        addons_len,
        command: command[0],
        target,
        header_len: 1 + 16 + 1 + addons_len + 1 + 2 + 1 + addr_len,
    })
}

pub fn decode_response_payload(input: &[u8]) -> Result<(usize, Vec<u8>), OutboundError> {
    if input.len() < 2 {
        return Err(OutboundError::BadVless(
            "VLESS response header missing".to_owned(),
        ));
    }
    if input[0] != VLESS_VERSION {
        return Err(OutboundError::BadVless(format!(
            "unexpected VLESS response version: {}",
            input[0]
        )));
    }
    let addons_len = input[1] as usize;
    let response_header_len = 2 + addons_len;
    if input.len() < response_header_len {
        return Err(OutboundError::BadVless(
            "VLESS response addons truncated".to_owned(),
        ));
    }
    Ok((response_header_len, input[response_header_len..].to_vec()))
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

pub(super) fn read_udp_response_payload(
    stream: &mut impl Read,
) -> Result<(usize, Vec<u8>), OutboundError> {
    let mut version = [0_u8; 1];
    read_exact(stream, &mut version, "vless response version")?;
    if version[0] != VLESS_VERSION {
        return Err(OutboundError::BadVless(format!(
            "unexpected VLESS response version: {}",
            version[0]
        )));
    }
    let mut addons_len = [0_u8; 1];
    read_exact(stream, &mut addons_len, "vless response addons length")?;
    let addons_len = addons_len[0] as usize;
    let mut addons = vec![0_u8; addons_len];
    read_exact(stream, &mut addons, "vless response addons")?;

    let mut length = [0_u8; 2];
    read_exact(stream, &mut length, "vless udp response payload length")?;
    let payload_len = u16::from_be_bytes(length) as usize;
    let mut payload = vec![0_u8; payload_len];
    read_exact(stream, &mut payload, "vless udp response payload")?;
    Ok((2 + addons_len, payload))
}

pub fn read_tcp_response_payload_from_stream(
    stream: &mut impl Read,
    payload_len: usize,
) -> Result<(usize, Vec<u8>), OutboundError> {
    let mut version = [0_u8; 1];
    read_exact(stream, &mut version, "vless response version")?;
    if version[0] != VLESS_VERSION {
        return Err(OutboundError::BadVless(format!(
            "unexpected VLESS response version: {}",
            version[0]
        )));
    }
    let mut addons_len = [0_u8; 1];
    read_exact(stream, &mut addons_len, "vless response addons length")?;
    let addons_len = addons_len[0] as usize;
    let mut addons = vec![0_u8; addons_len];
    read_exact(stream, &mut addons, "vless response addons")?;

    let mut payload = vec![0_u8; payload_len];
    read_exact(stream, &mut payload, "vless response payload")?;
    Ok((2 + addons_len, payload))
}

pub(super) fn read_vless_host(
    stream: &mut impl Read,
    atyp: u8,
) -> Result<(String, usize), OutboundError> {
    match atyp {
        1 => {
            let mut octets = [0_u8; 4];
            read_exact(stream, &mut octets, "vless ipv4 target")?;
            Ok((Ipv4Addr::from(octets).to_string(), 4))
        }
        2 => {
            let mut len = [0_u8; 1];
            read_exact(stream, &mut len, "vless domain length")?;
            let mut host = vec![0_u8; len[0] as usize];
            read_exact(stream, &mut host, "vless domain target")?;
            let host =
                String::from_utf8(host).map_err(|err| OutboundError::BadVless(err.to_string()))?;
            Ok((host, 1 + len[0] as usize))
        }
        3 => {
            let mut octets = [0_u8; 16];
            read_exact(stream, &mut octets, "vless ipv6 target")?;
            Ok((Ipv6Addr::from(octets).to_string(), 16))
        }
        value => Err(OutboundError::BadVless(format!(
            "bad VLESS address type: {value}"
        ))),
    }
}

pub(super) fn read_exact(
    stream: &mut impl Read,
    buf: &mut [u8],
    context: &str,
) -> Result<(), OutboundError> {
    stream
        .read_exact(buf)
        .map_err(|err| OutboundError::BadVless(format!("read {context} failed: {err}")))
}

pub fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}
