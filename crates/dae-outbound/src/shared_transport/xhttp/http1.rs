use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use crate::error::OutboundError;
use crate::shared_transport::ir;

use super::options::{XHttpLifecycleOptions, XHttpLifecycleReport};

pub fn xhttp_packet_request(
    options: &XHttpLifecycleOptions,
    payload: &[u8],
) -> Result<Vec<u8>, OutboundError> {
    let path = xhttp_request_path(options);
    // F-12: 拒绝 CTL，防止 host/path/mode/alpn 注入额外请求行/头。
    crate::shared_transport::dataplane::validate_http_field(&options.host, "xHTTP HTTP host")?;
    crate::shared_transport::dataplane::validate_http_field(&path, "xHTTP HTTP path")?;
    crate::shared_transport::dataplane::validate_http_field(&options.mode, "xHTTP HTTP mode")?;
    crate::shared_transport::dataplane::validate_http_field(&options.alpn, "xHTTP HTTP alpn")?;
    Ok(format!(
        "POST {path} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/octet-stream\r\nX-DAE-XHTTP-Mode: {}\r\nX-DAE-XHTTP-ALPN: {}\r\nContent-Length: {}\r\n\r\n",
        options.host,
        options.mode,
        options.alpn,
        payload.len()
    )
    .into_bytes()
    .into_iter()
    .chain(payload.iter().copied())
    .collect())
}

pub fn xhttp_packet_exchange(
    endpoint: &str,
    options: &XHttpLifecycleOptions,
    payload: &[u8],
    timeout: Duration,
) -> Result<XHttpLifecycleReport, OutboundError> {
    let mut stream = TcpStream::connect(endpoint)
        .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
    set_timeout(&stream, timeout)?;
    let request = xhttp_packet_request(options, payload)?;
    stream
        .write_all(&request)
        .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
    let echoed_payload = read_http_response_body(&mut stream)?;
    let alpn = ir::validate_xhttp_alpn(&options.security, &options.alpn);
    Ok(XHttpLifecycleReport {
        transport: "xhttp-packet",
        host: options.host.clone(),
        path: ir::normalize_xhttp_path_and_query(&options.path).path,
        mode: options.mode.clone(),
        alpn: options.alpn.clone(),
        use_h3: alpn.use_h3,
        payload_len: payload.len(),
        echoed_payload,
        lifecycle_harness: true,
        full_h2_h3_stack: false,
    })
}

pub fn xhttp_request_path(options: &XHttpLifecycleOptions) -> String {
    let path = ir::normalize_xhttp_path_and_query(&options.path);
    let lifecycle = format!("session={}&seq={}", options.session_id, options.seq);
    if path.query.is_empty() {
        format!("{}?{lifecycle}", path.path)
    } else {
        format!("{}?{}&{lifecycle}", path.path, path.query)
    }
}

fn read_http_response_body(stream: &mut TcpStream) -> Result<Vec<u8>, OutboundError> {
    let (head, mut leftover) = read_http_head_and_leftover(stream)?;
    let content_length = crate::shared_transport::bounded_http_message_body_length(
        content_length(&head)?,
        "xhttp response",
    )?;
    while leftover.len() < content_length {
        let mut buf = [0_u8; 8192];
        let wanted = (content_length - leftover.len()).min(buf.len());
        let n = stream
            .read(&mut buf[..wanted])
            .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
        if n == 0 {
            break;
        }
        leftover.extend_from_slice(&buf[..n]);
    }
    if leftover.len() < content_length {
        return Err(OutboundError::BadSharedTransport(
            "incomplete xhttp response body".to_owned(),
        ));
    }
    leftover.truncate(content_length);
    Ok(leftover)
}

fn read_http_head_and_leftover(stream: &mut TcpStream) -> Result<(String, Vec<u8>), OutboundError> {
    let mut data = Vec::new();
    let mut buf = [0_u8; 256];
    loop {
        let n = stream
            .read(&mut buf)
            .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
        if n == 0 {
            return Err(OutboundError::BadSharedTransport(
                "incomplete xhttp response".to_owned(),
            ));
        }
        data.extend_from_slice(&buf[..n]);
        if data.len() > 8192 {
            return Err(OutboundError::BadSharedTransport(
                "xhttp response header too large".to_owned(),
            ));
        }
        if let Some(index) = data.windows(4).position(|window| window == b"\r\n\r\n") {
            let body_start = index + 4;
            let leftover = data[body_start..].to_vec();
            data.truncate(body_start);
            let head = String::from_utf8(data)
                .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
            return Ok((head, leftover));
        }
    }
}

fn content_length(head: &str) -> Result<usize, OutboundError> {
    for line in head.split("\r\n") {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        if key.eq_ignore_ascii_case("content-length") {
            return value
                .trim()
                .parse::<usize>()
                .map_err(|err| OutboundError::BadSharedTransport(err.to_string()));
        }
    }
    Ok(0)
}

fn set_timeout(stream: &TcpStream, timeout: Duration) -> Result<(), OutboundError> {
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))
}
