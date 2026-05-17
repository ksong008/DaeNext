use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use crate::error::OutboundError;

pub const DEFAULT_WS_KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";
pub const WS_ACCEPT_SAMPLE: &str = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";
pub const WS_MASK_KEY: [u8; 4] = [0x11, 0x22, 0x33, 0x44];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SharedTransportLoopbackReport {
    pub transport: &'static str,
    pub endpoint: String,
    pub host: String,
    pub path: String,
    pub payload_len: usize,
    pub echoed_payload: Vec<u8>,
    pub true_dataplane: bool,
    pub default_go_path: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpUpgradeOptions {
    pub host: String,
    pub path: String,
}

impl HttpUpgradeOptions {
    pub fn new(host: impl Into<String>, path: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            path: normalize_path(&path.into()),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SimpleObfsHttpOptions {
    pub host: String,
    pub path: String,
}

impl SimpleObfsHttpOptions {
    pub fn new(host: impl Into<String>, path: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            path: normalize_path(&path.into()),
        }
    }
}

pub fn http_upgrade_exchange(
    endpoint: &str,
    options: &HttpUpgradeOptions,
    payload: &[u8],
    timeout: Duration,
) -> Result<SharedTransportLoopbackReport, OutboundError> {
    let mut stream = TcpStream::connect(endpoint)
        .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
    set_timeout(&mut stream, timeout)?;
    let request = http_upgrade_request(options);
    stream
        .write_all(&request)
        .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
    let response = read_http_head(&mut stream)?;
    validate_http_status(&response, 101)?;
    stream
        .write_all(payload)
        .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
    let echoed_payload = read_exact_payload(&mut stream, payload.len())?;
    Ok(report(
        "httpupgrade",
        endpoint,
        &options.host,
        &options.path,
        payload,
        echoed_payload,
    ))
}

pub fn websocket_exchange(
    endpoint: &str,
    options: &HttpUpgradeOptions,
    payload: &[u8],
    timeout: Duration,
) -> Result<SharedTransportLoopbackReport, OutboundError> {
    let mut stream = TcpStream::connect(endpoint)
        .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
    set_timeout(&mut stream, timeout)?;
    let request = websocket_handshake_request(options, DEFAULT_WS_KEY);
    stream
        .write_all(&request)
        .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
    let response = read_http_head(&mut stream)?;
    validate_http_status(&response, 101)?;
    let frame = websocket_client_binary_frame(payload, WS_MASK_KEY)?;
    stream
        .write_all(&frame)
        .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
    let echoed_payload = read_websocket_binary_frame(&mut stream)?;
    Ok(report(
        "websocket",
        endpoint,
        &options.host,
        &options.path,
        payload,
        echoed_payload,
    ))
}

pub fn simpleobfs_http_exchange(
    endpoint: &str,
    options: &SimpleObfsHttpOptions,
    payload: &[u8],
    timeout: Duration,
) -> Result<SharedTransportLoopbackReport, OutboundError> {
    let mut stream = TcpStream::connect(endpoint)
        .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
    set_timeout(&mut stream, timeout)?;
    let request = simpleobfs_http_request(options);
    stream
        .write_all(&request)
        .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
    stream
        .write_all(payload)
        .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
    let echoed_payload = read_exact_payload(&mut stream, payload.len())?;
    Ok(report(
        "simpleobfs-http",
        endpoint,
        &options.host,
        &options.path,
        payload,
        echoed_payload,
    ))
}

pub fn http_upgrade_request(options: &HttpUpgradeOptions) -> Vec<u8> {
    format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\n",
        options.path, options.host
    )
    .into_bytes()
}

pub fn websocket_handshake_request(options: &HttpUpgradeOptions, key: &str) -> Vec<u8> {
    format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {key}\r\n\r\n",
        options.path, options.host
    )
    .into_bytes()
}

pub fn simpleobfs_http_request(options: &SimpleObfsHttpOptions) -> Vec<u8> {
    format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: curl/7.64.1\r\nAccept: */*\r\n\r\n",
        options.path, options.host
    )
    .into_bytes()
}

pub fn websocket_client_binary_frame(
    payload: &[u8],
    mask_key: [u8; 4],
) -> Result<Vec<u8>, OutboundError> {
    websocket_frame(payload, true, mask_key)
}

pub fn websocket_server_binary_frame(payload: &[u8]) -> Result<Vec<u8>, OutboundError> {
    websocket_frame(payload, false, [0, 0, 0, 0])
}

pub fn read_websocket_binary_frame(stream: &mut TcpStream) -> Result<Vec<u8>, OutboundError> {
    let mut head = [0_u8; 2];
    stream
        .read_exact(&mut head)
        .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
    let fin = head[0] & 0x80 != 0;
    let opcode = head[0] & 0x0f;
    if !fin || opcode != 2 {
        return Err(OutboundError::BadSharedTransport(format!(
            "unexpected websocket frame: fin={fin} opcode={opcode}"
        )));
    }
    let masked = head[1] & 0x80 != 0;
    let mut len = (head[1] & 0x7f) as usize;
    if len == 126 {
        let mut ext = [0_u8; 2];
        stream
            .read_exact(&mut ext)
            .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
        len = u16::from_be_bytes(ext) as usize;
    } else if len == 127 {
        return Err(OutboundError::BadSharedTransport(
            "websocket 64-bit length unsupported in stage20 harness".to_owned(),
        ));
    }
    let mut mask_key = [0_u8; 4];
    if masked {
        stream
            .read_exact(&mut mask_key)
            .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
    }
    let mut payload = vec![0_u8; len];
    stream
        .read_exact(&mut payload)
        .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
    if masked {
        for (index, byte) in payload.iter_mut().enumerate() {
            *byte ^= mask_key[index % 4];
        }
    }
    Ok(payload)
}

fn websocket_frame(
    payload: &[u8],
    masked: bool,
    mask_key: [u8; 4],
) -> Result<Vec<u8>, OutboundError> {
    if payload.len() > u16::MAX as usize {
        return Err(OutboundError::BadSharedTransport(
            "stage20 websocket frame too large".to_owned(),
        ));
    }
    let mut out = Vec::with_capacity(payload.len() + 8);
    out.push(0x82);
    let mask_bit = if masked { 0x80 } else { 0 };
    if payload.len() <= 125 {
        out.push(mask_bit | payload.len() as u8);
    } else {
        out.push(mask_bit | 126);
        out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    }
    if masked {
        out.extend_from_slice(&mask_key);
        out.extend(
            payload
                .iter()
                .enumerate()
                .map(|(index, byte)| byte ^ mask_key[index % 4]),
        );
    } else {
        out.extend_from_slice(payload);
    }
    Ok(out)
}

fn set_timeout(stream: &mut TcpStream, timeout: Duration) -> Result<(), OutboundError> {
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))
}

fn read_http_head(stream: &mut TcpStream) -> Result<Vec<u8>, OutboundError> {
    let mut response = Vec::new();
    let mut buf = [0_u8; 256];
    loop {
        let n = stream
            .read(&mut buf)
            .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
        if n == 0 {
            break;
        }
        response.extend_from_slice(&buf[..n]);
        if response.windows(4).any(|window| window == b"\r\n\r\n") {
            return Ok(response);
        }
        if response.len() > 8192 {
            return Err(OutboundError::BadSharedTransport(
                "http response header too large".to_owned(),
            ));
        }
    }
    Err(OutboundError::BadSharedTransport(
        "incomplete http response header".to_owned(),
    ))
}

fn validate_http_status(response: &[u8], want: u16) -> Result<(), OutboundError> {
    let text = std::str::from_utf8(response)
        .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
    let line = text
        .split("\r\n")
        .next()
        .ok_or_else(|| OutboundError::BadSharedTransport("empty response".to_owned()))?;
    let status = line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| OutboundError::BadSharedTransport("missing status".to_owned()))?
        .parse::<u16>()
        .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
    if status != want {
        return Err(OutboundError::BadSharedTransport(format!(
            "unexpected status: {status}"
        )));
    }
    Ok(())
}

fn read_exact_payload(stream: &mut TcpStream, len: usize) -> Result<Vec<u8>, OutboundError> {
    let mut payload = vec![0_u8; len];
    stream
        .read_exact(&mut payload)
        .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
    Ok(payload)
}

fn normalize_path(path: &str) -> String {
    if path.is_empty() {
        return "/".to_owned();
    }
    if path.starts_with('/') {
        path.to_owned()
    } else {
        format!("/{path}")
    }
}

fn report(
    transport: &'static str,
    endpoint: &str,
    host: &str,
    path: &str,
    payload: &[u8],
    echoed_payload: Vec<u8>,
) -> SharedTransportLoopbackReport {
    SharedTransportLoopbackReport {
        transport,
        endpoint: endpoint.to_owned(),
        host: host.to_owned(),
        path: path.to_owned(),
        payload_len: payload.len(),
        echoed_payload,
        true_dataplane: true,
        default_go_path: true,
    }
}
