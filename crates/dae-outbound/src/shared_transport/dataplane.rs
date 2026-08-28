use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use base64::Engine as _;
use sha1::{Digest as _, Sha1};

use crate::error::OutboundError;

pub const DEFAULT_WS_KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";
pub const WS_ACCEPT_SAMPLE: &str = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";
pub const WS_MASK_KEY: [u8; 4] = [0x11, 0x22, 0x33, 0x44];
const WEBSOCKET_ACCEPT_GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WebSocketClientHandshake {
    pub request: Vec<u8>,
    pub expected_accept: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SharedTransportLoopbackReport {
    pub transport: &'static str,
    pub endpoint: String,
    pub host: String,
    pub path: String,
    pub payload_len: usize,
    pub echoed_payload: Vec<u8>,
    pub true_dataplane: bool,
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
    let request = http_upgrade_request(options)?;
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
    let request = websocket_handshake_request(options, DEFAULT_WS_KEY)?;
    stream
        .write_all(&request)
        .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
    let response = read_http_head(&mut stream)?;
    validate_websocket_handshake_response(&response, WS_ACCEPT_SAMPLE)?;
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
    let request = simpleobfs_http_request(options)?;
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

pub(crate) fn validate_http_field(value: &str, context: &str) -> Result<(), OutboundError> {
    if value.bytes().any(|byte| byte < 0x20 || byte == 0x7f) {
        return Err(OutboundError::BadSharedTransport(format!(
            "{context} contains control characters; refusing to build HTTP request"
        )));
    }
    Ok(())
}

pub fn http_upgrade_request(options: &HttpUpgradeOptions) -> Result<Vec<u8>, OutboundError> {
    validate_http_field(&options.host, "HTTP upgrade host")?;
    validate_http_field(&options.path, "HTTP upgrade path")?;
    Ok(format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\n",
        options.path, options.host
    )
    .into_bytes())
}

pub fn websocket_handshake_request(
    options: &HttpUpgradeOptions,
    key: &str,
) -> Result<Vec<u8>, OutboundError> {
    validate_http_field(&options.host, "websocket handshake host")?;
    validate_http_field(&options.path, "websocket handshake path")?;
    validate_http_field(key, "websocket handshake key")?;
    Ok(format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {key}\r\n\r\n",
        options.path, options.host
    )
    .into_bytes())
}

pub fn websocket_client_handshake_key() -> Result<String, OutboundError> {
    let mut nonce = [0_u8; 16];
    getrandom::fill(&mut nonce).map_err(|err| {
        OutboundError::BadSharedTransport(format!("generate websocket client nonce: {err}"))
    })?;
    Ok(base64::engine::general_purpose::STANDARD.encode(nonce))
}

pub fn websocket_client_handshake_request(
    options: &HttpUpgradeOptions,
) -> Result<Vec<u8>, OutboundError> {
    Ok(websocket_client_handshake(options)?.request)
}

pub fn websocket_client_handshake(
    options: &HttpUpgradeOptions,
) -> Result<WebSocketClientHandshake, OutboundError> {
    let key = websocket_client_handshake_key()?;
    Ok(WebSocketClientHandshake {
        request: websocket_handshake_request(options, &key)?,
        expected_accept: websocket_accept_for_key(&key),
    })
}

pub fn websocket_accept_for_key(key: &str) -> String {
    let mut sha1 = Sha1::new();
    sha1.update(key.as_bytes());
    sha1.update(WEBSOCKET_ACCEPT_GUID);
    base64::engine::general_purpose::STANDARD.encode(sha1.finalize())
}

pub fn validate_websocket_handshake_response(
    response: &[u8],
    expected_accept: &str,
) -> Result<(), OutboundError> {
    let head_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|offset| offset + 4)
        .ok_or_else(|| {
            OutboundError::BadSharedTransport("incomplete websocket response head".to_owned())
        })?;
    let head = std::str::from_utf8(&response[..head_end])
        .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
    validate_http_status(head.as_bytes(), 101)?;
    let mut upgrade = false;
    let mut connection = false;
    let mut accept = None;
    for line in head.split("\r\n").skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        if name.eq_ignore_ascii_case("upgrade") {
            upgrade |= value.eq_ignore_ascii_case("websocket");
        } else if name.eq_ignore_ascii_case("connection") {
            connection |= value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case("upgrade"));
        } else if name.eq_ignore_ascii_case("sec-websocket-accept")
            && accept.replace(value).is_some()
        {
            return Err(OutboundError::BadSharedTransport(
                "duplicate Sec-WebSocket-Accept header".to_owned(),
            ));
        }
    }
    if !upgrade {
        return Err(OutboundError::BadSharedTransport(
            "websocket response is missing Upgrade: websocket".to_owned(),
        ));
    }
    if !connection {
        return Err(OutboundError::BadSharedTransport(
            "websocket response is missing Connection: upgrade".to_owned(),
        ));
    }
    if accept != Some(expected_accept) {
        return Err(OutboundError::BadSharedTransport(
            "websocket Sec-WebSocket-Accept mismatch".to_owned(),
        ));
    }
    Ok(())
}

pub fn websocket_client_mask_key() -> Result<[u8; 4], OutboundError> {
    let mut mask_key = [0_u8; 4];
    getrandom::fill(&mut mask_key).map_err(|err| {
        OutboundError::BadSharedTransport(format!("generate websocket frame mask: {err}"))
    })?;
    Ok(mask_key)
}

pub fn simpleobfs_http_request(options: &SimpleObfsHttpOptions) -> Result<Vec<u8>, OutboundError> {
    validate_http_field(&options.host, "simpleobfs HTTP host")?;
    validate_http_field(&options.path, "simpleobfs HTTP path")?;
    Ok(format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: curl/7.64.1\r\nAccept: */*\r\n\r\n",
        options.path, options.host
    )
    .into_bytes())
}

pub fn websocket_client_binary_frame(
    payload: &[u8],
    mask_key: [u8; 4],
) -> Result<Vec<u8>, OutboundError> {
    websocket_frame(payload, true, mask_key)
}

pub fn websocket_client_binary_frame_with_random_mask(
    payload: &[u8],
) -> Result<Vec<u8>, OutboundError> {
    websocket_client_binary_frame(payload, websocket_client_mask_key()?)
}

pub fn websocket_server_binary_frame(payload: &[u8]) -> Result<Vec<u8>, OutboundError> {
    websocket_frame(payload, false, [0, 0, 0, 0])
}

pub fn read_websocket_binary_frame(stream: &mut impl Read) -> Result<Vec<u8>, OutboundError> {
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
            "websocket 64-bit length unsupported in shared transport harness".to_owned(),
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
            "websocket frame too large".to_owned(),
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

pub fn read_http_head(stream: &mut impl Read) -> Result<Vec<u8>, OutboundError> {
    let (mut head, leftover) =
        read_http_head_with_leftover(stream, 8192, OutboundError::BadSharedTransport)?;
    head.extend_from_slice(&leftover);
    Ok(head)
}

pub fn read_http_head_with_leftover(
    stream: &mut impl Read,
    max_bytes: usize,
    error: impl Fn(String) -> OutboundError,
) -> Result<(Vec<u8>, Vec<u8>), OutboundError> {
    let mut response = Vec::new();
    let mut buffer = [0_u8; 256];
    loop {
        let read = stream
            .read(&mut buffer)
            .map_err(|err| error(err.to_string()))?;
        if read == 0 {
            return Err(error("incomplete http response header".to_owned()));
        }
        response.extend_from_slice(&buffer[..read]);
        if let Some(index) = response.windows(4).position(|window| window == b"\r\n\r\n") {
            let head_end = index + 4;
            if head_end > max_bytes {
                return Err(error("http response header too large".to_owned()));
            }
            let leftover = response.split_off(head_end);
            return Ok((response, leftover));
        }
        if response.len() > max_bytes {
            return Err(error("http response header too large".to_owned()));
        }
    }
}

pub fn validate_http_status(response: &[u8], want: u16) -> Result<(), OutboundError> {
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
    }
}

#[cfg(test)]
mod http_control_character_tests {
    use std::io::Cursor;

    use super::{
        HttpUpgradeOptions, http_upgrade_request, read_http_head_with_leftover, validate_http_field,
    };
    use crate::error::OutboundError;

    #[test]
    fn rejects_crlf_injection_in_host() {
        let err = validate_http_field("evil.example\r\nX-Injected: 1", "host").unwrap_err();
        assert!(err.to_string().contains("control characters"));
    }

    #[test]
    fn rejects_crlf_injection_in_path() {
        let options = HttpUpgradeOptions {
            host: "example.com".to_owned(),
            path: "/ok\r\nX-Injected: 1".to_owned(),
        };
        assert!(http_upgrade_request(&options).is_err());
    }

    #[test]
    fn accepts_plain_values() {
        let options = HttpUpgradeOptions {
            host: "example.com".to_owned(),
            path: "/ok".to_owned(),
        };
        assert!(http_upgrade_request(&options).is_ok());
    }

    #[test]
    fn shared_http_head_reader_preserves_leftover_bytes() {
        let mut stream = Cursor::new(b"HTTP/1.1 101 Switching Protocols\r\n\r\nfirst");
        let (head, leftover) =
            read_http_head_with_leftover(&mut stream, 8192, OutboundError::BadSharedTransport)
                .unwrap();
        assert_eq!(head, b"HTTP/1.1 101 Switching Protocols\r\n\r\n");
        assert_eq!(leftover, b"first");
    }

    #[test]
    fn rejects_all_control_characters() {
        for byte in 0x00_u8..=0x1f {
            let value = format!("a{}b", char::from(byte));
            assert!(
                validate_http_field(&value, "field").is_err(),
                "byte 0x{byte:02x} must be rejected"
            );
        }
        assert!(validate_http_field("a\u{7f}b", "field").is_err());
    }
}
