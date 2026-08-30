use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use crate::error::OutboundError;
#[cfg(test)]
pub(crate) use dae_outbound_stream::http_head::read_http_message;
pub(crate) use dae_outbound_stream::websocket::read_websocket_binary_frame;
#[cfg(test)]
pub(crate) use dae_outbound_stream::websocket::validate_http_field;
#[cfg(test)]
pub(crate) use dae_outbound_stream::websocket::websocket_server_binary_frame;
use dae_outbound_stream::websocket::{
    DEFAULT_WS_KEY, HttpUpgradeOptions, SimpleObfsHttpOptions, WS_ACCEPT_SAMPLE, WS_MASK_KEY,
    http_upgrade_request, simpleobfs_http_request, validate_http_status,
    validate_websocket_handshake_response, websocket_client_binary_frame,
    websocket_handshake_request,
};
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

fn set_timeout(stream: &mut TcpStream, timeout: Duration) -> Result<(), OutboundError> {
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))
}

pub fn read_http_head(stream: &mut impl Read) -> Result<Vec<u8>, OutboundError> {
    dae_outbound_stream::http_head::read_http_head(stream)
}

pub fn read_http_head_with_leftover(
    stream: &mut impl Read,
    max_bytes: usize,
    error: impl Fn(String) -> OutboundError,
) -> Result<(Vec<u8>, Vec<u8>), OutboundError> {
    dae_outbound_stream::http_head::read_http_head_with_leftover(stream, max_bytes, error)
}

fn read_exact_payload(stream: &mut TcpStream, len: usize) -> Result<Vec<u8>, OutboundError> {
    let mut payload = vec![0_u8; len];
    stream
        .read_exact(&mut payload)
        .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
    Ok(payload)
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
        HttpUpgradeOptions, http_upgrade_request, read_http_head_with_leftover, read_http_message,
        validate_http_field,
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
    fn shared_http_message_reader_reads_only_declared_body() {
        let mut stream = Cursor::new(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhelloextra");
        let (head, body) = read_http_message(&mut stream, "fixture").unwrap();
        assert!(head.ends_with(b"\r\n\r\n"));
        assert_eq!(body, b"hello");
    }

    #[test]
    fn shared_http_message_reader_rejects_incomplete_body() {
        let mut stream = Cursor::new(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nno");
        let error = read_http_message(&mut stream, "fixture")
            .unwrap_err()
            .to_string();
        assert!(error.contains("incomplete fixture body"));
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
