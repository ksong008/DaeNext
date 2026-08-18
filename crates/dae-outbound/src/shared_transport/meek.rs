use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use base64::{Engine as _, engine::general_purpose};
use url::Url;

use crate::error::OutboundError;
use crate::shared_transport::contract;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MeekRoundTripOptions {
    pub url: String,
    pub host: String,
    pub path: String,
    pub session_tag: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MeekRoundTripReport {
    pub transport: &'static str,
    pub url: String,
    pub session_id: String,
    pub round_trips: usize,
    pub echoed_payloads: Vec<Vec<u8>>,
    pub polling_harness: bool,
    pub full_https_round_tripper: bool,
}

impl MeekRoundTripOptions {
    pub fn from_https_url(url: &str, session_tag: Vec<u8>) -> Result<Self, OutboundError> {
        let parsed =
            Url::parse(url).map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
        if parsed.scheme() != contract::MEEK_URL_SCHEME_REQUIRED {
            return Err(OutboundError::BadSharedTransport(
                "meek url must be https".to_owned(),
            ));
        }
        let host = parsed
            .host_str()
            .ok_or_else(|| OutboundError::BadSharedTransport("missing meek host".to_owned()))?;
        let host = if let Some(port) = parsed.port() {
            format!("{host}:{port}")
        } else {
            host.to_owned()
        };
        let mut path = parsed.path().to_owned();
        if path.is_empty() {
            path = "/".to_owned();
        }
        if let Some(query) = parsed.query() {
            path.push('?');
            path.push_str(query);
        }
        Ok(Self {
            url: url.to_owned(),
            host,
            path,
            session_tag,
        })
    }

    pub fn session_id(&self) -> String {
        general_purpose::URL_SAFE_NO_PAD.encode(&self.session_tag)
    }
}

pub fn meek_http_request(
    options: &MeekRoundTripOptions,
    body: &[u8],
) -> Result<Vec<u8>, OutboundError> {
    super::dataplane::validate_http_field(&options.host, "meek HTTP host")?;
    super::dataplane::validate_http_field(&options.path, "meek HTTP path")?;
    Ok(format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nX-Session-ID: {}\r\nContent-Length: {}\r\n\r\n",
        options.path,
        options.host,
        options.session_id(),
        body.len()
    )
    .into_bytes()
    .into_iter()
    .chain(body.iter().copied())
    .collect())
}

pub fn meek_polling_exchange(
    endpoint: &str,
    options: &MeekRoundTripOptions,
    writes: &[&[u8]],
    timeout: Duration,
) -> Result<MeekRoundTripReport, OutboundError> {
    let mut echoed_payloads = Vec::with_capacity(writes.len());
    for body in writes {
        let mut stream = TcpStream::connect(endpoint)
            .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
        set_timeout(&stream, timeout)?;
        stream
            .write_all(&meek_http_request(options, body)?)
            .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
        echoed_payloads.push(read_http_response_body(&mut stream)?);
    }
    Ok(MeekRoundTripReport {
        transport: "meek-polling",
        url: options.url.clone(),
        session_id: options.session_id(),
        round_trips: writes.len(),
        echoed_payloads,
        polling_harness: true,
        full_https_round_tripper: false,
    })
}

fn read_http_response_body(stream: &mut TcpStream) -> Result<Vec<u8>, OutboundError> {
    let (head, mut leftover) = read_http_head_and_leftover(stream)?;
    let content_length = crate::shared_transport::bounded_http_message_body_length(
        content_length(&head)?,
        "meek response",
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
            "incomplete meek response body".to_owned(),
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
                "incomplete meek response".to_owned(),
            ));
        }
        data.extend_from_slice(&buf[..n]);
        if data.len() > 8192 {
            return Err(OutboundError::BadSharedTransport(
                "meek response header too large".to_owned(),
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
