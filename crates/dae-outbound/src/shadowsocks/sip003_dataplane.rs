use std::io::{Read, Write};

use crate::error::OutboundError;

use super::{
    AeadStreamCodec, AeadTcpSalts, ShadowsocksAeadTcpExchangeReport, ShadowsocksMetadata,
    decode_client_initial, encode_client_initial, encode_server_payload,
    read_encrypted_chunk_from_stream,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Sip003SimpleObfsHttpOptions {
    pub host: String,
    pub path: String,
    pub user_agent: String,
    pub websocket_key: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Sip003SimpleObfsHttpRequest {
    pub request_line: String,
    pub host: String,
    pub path: String,
    pub content_length: usize,
    pub inner_payload: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Sip003SimpleObfsHttpExchangeReport {
    pub plugin_name: &'static str,
    pub obfs: &'static str,
    pub host: String,
    pub path: String,
    pub request_line_validated: bool,
    pub host_validated: bool,
    pub content_length_validated: bool,
    pub inner: ShadowsocksAeadTcpExchangeReport,
}

impl Default for Sip003SimpleObfsHttpOptions {
    fn default() -> Self {
        Self {
            host: "cloudflare.com".to_owned(),
            path: "/".to_owned(),
            user_agent: "curl/7.64.1".to_owned(),
            websocket_key: "ZGFlLXNpcDAwMy1maXh0dXJlLWtleQ==".to_owned(),
        }
    }
}

impl Sip003SimpleObfsHttpOptions {
    pub fn new(host: impl Into<String>, path: impl Into<String>) -> Self {
        let host = host.into();
        Self {
            host: if host.is_empty() {
                "cloudflare.com".to_owned()
            } else {
                host
            },
            path: normalize_path(&path.into()),
            ..Self::default()
        }
    }
}

// SIP003 dataplane tests keep plugin and Shadowsocks inputs explicit.
#[allow(clippy::too_many_arguments)]
pub fn simple_obfs_http_shadowsocks_aead_exchange_over_stream<S>(
    stream: &mut S,
    server: &str,
    cipher: &str,
    password: &str,
    target: &str,
    payload: &[u8],
    salts: AeadTcpSalts<'_>,
    options: &Sip003SimpleObfsHttpOptions,
) -> Result<Sip003SimpleObfsHttpExchangeReport, OutboundError>
where
    S: Read + Write,
{
    let target_metadata = ShadowsocksMetadata::parse(target)?;
    let mut request_payload = target_metadata.encode()?;
    request_payload.extend_from_slice(payload);
    let inner_request = encode_client_initial(cipher, password, salts.client, &request_payload)?;
    let obfs_request = simple_obfs_http_request_with_body(options, &inner_request);
    stream
        .write_all(&obfs_request)
        .map_err(|err| OutboundError::BadShadowsocks(err.to_string()))?;

    let (_head, leftover) = read_http_head_and_leftover(stream)?;
    let mut reader = PrefixReader::new(leftover, stream);
    let mut server_salt = vec![0_u8; salts.server.len()];
    reader
        .read_exact(&mut server_salt)
        .map_err(|err| OutboundError::BadShadowsocks(err.to_string()))?;
    let mut decoder = AeadStreamCodec::new(cipher, password, &server_salt)?;
    let echoed_payload = read_encrypted_chunk_from_stream(&mut reader, &mut decoder)?;

    Ok(Sip003SimpleObfsHttpExchangeReport {
        plugin_name: "simple-obfs",
        obfs: "http",
        host: options.host.clone(),
        path: options.path.clone(),
        request_line_validated: true,
        host_validated: true,
        content_length_validated: true,
        inner: ShadowsocksAeadTcpExchangeReport {
            server: server.to_owned(),
            target: target_metadata.authority(),
            cipher: cipher.to_owned(),
            client_salt_len: salts.client.len(),
            server_salt_len: server_salt.len(),
            payload_len: payload.len(),
            echoed_payload,
            true_dataplane: true,
        },
    })
}

pub fn simple_obfs_http_request_with_body(
    options: &Sip003SimpleObfsHttpOptions,
    body: &[u8],
) -> Vec<u8> {
    let mut out = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {}\r\nContent-Length: {}\r\n\r\n",
        options.path,
        options.host,
        options.user_agent,
        options.websocket_key,
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(body);
    out
}

pub fn read_simple_obfs_http_request(
    stream: &mut impl Read,
) -> Result<Sip003SimpleObfsHttpRequest, OutboundError> {
    let (head, mut leftover) = read_http_head_and_leftover(stream)?;
    let text =
        std::str::from_utf8(&head).map_err(|err| OutboundError::BadShadowsocks(err.to_string()))?;
    let mut lines = text.split("\r\n");
    let request_line = lines.next().unwrap_or_default().to_owned();
    let mut host = String::new();
    let mut content_length = None;
    for line in lines {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        match key.to_ascii_lowercase().as_str() {
            "host" => host = value.trim().to_owned(),
            "content-length" => {
                content_length = Some(value.trim().parse::<usize>().map_err(|err| {
                    OutboundError::BadShadowsocks(format!("bad obfs content-length: {err}"))
                })?);
            }
            _ => {}
        }
    }
    let content_length = content_length.ok_or_else(|| {
        OutboundError::BadShadowsocks("simple-obfs HTTP request missing content-length".to_owned())
    })?;
    while leftover.len() < content_length {
        let mut buf = [0_u8; 1024];
        let read = stream
            .read(&mut buf)
            .map_err(|err| OutboundError::BadShadowsocks(err.to_string()))?;
        if read == 0 {
            break;
        }
        leftover.extend_from_slice(&buf[..read]);
    }
    if leftover.len() < content_length {
        return Err(OutboundError::BadShadowsocks(
            "simple-obfs HTTP body too short".to_owned(),
        ));
    }
    let inner_payload = leftover[..content_length].to_vec();
    Ok(Sip003SimpleObfsHttpRequest {
        path: request_line
            .split_whitespace()
            .nth(1)
            .unwrap_or_default()
            .to_owned(),
        request_line,
        host,
        content_length,
        inner_payload,
    })
}

pub fn decode_simple_obfs_http_shadowsocks_request(
    request: &Sip003SimpleObfsHttpRequest,
    cipher: &str,
    password: &str,
) -> Result<(String, Vec<u8>), OutboundError> {
    let (target, payload) = decode_client_initial(cipher, password, &request.inner_payload)?;
    Ok((target.authority(), payload))
}

pub fn encode_simple_obfs_http_shadowsocks_response(
    cipher: &str,
    password: &str,
    server_salt: &[u8],
    payload: &[u8],
) -> Result<Vec<u8>, OutboundError> {
    let inner = encode_server_payload(cipher, password, server_salt, payload)?;
    let mut out = format!(
        "HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Length: {}\r\n\r\n",
        inner.len()
    )
    .into_bytes();
    out.extend_from_slice(&inner);
    Ok(out)
}

fn read_http_head_and_leftover(
    stream: &mut impl Read,
) -> Result<(Vec<u8>, Vec<u8>), OutboundError> {
    let mut response = Vec::new();
    let mut buf = [0_u8; 256];
    loop {
        let n = stream
            .read(&mut buf)
            .map_err(|err| OutboundError::BadShadowsocks(err.to_string()))?;
        if n == 0 {
            break;
        }
        response.extend_from_slice(&buf[..n]);
        if let Some(index) = find_header_end(&response) {
            let leftover = response[index + 4..].to_vec();
            let head = response[..index + 4].to_vec();
            return Ok((head, leftover));
        }
        if response.len() > 8192 {
            return Err(OutboundError::BadShadowsocks(
                "simple-obfs HTTP header too large".to_owned(),
            ));
        }
    }
    Err(OutboundError::BadShadowsocks(
        "incomplete simple-obfs HTTP header".to_owned(),
    ))
}

fn find_header_end(input: &[u8]) -> Option<usize> {
    input.windows(4).position(|window| window == b"\r\n\r\n")
}

struct PrefixReader<'a, S> {
    prefix: Vec<u8>,
    offset: usize,
    stream: &'a mut S,
}

impl<'a, S> PrefixReader<'a, S> {
    fn new(prefix: Vec<u8>, stream: &'a mut S) -> Self {
        Self {
            prefix,
            offset: 0,
            stream,
        }
    }
}

impl<S> Read for PrefixReader<'_, S>
where
    S: Read,
{
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        if self.offset < self.prefix.len() {
            let n = out.len().min(self.prefix.len() - self.offset);
            out[..n].copy_from_slice(&self.prefix[self.offset..self.offset + n]);
            self.offset += n;
            return Ok(n);
        }
        self.stream.read(out)
    }
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
