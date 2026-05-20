use std::io::{Read, Write};

use aes::Aes128;
use aes::cipher::{Block, BlockEncrypt, KeyInit};
use md5::{Digest, Md5};

use crate::error::OutboundError;
use crate::socks5::Socks5Address;

use super::ShadowsocksMetadata;

const AES_128_CFB_KEY_LEN: usize = 16;
const AES_128_CFB_IV_LEN: usize = 16;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShadowsocksRThreeLayerOptions {
    pub protocol: String,
    pub protocol_param: String,
    pub obfs: String,
    pub obfs_host: String,
    pub obfs_port: u16,
    pub obfs_param: String,
    pub client_iv: [u8; AES_128_CFB_IV_LEN],
    pub server_iv: [u8; AES_128_CFB_IV_LEN],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShadowsocksRThreeLayerRequest {
    pub obfs: String,
    pub protocol: String,
    pub stream_cipher: String,
    pub obfs_request_head_len: usize,
    pub obfs_request_payload_len: usize,
    pub stream_iv_len: usize,
    pub stream_key_len: usize,
    pub target: String,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShadowsocksRThreeLayerExchangeReport {
    pub protocol_name: &'static str,
    pub obfs: String,
    pub protocol: String,
    pub stream_cipher: String,
    pub proxy: String,
    pub target: String,
    pub obfs_host: String,
    pub obfs_port: u16,
    pub obfs_request_head_len: usize,
    pub obfs_request_payload_len: usize,
    pub stream_iv_len: usize,
    pub stream_key_len: usize,
    pub ssr_protocol_addr_len: usize,
    pub payload_len: usize,
    pub echoed_payload: Vec<u8>,
    pub obfs_layer_validated: bool,
    pub stream_cipher_validated: bool,
    pub protocol_wrapper_validated: bool,
    pub three_layer_order_validated: bool,
    pub true_dataplane: bool,
    pub default_go_path: bool,
}

impl ShadowsocksRThreeLayerOptions {
    pub fn http_simple_origin(
        obfs_host: impl Into<String>,
        obfs_port: u16,
        client_iv: [u8; AES_128_CFB_IV_LEN],
        server_iv: [u8; AES_128_CFB_IV_LEN],
    ) -> Self {
        Self {
            protocol: "origin".to_owned(),
            protocol_param: String::new(),
            obfs: "http_simple".to_owned(),
            obfs_host: obfs_host.into(),
            obfs_port,
            obfs_param: String::new(),
            client_iv,
            server_iv,
        }
    }
}

pub fn shadowsocksr_three_layer_tcp_exchange_over_stream<S>(
    stream: &mut S,
    proxy: &str,
    cipher: &str,
    password: &str,
    target: &str,
    payload: &[u8],
    options: &ShadowsocksRThreeLayerOptions,
) -> Result<ShadowsocksRThreeLayerExchangeReport, OutboundError>
where
    S: Read + Write,
{
    validate_supported_stack(cipher, options)?;
    let key = evp_bytes_to_key(password.as_bytes(), AES_128_CFB_KEY_LEN);
    let target_metadata = ShadowsocksMetadata::parse(target)?;
    let target_bytes = target_metadata.encode()?;
    let mut protocol_payload = target_bytes.clone();
    protocol_payload.extend_from_slice(payload);
    let stream_payload =
        stream_encrypt_with_iv(cipher, &key, &options.client_iv, &protocol_payload)?;
    let request = http_simple_obfs_request(options, &stream_payload)?;
    stream
        .write_all(&request)
        .map_err(|err| OutboundError::BadShadowsocks(err.to_string()))?;
    stream
        .flush()
        .map_err(|err| OutboundError::BadShadowsocks(err.to_string()))?;

    let response_payload =
        read_http_simple_response_payload(stream, AES_128_CFB_IV_LEN + payload.len())?;
    let echoed_payload = stream_decrypt_with_iv(cipher, &key, &response_payload)?;
    if echoed_payload != payload {
        return Err(OutboundError::BadShadowsocks(
            "SSR response payload mismatch".to_owned(),
        ));
    }

    Ok(ShadowsocksRThreeLayerExchangeReport {
        protocol_name: "shadowsocksr",
        obfs: options.obfs.clone(),
        protocol: options.protocol.clone(),
        stream_cipher: cipher.to_owned(),
        proxy: proxy.to_owned(),
        target: target_metadata.authority(),
        obfs_host: options.obfs_host.clone(),
        obfs_port: options.obfs_port,
        obfs_request_head_len: request.len(),
        obfs_request_payload_len: stream_payload.len(),
        stream_iv_len: AES_128_CFB_IV_LEN,
        stream_key_len: key.len(),
        ssr_protocol_addr_len: target_bytes.len(),
        payload_len: payload.len(),
        echoed_payload,
        obfs_layer_validated: true,
        stream_cipher_validated: true,
        protocol_wrapper_validated: true,
        three_layer_order_validated: true,
        true_dataplane: true,
        default_go_path: true,
    })
}

pub fn read_shadowsocksr_http_simple_request(
    stream: &mut impl Read,
    cipher: &str,
    password: &str,
    options: &ShadowsocksRThreeLayerOptions,
) -> Result<ShadowsocksRThreeLayerRequest, OutboundError> {
    validate_supported_stack(cipher, options)?;
    let (head, remainder) = read_http_head_with_remainder(stream)?;
    if !remainder.is_empty() {
        return Err(OutboundError::BadShadowsocks(
            "SSR http_simple request carried unexpected body bytes".to_owned(),
        ));
    }
    let head_text =
        std::str::from_utf8(&head).map_err(|err| OutboundError::BadShadowsocks(err.to_string()))?;
    let request_line = head_text
        .split("\r\n")
        .next()
        .ok_or_else(|| OutboundError::BadShadowsocks("SSR request head empty".to_owned()))?;
    let stream_payload = decode_http_simple_request_line(request_line)?;
    let key = evp_bytes_to_key(password.as_bytes(), AES_128_CFB_KEY_LEN);
    let protocol_payload = stream_decrypt_with_iv(cipher, &key, &stream_payload)?;
    let (target, consumed) = Socks5Address::decode(&protocol_payload)?;
    let payload = protocol_payload[consumed..].to_vec();
    Ok(ShadowsocksRThreeLayerRequest {
        obfs: options.obfs.clone(),
        protocol: options.protocol.clone(),
        stream_cipher: cipher.to_owned(),
        obfs_request_head_len: head.len(),
        obfs_request_payload_len: stream_payload.len(),
        stream_iv_len: AES_128_CFB_IV_LEN,
        stream_key_len: key.len(),
        target: target.authority(),
        payload,
    })
}

pub fn encode_shadowsocksr_http_simple_response(
    cipher: &str,
    password: &str,
    server_iv: &[u8],
    payload: &[u8],
) -> Result<Vec<u8>, OutboundError> {
    let key = evp_bytes_to_key(password.as_bytes(), AES_128_CFB_KEY_LEN);
    let stream_payload = stream_encrypt_with_iv(cipher, &key, server_iv, payload)?;
    let mut response = b"HTTP/1.1 200 OK\r\nConnection: keep-alive\r\n\r\n".to_vec();
    response.extend_from_slice(&stream_payload);
    Ok(response)
}

fn validate_supported_stack(
    cipher: &str,
    options: &ShadowsocksRThreeLayerOptions,
) -> Result<(), OutboundError> {
    if cipher != "aes-128-cfb" {
        return Err(OutboundError::BadShadowsocks(format!(
            "stage95 SSR harness supports aes-128-cfb, got {cipher}"
        )));
    }
    if options.obfs != "http_simple" || options.protocol != "origin" {
        return Err(OutboundError::BadShadowsocks(format!(
            "stage95 SSR harness supports http_simple/origin, got {}/{}",
            options.obfs, options.protocol
        )));
    }
    Ok(())
}

fn http_simple_obfs_request(
    options: &ShadowsocksRThreeLayerOptions,
    stream_payload: &[u8],
) -> Result<Vec<u8>, OutboundError> {
    let encoded = percent_encode(stream_payload);
    Ok(format!(
        "GET /{encoded} HTTP/1.1\r\nHost: {}:{}\r\nUser-Agent: Mozilla/5.0 (dae stage95)\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.8\r\nAccept-Encoding: gzip, deflate\r\nDNT: 1\r\nConnection: keep-alive\r\n\r\n",
        options.obfs_host, options.obfs_port
    )
    .into_bytes())
}

fn decode_http_simple_request_line(line: &str) -> Result<Vec<u8>, OutboundError> {
    let Some(path_and_tail) = line.strip_prefix("GET /") else {
        return Err(OutboundError::BadShadowsocks(
            "SSR http_simple request line must start with GET /".to_owned(),
        ));
    };
    let Some((encoded, version)) = path_and_tail.split_once(' ') else {
        return Err(OutboundError::BadShadowsocks(
            "SSR http_simple request line missing HTTP version".to_owned(),
        ));
    };
    if version != "HTTP/1.1" {
        return Err(OutboundError::BadShadowsocks(format!(
            "SSR http_simple HTTP version mismatch: {version}"
        )));
    }
    percent_decode(encoded)
}

fn read_http_simple_response_payload(
    stream: &mut impl Read,
    expected_len: usize,
) -> Result<Vec<u8>, OutboundError> {
    let (head, mut body) = read_http_head_with_remainder(stream)?;
    let head_text =
        std::str::from_utf8(&head).map_err(|err| OutboundError::BadShadowsocks(err.to_string()))?;
    let status_line = head_text
        .split("\r\n")
        .next()
        .ok_or_else(|| OutboundError::BadShadowsocks("SSR response head empty".to_owned()))?;
    if !status_line.contains(" 200 ") {
        return Err(OutboundError::BadShadowsocks(format!(
            "SSR http_simple response status mismatch: {status_line}"
        )));
    }
    while body.len() < expected_len {
        let mut chunk = vec![0_u8; expected_len - body.len()];
        stream
            .read_exact(&mut chunk)
            .map_err(|err| OutboundError::BadShadowsocks(err.to_string()))?;
        body.extend_from_slice(&chunk);
    }
    body.truncate(expected_len);
    Ok(body)
}

fn read_http_head_with_remainder(
    stream: &mut impl Read,
) -> Result<(Vec<u8>, Vec<u8>), OutboundError> {
    let mut buf = Vec::new();
    let mut chunk = [0_u8; 256];
    loop {
        let n = stream
            .read(&mut chunk)
            .map_err(|err| OutboundError::BadShadowsocks(err.to_string()))?;
        if n == 0 {
            return Err(OutboundError::BadShadowsocks(
                "incomplete SSR HTTP obfs head".to_owned(),
            ));
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = find_header_end(&buf) {
            let body = buf[pos + 4..].to_vec();
            buf.truncate(pos + 4);
            return Ok((buf, body));
        }
        if buf.len() > 16384 {
            return Err(OutboundError::BadShadowsocks(
                "SSR HTTP obfs head too large".to_owned(),
            ));
        }
    }
}

fn stream_encrypt_with_iv(
    cipher: &str,
    key: &[u8],
    iv: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, OutboundError> {
    if cipher != "aes-128-cfb" || key.len() != AES_128_CFB_KEY_LEN || iv.len() != AES_128_CFB_IV_LEN
    {
        return Err(OutboundError::BadShadowsocks(
            "invalid SSR stream cipher material".to_owned(),
        ));
    }
    let mut out = Vec::with_capacity(iv.len() + plaintext.len());
    out.extend_from_slice(iv);
    out.extend_from_slice(&aes_128_cfb_encrypt(key, iv, plaintext)?);
    Ok(out)
}

fn stream_decrypt_with_iv(
    cipher: &str,
    key: &[u8],
    ciphertext_with_iv: &[u8],
) -> Result<Vec<u8>, OutboundError> {
    if cipher != "aes-128-cfb" || key.len() != AES_128_CFB_KEY_LEN {
        return Err(OutboundError::BadShadowsocks(
            "invalid SSR stream cipher".to_owned(),
        ));
    }
    if ciphertext_with_iv.len() < AES_128_CFB_IV_LEN {
        return Err(OutboundError::BadShadowsocks(
            "SSR stream payload missing IV".to_owned(),
        ));
    }
    let (iv, ciphertext) = ciphertext_with_iv.split_at(AES_128_CFB_IV_LEN);
    aes_128_cfb_decrypt(key, iv, ciphertext)
}

fn aes_128_cfb_encrypt(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, OutboundError> {
    let cipher = Aes128::new_from_slice(key)
        .map_err(|err| OutboundError::BadShadowsocks(err.to_string()))?;
    let mut prev = <[u8; AES_128_CFB_IV_LEN]>::try_from(iv)
        .map_err(|_| OutboundError::BadShadowsocks("invalid AES-CFB IV".to_owned()))?;
    let mut out = Vec::with_capacity(plaintext.len());
    for chunk in plaintext.chunks(AES_128_CFB_IV_LEN) {
        let mut block = Block::<Aes128>::clone_from_slice(&prev);
        cipher.encrypt_block(&mut block);
        let start = out.len();
        out.extend(
            chunk
                .iter()
                .enumerate()
                .map(|(idx, byte)| byte ^ block[idx]),
        );
        if chunk.len() == AES_128_CFB_IV_LEN {
            prev.copy_from_slice(&out[start..start + AES_128_CFB_IV_LEN]);
        }
    }
    Ok(out)
}

fn aes_128_cfb_decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, OutboundError> {
    let cipher = Aes128::new_from_slice(key)
        .map_err(|err| OutboundError::BadShadowsocks(err.to_string()))?;
    let mut prev = <[u8; AES_128_CFB_IV_LEN]>::try_from(iv)
        .map_err(|_| OutboundError::BadShadowsocks("invalid AES-CFB IV".to_owned()))?;
    let mut out = Vec::with_capacity(ciphertext.len());
    for chunk in ciphertext.chunks(AES_128_CFB_IV_LEN) {
        let mut block = Block::<Aes128>::clone_from_slice(&prev);
        cipher.encrypt_block(&mut block);
        out.extend(
            chunk
                .iter()
                .enumerate()
                .map(|(idx, byte)| byte ^ block[idx]),
        );
        if chunk.len() == AES_128_CFB_IV_LEN {
            prev.copy_from_slice(chunk);
        }
    }
    Ok(out)
}

fn evp_bytes_to_key(password: &[u8], key_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(key_len);
    let mut previous = Vec::new();
    while out.len() < key_len {
        let mut hasher = Md5::new();
        if !previous.is_empty() {
            hasher.update(&previous);
        }
        hasher.update(password);
        previous = hasher.finalize().to_vec();
        out.extend_from_slice(&previous);
    }
    out.truncate(key_len);
    out
}

fn percent_encode(input: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(input.len() * 3);
    for byte in input {
        out.push('%');
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn percent_decode(input: &str) -> Result<Vec<u8>, OutboundError> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 3);
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'%' || index + 2 >= bytes.len() {
            return Err(OutboundError::BadShadowsocks(
                "bad SSR percent encoding".to_owned(),
            ));
        }
        let high = hex_nibble(bytes[index + 1])?;
        let low = hex_nibble(bytes[index + 2])?;
        out.push((high << 4) | low);
        index += 3;
    }
    Ok(out)
}

fn hex_nibble(byte: u8) -> Result<u8, OutboundError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(OutboundError::BadShadowsocks(format!(
            "bad SSR percent escape byte: {byte}"
        ))),
    }
}

fn find_header_end(input: &[u8]) -> Option<usize> {
    input.windows(4).position(|window| window == b"\r\n\r\n")
}
