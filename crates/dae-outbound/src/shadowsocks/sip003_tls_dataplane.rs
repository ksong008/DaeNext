use std::io::{Cursor, Read, Write};

use crate::error::OutboundError;

use super::{
    AeadStreamCodec, AeadTcpSalts, ShadowsocksAeadTcpExchangeReport, ShadowsocksMetadata,
    cipher_spec, decode_client_initial, encode_client_initial, encode_server_payload,
    read_encrypted_chunk_from_stream,
};

const TLS_HANDSHAKE_RECORD: u8 = 0x16;
const TLS_APPLICATION_DATA_RECORD: u8 = 0x17;
const SIMPLE_OBFS_TLS_FIRST_RESPONSE_DISCARD: usize = 105;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Sip003SimpleObfsTlsOptions {
    pub server_name: String,
    pub timestamp_unix: u32,
    pub random: [u8; 28],
    pub session_id: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Sip003SimpleObfsTlsRequest {
    pub record_type: u8,
    pub record_version: [u8; 2],
    pub handshake_version: [u8; 2],
    pub server_name: String,
    pub session_ticket_len: usize,
    pub inner_payload: Vec<u8>,
    pub client_hello_len: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Sip003SimpleObfsTlsExchangeReport {
    pub plugin_name: &'static str,
    pub obfs: &'static str,
    pub server_name: String,
    pub client_hello_validated: bool,
    pub sni_validated: bool,
    pub session_ticket_validated: bool,
    pub inner: ShadowsocksAeadTcpExchangeReport,
}

impl Default for Sip003SimpleObfsTlsOptions {
    fn default() -> Self {
        Self {
            server_name: "cloudflare.com".to_owned(),
            timestamp_unix: 1_765_000_093,
            random: [0x42; 28],
            session_id: [0x24; 32],
        }
    }
}

impl Sip003SimpleObfsTlsOptions {
    pub fn new(server_name: impl Into<String>) -> Self {
        let server_name = server_name.into();
        Self {
            server_name: if server_name.is_empty() {
                "cloudflare.com".to_owned()
            } else {
                server_name
            },
            ..Self::default()
        }
    }
}

pub fn simple_obfs_tls_shadowsocks_aead_exchange_over_stream<S>(
    stream: &mut S,
    server: &str,
    cipher: &str,
    password: &str,
    target: &str,
    payload: &[u8],
    salts: AeadTcpSalts<'_>,
    options: &Sip003SimpleObfsTlsOptions,
) -> Result<Sip003SimpleObfsTlsExchangeReport, OutboundError>
where
    S: Read + Write,
{
    let spec = cipher_spec(cipher)?;
    let target_metadata = ShadowsocksMetadata::parse(target)?;
    let mut request_payload = target_metadata.encode()?;
    request_payload.extend_from_slice(payload);
    let inner_request = encode_client_initial(cipher, password, salts.client, &request_payload)?;
    let obfs_request = simple_obfs_tls_client_hello_with_body(options, &inner_request)?;
    stream
        .write_all(&obfs_request)
        .map_err(|err| OutboundError::BadShadowsocks(err.to_string()))?;

    let inner_response = read_simple_obfs_tls_response_payload(stream)?;
    if inner_response.len() < spec.salt_len {
        return Err(OutboundError::BadShadowsocks(
            "simple-obfs TLS response missing Shadowsocks server salt".to_owned(),
        ));
    }
    let (server_salt, encrypted) = inner_response.split_at(spec.salt_len);
    let mut decoder = AeadStreamCodec::new(cipher, password, server_salt)?;
    let mut encrypted_reader = Cursor::new(encrypted);
    let echoed_payload = read_encrypted_chunk_from_stream(&mut encrypted_reader, &mut decoder)?;

    Ok(Sip003SimpleObfsTlsExchangeReport {
        plugin_name: "simple-obfs",
        obfs: "tls",
        server_name: options.server_name.clone(),
        client_hello_validated: true,
        sni_validated: true,
        session_ticket_validated: true,
        inner: ShadowsocksAeadTcpExchangeReport {
            server: server.to_owned(),
            target: target_metadata.authority(),
            cipher: spec.cipher.to_owned(),
            client_salt_len: salts.client.len(),
            server_salt_len: server_salt.len(),
            payload_len: payload.len(),
            echoed_payload,
            true_dataplane: true,
        },
    })
}

pub fn simple_obfs_tls_client_hello_with_body(
    options: &Sip003SimpleObfsTlsOptions,
    body: &[u8],
) -> Result<Vec<u8>, OutboundError> {
    let server = options.server_name.as_bytes();
    let record_len = checked_u16(212 + body.len() + server.len(), "TLS record length")?;
    let hello_len = checked_u16(208 + body.len() + server.len(), "TLS client hello length")?;
    let ext_len = checked_u16(79 + body.len() + server.len(), "TLS extension length")?;
    let ticket_len = checked_u16(body.len(), "TLS session ticket length")?;
    let server_len = checked_u16(server.len(), "TLS server name length")?;
    let sni_ext_len = checked_u16(server.len() + 5, "TLS SNI extension length")?;
    let sni_list_len = checked_u16(server.len() + 3, "TLS SNI list length")?;

    let mut out = Vec::with_capacity(5 + record_len as usize);
    out.push(TLS_HANDSHAKE_RECORD);
    out.extend_from_slice(&[0x03, 0x01]);
    put_u16(&mut out, record_len);

    out.push(0x01);
    out.push(0x00);
    put_u16(&mut out, hello_len);
    out.extend_from_slice(&[0x03, 0x03]);

    put_u32(&mut out, options.timestamp_unix);
    out.extend_from_slice(&options.random);
    out.push(32);
    out.extend_from_slice(&options.session_id);

    out.extend_from_slice(&[0x00, 0x38]);
    out.extend_from_slice(&[
        0xc0, 0x2c, 0xc0, 0x30, 0x00, 0x9f, 0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0xaa, 0xc0, 0x2b, 0xc0,
        0x2f, 0x00, 0x9e, 0xc0, 0x24, 0xc0, 0x28, 0x00, 0x6b, 0xc0, 0x23, 0xc0, 0x27, 0x00, 0x67,
        0xc0, 0x0a, 0xc0, 0x14, 0x00, 0x39, 0xc0, 0x09, 0xc0, 0x13, 0x00, 0x33, 0x00, 0x9d, 0x00,
        0x9c, 0x00, 0x3d, 0x00, 0x3c, 0x00, 0x35, 0x00, 0x2f, 0x00, 0xff,
    ]);

    out.extend_from_slice(&[0x01, 0x00]);
    put_u16(&mut out, ext_len);

    out.extend_from_slice(&[0x00, 0x23]);
    put_u16(&mut out, ticket_len);
    out.extend_from_slice(body);

    out.extend_from_slice(&[0x00, 0x00]);
    put_u16(&mut out, sni_ext_len);
    put_u16(&mut out, sni_list_len);
    out.push(0x00);
    put_u16(&mut out, server_len);
    out.extend_from_slice(server);

    out.extend_from_slice(&[0x00, 0x0b, 0x00, 0x04, 0x03, 0x01, 0x00, 0x02]);
    out.extend_from_slice(&[
        0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x19, 0x00, 0x18,
    ]);
    out.extend_from_slice(&[
        0x00, 0x0d, 0x00, 0x20, 0x00, 0x1e, 0x06, 0x01, 0x06, 0x02, 0x06, 0x03, 0x05, 0x01, 0x05,
        0x02, 0x05, 0x03, 0x04, 0x01, 0x04, 0x02, 0x04, 0x03, 0x03, 0x01, 0x03, 0x02, 0x03, 0x03,
        0x02, 0x01, 0x02, 0x02, 0x02, 0x03,
    ]);
    out.extend_from_slice(&[0x00, 0x16, 0x00, 0x00]);
    out.extend_from_slice(&[0x00, 0x17, 0x00, 0x00]);
    Ok(out)
}

pub fn read_simple_obfs_tls_client_hello(
    stream: &mut impl Read,
) -> Result<Sip003SimpleObfsTlsRequest, OutboundError> {
    let mut header = [0_u8; 5];
    stream
        .read_exact(&mut header)
        .map_err(|err| OutboundError::BadShadowsocks(err.to_string()))?;
    let record_len = u16::from_be_bytes([header[3], header[4]]) as usize;
    let mut body = vec![0_u8; record_len];
    stream
        .read_exact(&mut body)
        .map_err(|err| OutboundError::BadShadowsocks(err.to_string()))?;
    parse_client_hello(header, body)
}

pub fn decode_simple_obfs_tls_shadowsocks_request(
    request: &Sip003SimpleObfsTlsRequest,
    cipher: &str,
    password: &str,
) -> Result<(String, Vec<u8>), OutboundError> {
    let (target, payload) = decode_client_initial(cipher, password, &request.inner_payload)?;
    Ok((target.authority(), payload))
}

pub fn encode_simple_obfs_tls_shadowsocks_response(
    cipher: &str,
    password: &str,
    server_salt: &[u8],
    payload: &[u8],
) -> Result<Vec<u8>, OutboundError> {
    let inner = encode_server_payload(cipher, password, server_salt, payload)?;
    let inner_len = checked_u16(inner.len(), "TLS application payload length")?;
    let mut out = Vec::with_capacity(SIMPLE_OBFS_TLS_FIRST_RESPONSE_DISCARD + 2 + inner.len());
    out.extend_from_slice(&first_response_discard_prefix());
    put_u16(&mut out, inner_len);
    out.extend_from_slice(&inner);
    Ok(out)
}

fn read_simple_obfs_tls_response_payload(stream: &mut impl Read) -> Result<Vec<u8>, OutboundError> {
    let mut discard = vec![0_u8; SIMPLE_OBFS_TLS_FIRST_RESPONSE_DISCARD];
    stream
        .read_exact(&mut discard)
        .map_err(|err| OutboundError::BadShadowsocks(err.to_string()))?;
    let mut len = [0_u8; 2];
    stream
        .read_exact(&mut len)
        .map_err(|err| OutboundError::BadShadowsocks(err.to_string()))?;
    let payload_len = u16::from_be_bytes(len) as usize;
    let mut payload = vec![0_u8; payload_len];
    stream
        .read_exact(&mut payload)
        .map_err(|err| OutboundError::BadShadowsocks(err.to_string()))?;
    Ok(payload)
}

fn parse_client_hello(
    header: [u8; 5],
    body: Vec<u8>,
) -> Result<Sip003SimpleObfsTlsRequest, OutboundError> {
    if header[0] != TLS_HANDSHAKE_RECORD {
        return Err(OutboundError::BadShadowsocks(format!(
            "simple-obfs TLS record type mismatch: {}",
            header[0]
        )));
    }
    if body.len() < 42 {
        return Err(OutboundError::BadShadowsocks(
            "simple-obfs TLS client hello too short".to_owned(),
        ));
    }
    let mut idx = 0;
    let handshake_type = take_u8(&body, &mut idx)?;
    if handshake_type != 0x01 {
        return Err(OutboundError::BadShadowsocks(format!(
            "simple-obfs TLS handshake type mismatch: {handshake_type}"
        )));
    }
    let hello_len = take_u24(&body, &mut idx)?;
    if hello_len != body.len().saturating_sub(4) {
        return Err(OutboundError::BadShadowsocks(format!(
            "simple-obfs TLS hello length mismatch: got {hello_len}, body {}",
            body.len().saturating_sub(4)
        )));
    }
    let handshake_version = take_array_2(&body, &mut idx)?;
    idx = idx
        .checked_add(32)
        .ok_or_else(|| OutboundError::BadShadowsocks("client hello index overflow".to_owned()))?;
    ensure_available(&body, idx, 1)?;
    let session_id_len = body[idx] as usize;
    idx += 1;
    ensure_available(&body, idx, session_id_len)?;
    idx += session_id_len;
    let cipher_suites_len = take_u16(&body, &mut idx)? as usize;
    ensure_available(&body, idx, cipher_suites_len)?;
    idx += cipher_suites_len;
    let compression_len = take_u8(&body, &mut idx)? as usize;
    ensure_available(&body, idx, compression_len)?;
    idx += compression_len;
    let extensions_len = take_u16(&body, &mut idx)? as usize;
    ensure_available(&body, idx, extensions_len)?;
    let extensions_end = idx + extensions_len;

    let mut server_name = String::new();
    let mut ticket = Vec::new();
    while idx < extensions_end {
        let ext_type = take_u16(&body, &mut idx)?;
        let ext_len = take_u16(&body, &mut idx)? as usize;
        ensure_available(&body, idx, ext_len)?;
        let ext = &body[idx..idx + ext_len];
        match ext_type {
            0x0023 => ticket = ext.to_vec(),
            0x0000 => server_name = parse_sni_extension(ext)?,
            _ => {}
        }
        idx += ext_len;
    }
    if ticket.is_empty() {
        return Err(OutboundError::BadShadowsocks(
            "simple-obfs TLS client hello missing session ticket".to_owned(),
        ));
    }
    if server_name.is_empty() {
        return Err(OutboundError::BadShadowsocks(
            "simple-obfs TLS client hello missing SNI".to_owned(),
        ));
    }
    Ok(Sip003SimpleObfsTlsRequest {
        record_type: header[0],
        record_version: [header[1], header[2]],
        handshake_version,
        server_name,
        session_ticket_len: ticket.len(),
        inner_payload: ticket,
        client_hello_len: body.len() + 5,
    })
}

fn parse_sni_extension(input: &[u8]) -> Result<String, OutboundError> {
    let mut idx = 0;
    let list_len = take_u16(input, &mut idx)? as usize;
    ensure_available(input, idx, list_len)?;
    let name_type = take_u8(input, &mut idx)?;
    if name_type != 0 {
        return Err(OutboundError::BadShadowsocks(format!(
            "simple-obfs TLS SNI name type mismatch: {name_type}"
        )));
    }
    let name_len = take_u16(input, &mut idx)? as usize;
    ensure_available(input, idx, name_len)?;
    std::str::from_utf8(&input[idx..idx + name_len])
        .map(str::to_owned)
        .map_err(|err| OutboundError::BadShadowsocks(err.to_string()))
}

fn first_response_discard_prefix() -> [u8; SIMPLE_OBFS_TLS_FIRST_RESPONSE_DISCARD] {
    let mut prefix = [0_u8; SIMPLE_OBFS_TLS_FIRST_RESPONSE_DISCARD];
    prefix[..5].copy_from_slice(&[0x16, 0x03, 0x03, 0x00, 0x5b]);
    prefix[96..102].copy_from_slice(&[0x14, 0x03, 0x03, 0x00, 0x01, 0x01]);
    prefix[102..105].copy_from_slice(&[TLS_APPLICATION_DATA_RECORD, 0x03, 0x03]);
    prefix
}

fn checked_u16(value: usize, name: &str) -> Result<u16, OutboundError> {
    u16::try_from(value).map_err(|_| OutboundError::BadShadowsocks(format!("{name} exceeds u16")))
}

fn put_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn take_u8(input: &[u8], idx: &mut usize) -> Result<u8, OutboundError> {
    ensure_available(input, *idx, 1)?;
    let value = input[*idx];
    *idx += 1;
    Ok(value)
}

fn take_u16(input: &[u8], idx: &mut usize) -> Result<u16, OutboundError> {
    ensure_available(input, *idx, 2)?;
    let value = u16::from_be_bytes([input[*idx], input[*idx + 1]]);
    *idx += 2;
    Ok(value)
}

fn take_u24(input: &[u8], idx: &mut usize) -> Result<usize, OutboundError> {
    ensure_available(input, *idx, 3)?;
    let value = ((input[*idx] as usize) << 16)
        | ((input[*idx + 1] as usize) << 8)
        | input[*idx + 2] as usize;
    *idx += 3;
    Ok(value)
}

fn take_array_2(input: &[u8], idx: &mut usize) -> Result<[u8; 2], OutboundError> {
    ensure_available(input, *idx, 2)?;
    let value = [input[*idx], input[*idx + 1]];
    *idx += 2;
    Ok(value)
}

fn ensure_available(input: &[u8], idx: usize, len: usize) -> Result<(), OutboundError> {
    if idx.checked_add(len).is_some_and(|end| end <= input.len()) {
        Ok(())
    } else {
        Err(OutboundError::BadShadowsocks(
            "simple-obfs TLS client hello truncated".to_owned(),
        ))
    }
}
