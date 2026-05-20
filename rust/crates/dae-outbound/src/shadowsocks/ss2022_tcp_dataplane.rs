use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use chacha20poly1305::ChaCha20Poly1305;

use crate::error::OutboundError;
use crate::socks5::Socks5Address;

use super::ss2022::{
    CipherConf2022, HEADER_TYPE_CLIENT_STREAM, HEADER_TYPE_SERVER_STREAM, MAX_PADDING_LENGTH,
    TCP_CHUNK_MAX_LEN, cipher_conf, validate_base64_psk,
};

const SESSION_SUBKEY_CONTEXT: &str = "shadowsocks 2022 session subkey";
const IDENTITY_SUBKEY_CONTEXT: &str = "shadowsocks 2022 identity subkey";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ss2022TcpSalts<'a> {
    pub client: &'a [u8],
    pub server: &'a [u8],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ss2022TcpExchangeReport {
    pub server: String,
    pub target: String,
    pub cipher: String,
    pub psk_count: usize,
    pub upsk_index: usize,
    pub key_len: usize,
    pub client_salt_len: usize,
    pub server_salt_len: usize,
    pub request_header_type: u8,
    pub response_header_type: u8,
    pub fixed_header_len: usize,
    pub variable_header_len: usize,
    pub target_metadata_len: usize,
    pub request_salt_echo_validated: bool,
    pub payload_len: usize,
    pub echoed_payload: Vec<u8>,
    pub multi_psk_identity_header_dataplane_admitted: bool,
    pub ss2022_udp_true_dataplane_admitted: bool,
    pub true_dataplane: bool,
    pub default_go_path: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ss2022TcpClientRequest {
    pub target: String,
    pub request_salt_len: usize,
    pub psk_count: usize,
    pub upsk_index: usize,
    pub request_header_type: u8,
    pub timestamp: u64,
    pub fixed_header_len: usize,
    pub variable_header_len: usize,
    pub target_metadata_len: usize,
    pub padding_len: usize,
    pub payload: Vec<u8>,
}

pub fn tcp_exchange(
    server: &str,
    cipher: &str,
    password: &str,
    target: &str,
    payload: &[u8],
    salts: Ss2022TcpSalts<'_>,
    timeout: Duration,
) -> Result<Ss2022TcpExchangeReport, OutboundError> {
    let mut stream =
        TcpStream::connect(server).map_err(|err| OutboundError::BadShadowsocks(err.to_string()))?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|err| OutboundError::BadShadowsocks(err.to_string()))?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|err| OutboundError::BadShadowsocks(err.to_string()))?;

    tcp_exchange_over_stream(
        &mut stream,
        server,
        cipher,
        password,
        target,
        payload,
        salts,
    )
}

pub fn tcp_exchange_over_stream<S>(
    stream: &mut S,
    server: &str,
    cipher: &str,
    password: &str,
    target: &str,
    payload: &[u8],
    salts: Ss2022TcpSalts<'_>,
) -> Result<Ss2022TcpExchangeReport, OutboundError>
where
    S: Read + Write,
{
    let conf = require_cipher_conf(cipher)?;
    validate_salt_len("client", salts.client, conf.salt_len)?;
    validate_salt_len("server", salts.server, conf.salt_len)?;
    let psk = parse_single_psk(password, conf.key_len)?;
    let target_addr = Socks5Address::parse(target)?;
    let target_metadata_len = target_addr.encode()?.len();
    let initial_payload_len = payload
        .len()
        .min(TCP_CHUNK_MAX_LEN.saturating_sub(target_metadata_len + 2));
    let variable_header_len =
        target_metadata_len + 2 + if payload.is_empty() { 1 } else { 0 } + initial_payload_len;
    let request = encode_client_initial_with_timestamp(
        &conf,
        &psk,
        salts.client,
        &target_addr,
        payload,
        unix_timestamp_now(),
    )?;

    stream
        .write_all(&request)
        .map_err(|err| OutboundError::BadShadowsocks(err.to_string()))?;
    let response = read_server_stream(stream, &conf, &psk, salts.client)?;

    Ok(Ss2022TcpExchangeReport {
        server: server.to_owned(),
        target: target_addr.authority(),
        cipher: conf.cipher.to_owned(),
        psk_count: 1,
        upsk_index: 0,
        key_len: conf.key_len,
        client_salt_len: salts.client.len(),
        server_salt_len: response.server_salt_len,
        request_header_type: HEADER_TYPE_CLIENT_STREAM,
        response_header_type: response.response_header_type,
        fixed_header_len: 11,
        variable_header_len,
        target_metadata_len,
        request_salt_echo_validated: response.request_salt_echo_validated,
        payload_len: payload.len(),
        echoed_payload: response.payload,
        multi_psk_identity_header_dataplane_admitted: false,
        ss2022_udp_true_dataplane_admitted: false,
        true_dataplane: true,
        default_go_path: true,
    })
}

pub fn encode_client_initial(
    cipher: &str,
    password: &str,
    salt: &[u8],
    target: &str,
    payload: &[u8],
    timestamp: u64,
) -> Result<Vec<u8>, OutboundError> {
    let conf = require_cipher_conf(cipher)?;
    validate_salt_len("client", salt, conf.salt_len)?;
    let psk = parse_single_psk(password, conf.key_len)?;
    let target_addr = Socks5Address::parse(target)?;
    encode_client_initial_with_timestamp(&conf, &psk, salt, &target_addr, payload, timestamp)
}

pub fn read_client_request_from_stream<S>(
    stream: &mut S,
    cipher: &str,
    password: &str,
    expected_payload_len: usize,
) -> Result<Ss2022TcpClientRequest, OutboundError>
where
    S: Read,
{
    let conf = require_cipher_conf(cipher)?;
    let psk = parse_single_psk(password, conf.key_len)?;
    let mut request_salt = vec![0_u8; conf.salt_len];
    stream
        .read_exact(&mut request_salt)
        .map_err(|err| OutboundError::BadShadowsocks(err.to_string()))?;
    decode_client_request_after_salt(stream, &conf, &psk, &request_salt, expected_payload_len)
}

pub fn encode_server_response(
    cipher: &str,
    password: &str,
    server_salt: &[u8],
    request_salt: &[u8],
    payload: &[u8],
    timestamp: u64,
) -> Result<Vec<u8>, OutboundError> {
    let conf = require_cipher_conf(cipher)?;
    validate_salt_len("server", server_salt, conf.salt_len)?;
    validate_salt_len("request", request_salt, conf.salt_len)?;
    if payload.is_empty() {
        return Err(OutboundError::BadShadowsocks(
            "SS2022 server stream payload cannot be empty".to_owned(),
        ));
    }
    let psk = parse_single_psk(password, conf.key_len)?;
    let mut codec = Ss2022StreamCodec::new(&conf, &psk, server_salt)?;
    let mut header = Vec::with_capacity(11 + request_salt.len());
    header.push(HEADER_TYPE_SERVER_STREAM);
    header.extend_from_slice(&timestamp.to_be_bytes());
    header.extend_from_slice(request_salt);
    header.extend_from_slice(&(payload.len() as u16).to_be_bytes());

    let mut out = Vec::with_capacity(server_salt.len() + header.len() + payload.len() + 32);
    out.extend_from_slice(server_salt);
    out.extend_from_slice(&codec.encrypt_next(&header)?);
    out.extend_from_slice(&codec.encrypt_next(payload)?);
    Ok(out)
}

pub fn decode_client_request(
    cipher: &str,
    password: &str,
    input: &[u8],
    expected_payload_len: usize,
) -> Result<Ss2022TcpClientRequest, OutboundError> {
    let conf = require_cipher_conf(cipher)?;
    let psk = parse_single_psk(password, conf.key_len)?;
    if input.len() < conf.salt_len {
        return Err(OutboundError::BadShadowsocks(
            "SS2022 client request missing salt".to_owned(),
        ));
    }
    let (salt, encrypted) = input.split_at(conf.salt_len);
    decode_client_request_after_salt(
        &mut std::io::Cursor::new(encrypted),
        &conf,
        &psk,
        salt,
        expected_payload_len,
    )
}

fn encode_client_initial_with_timestamp(
    conf: &CipherConf2022,
    psk: &[u8],
    salt: &[u8],
    target: &Socks5Address,
    payload: &[u8],
    timestamp: u64,
) -> Result<Vec<u8>, OutboundError> {
    let mut var_header = target.encode()?;
    let padding_len = if payload.is_empty() { 1 } else { 0 };
    var_header.extend_from_slice(&(padding_len as u16).to_be_bytes());
    if padding_len > 0 {
        var_header.push(0);
    }
    let initial_payload_len = payload
        .len()
        .min(TCP_CHUNK_MAX_LEN.saturating_sub(var_header.len()));
    var_header.extend_from_slice(&payload[..initial_payload_len]);
    if var_header.len() > TCP_CHUNK_MAX_LEN {
        return Err(OutboundError::BadShadowsocks(format!(
            "SS2022 initial variable header too large: {}",
            var_header.len()
        )));
    }

    let mut fixed_header = Vec::with_capacity(11);
    fixed_header.push(HEADER_TYPE_CLIENT_STREAM);
    fixed_header.extend_from_slice(&timestamp.to_be_bytes());
    fixed_header.extend_from_slice(&(var_header.len() as u16).to_be_bytes());

    let mut codec = Ss2022StreamCodec::new(conf, psk, salt)?;
    let mut out = Vec::with_capacity(salt.len() + fixed_header.len() + var_header.len() + 32);
    out.extend_from_slice(salt);
    out.extend_from_slice(&codec.encrypt_next(&fixed_header)?);
    out.extend_from_slice(&codec.encrypt_next(&var_header)?);
    for chunk in payload[initial_payload_len..].chunks(TCP_CHUNK_MAX_LEN) {
        out.extend_from_slice(&codec.encrypt_next(&(chunk.len() as u16).to_be_bytes())?);
        out.extend_from_slice(&codec.encrypt_next(chunk)?);
    }
    Ok(out)
}

fn decode_client_request_after_salt<S>(
    stream: &mut S,
    conf: &CipherConf2022,
    psk: &[u8],
    request_salt: &[u8],
    expected_payload_len: usize,
) -> Result<Ss2022TcpClientRequest, OutboundError>
where
    S: Read,
{
    let mut codec = Ss2022StreamCodec::new(conf, psk, request_salt)?;
    let fixed_header = read_encrypted_exact(stream, &mut codec, 11)?;
    if fixed_header.len() != 11 {
        return Err(OutboundError::BadShadowsocks(
            "SS2022 fixed header length mismatch".to_owned(),
        ));
    }
    let request_header_type = fixed_header[0];
    if request_header_type != HEADER_TYPE_CLIENT_STREAM {
        return Err(OutboundError::BadShadowsocks(format!(
            "SS2022 unexpected client header type: {request_header_type}"
        )));
    }
    let timestamp = u64::from_be_bytes([
        fixed_header[1],
        fixed_header[2],
        fixed_header[3],
        fixed_header[4],
        fixed_header[5],
        fixed_header[6],
        fixed_header[7],
        fixed_header[8],
    ]);
    let var_header_len = u16::from_be_bytes([fixed_header[9], fixed_header[10]]) as usize;
    let var_header = read_encrypted_exact(stream, &mut codec, var_header_len)?;
    let (target, consumed) = Socks5Address::decode(&var_header)?;
    if var_header.len() < consumed + 2 {
        return Err(OutboundError::BadShadowsocks(
            "SS2022 variable header missing padding length".to_owned(),
        ));
    }
    let padding_len = u16::from_be_bytes([var_header[consumed], var_header[consumed + 1]]) as usize;
    if padding_len > MAX_PADDING_LENGTH {
        return Err(OutboundError::BadShadowsocks(format!(
            "SS2022 padding too large: {padding_len}"
        )));
    }
    let payload_offset = consumed + 2 + padding_len;
    if var_header.len() < payload_offset {
        return Err(OutboundError::BadShadowsocks(
            "SS2022 variable header padding overflows".to_owned(),
        ));
    }
    let mut payload = var_header[payload_offset..].to_vec();
    while payload.len() < expected_payload_len {
        let len_plain = read_encrypted_exact(stream, &mut codec, 2)?;
        let chunk_len = u16::from_be_bytes([len_plain[0], len_plain[1]]) as usize;
        let chunk = read_encrypted_exact(stream, &mut codec, chunk_len)?;
        payload.extend_from_slice(&chunk);
    }

    Ok(Ss2022TcpClientRequest {
        target: target.authority(),
        request_salt_len: request_salt.len(),
        psk_count: 1,
        upsk_index: 0,
        request_header_type,
        timestamp,
        fixed_header_len: fixed_header.len(),
        variable_header_len: var_header_len,
        target_metadata_len: consumed,
        padding_len,
        payload,
    })
}

#[derive(Debug)]
struct Ss2022ServerResponse {
    server_salt_len: usize,
    response_header_type: u8,
    request_salt_echo_validated: bool,
    payload: Vec<u8>,
}

fn read_server_stream<S>(
    stream: &mut S,
    conf: &CipherConf2022,
    psk: &[u8],
    request_salt: &[u8],
) -> Result<Ss2022ServerResponse, OutboundError>
where
    S: Read,
{
    let mut server_salt = vec![0_u8; conf.salt_len];
    stream
        .read_exact(&mut server_salt)
        .map_err(|err| OutboundError::BadShadowsocks(err.to_string()))?;
    let mut codec = Ss2022StreamCodec::new(conf, psk, &server_salt)?;
    let header_len = 1 + 8 + conf.salt_len + 2;
    let header = read_encrypted_exact(stream, &mut codec, header_len)?;
    let response_header_type = header[0];
    if response_header_type != HEADER_TYPE_SERVER_STREAM {
        return Err(OutboundError::BadShadowsocks(format!(
            "SS2022 unexpected server header type: {response_header_type}"
        )));
    }
    let salt_start = 1 + 8;
    let salt_end = salt_start + conf.salt_len;
    let echoed_salt = &header[salt_start..salt_end];
    let payload_len = u16::from_be_bytes([header[salt_end], header[salt_end + 1]]) as usize;
    if payload_len == 0 {
        return Err(OutboundError::BadShadowsocks(
            "SS2022 server payload length cannot be zero".to_owned(),
        ));
    }
    let payload = read_encrypted_exact(stream, &mut codec, payload_len)?;
    Ok(Ss2022ServerResponse {
        server_salt_len: server_salt.len(),
        response_header_type,
        request_salt_echo_validated: echoed_salt == request_salt,
        payload,
    })
}

fn read_encrypted_exact<S>(
    stream: &mut S,
    codec: &mut Ss2022StreamCodec,
    plaintext_len: usize,
) -> Result<Vec<u8>, OutboundError>
where
    S: Read,
{
    let mut encrypted = vec![0_u8; plaintext_len + codec.tag_len];
    stream
        .read_exact(&mut encrypted)
        .map_err(|err| OutboundError::BadShadowsocks(err.to_string()))?;
    codec.decrypt_next(&encrypted)
}

struct Ss2022StreamCodec {
    cipher: Ss2022AeadCipher,
    nonce: Vec<u8>,
    tag_len: usize,
}

impl Ss2022StreamCodec {
    fn new(conf: &CipherConf2022, psk: &[u8], salt: &[u8]) -> Result<Self, OutboundError> {
        let subkey = derive_subkey(psk, salt, conf.key_len, SESSION_SUBKEY_CONTEXT);
        Ok(Self {
            cipher: Ss2022AeadCipher::new(conf.cipher, &subkey)?,
            nonce: vec![0_u8; conf.nonce_len],
            tag_len: conf.tag_len,
        })
    }

    fn encrypt_next(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, OutboundError> {
        let encrypted = self.cipher.encrypt(&self.nonce, plaintext)?;
        increment_nonce_le(&mut self.nonce);
        Ok(encrypted)
    }

    fn decrypt_next(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, OutboundError> {
        let plain = self.cipher.decrypt(&self.nonce, ciphertext)?;
        increment_nonce_le(&mut self.nonce);
        Ok(plain)
    }
}

enum Ss2022AeadCipher {
    Aes128(Box<Aes128Gcm>),
    Aes256(Box<Aes256Gcm>),
    ChaCha(Box<ChaCha20Poly1305>),
}

impl Ss2022AeadCipher {
    fn new(cipher: &str, key: &[u8]) -> Result<Self, OutboundError> {
        match cipher {
            "2022-blake3-aes-128-gcm" => Ok(Self::Aes128(Box::new(
                Aes128Gcm::new_from_slice(key).map_err(|_| {
                    OutboundError::BadShadowsocks("bad SS2022 aes-128 key".to_owned())
                })?,
            ))),
            "2022-blake3-aes-256-gcm" => Ok(Self::Aes256(Box::new(
                Aes256Gcm::new_from_slice(key).map_err(|_| {
                    OutboundError::BadShadowsocks("bad SS2022 aes-256 key".to_owned())
                })?,
            ))),
            "2022-blake3-chacha20-poly1305" => Ok(Self::ChaCha(Box::new(
                ChaCha20Poly1305::new_from_slice(key).map_err(|_| {
                    OutboundError::BadShadowsocks("bad SS2022 chacha key".to_owned())
                })?,
            ))),
            _ => Err(OutboundError::BadShadowsocks(format!(
                "unsupported SS2022 cipher: {cipher}"
            ))),
        }
    }

    fn encrypt(&self, nonce: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, OutboundError> {
        match self {
            Self::Aes128(cipher) => cipher
                .encrypt(aes_gcm::Nonce::from_slice(nonce), plaintext)
                .map_err(|_| OutboundError::BadShadowsocks("SS2022 encrypt failed".to_owned())),
            Self::Aes256(cipher) => cipher
                .encrypt(aes_gcm::Nonce::from_slice(nonce), plaintext)
                .map_err(|_| OutboundError::BadShadowsocks("SS2022 encrypt failed".to_owned())),
            Self::ChaCha(cipher) => cipher
                .encrypt(chacha20poly1305::Nonce::from_slice(nonce), plaintext)
                .map_err(|_| OutboundError::BadShadowsocks("SS2022 encrypt failed".to_owned())),
        }
    }

    fn decrypt(&self, nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, OutboundError> {
        match self {
            Self::Aes128(cipher) => cipher
                .decrypt(aes_gcm::Nonce::from_slice(nonce), ciphertext)
                .map_err(|_| OutboundError::BadShadowsocks("SS2022 decrypt failed".to_owned())),
            Self::Aes256(cipher) => cipher
                .decrypt(aes_gcm::Nonce::from_slice(nonce), ciphertext)
                .map_err(|_| OutboundError::BadShadowsocks("SS2022 decrypt failed".to_owned())),
            Self::ChaCha(cipher) => cipher
                .decrypt(chacha20poly1305::Nonce::from_slice(nonce), ciphertext)
                .map_err(|_| OutboundError::BadShadowsocks("SS2022 decrypt failed".to_owned())),
        }
    }
}

fn require_cipher_conf(cipher: &str) -> Result<CipherConf2022, OutboundError> {
    cipher_conf(cipher).ok_or_else(|| {
        OutboundError::BadShadowsocks(format!("unsupported shadowsocks 2022 cipher: {cipher}"))
    })
}

fn parse_single_psk(password: &str, key_len: usize) -> Result<Vec<u8>, OutboundError> {
    let parts = password.split(':').collect::<Vec<_>>();
    if parts.len() != 1 {
        return Err(OutboundError::BadShadowsocks(
            "Stage 88 SS2022 TCP dataplane admits single PSK only; multi-PSK identity header remains gated".to_owned(),
        ));
    }
    validate_base64_psk(parts[0], key_len)
}

fn derive_subkey(psk: &[u8], salt: &[u8], key_len: usize, context: &str) -> Vec<u8> {
    let mut key_material = Vec::with_capacity(psk.len() + salt.len());
    key_material.extend_from_slice(psk);
    key_material.extend_from_slice(salt);
    let derived = blake3::derive_key(context, &key_material);
    derived[..key_len].to_vec()
}

fn increment_nonce_le(nonce: &mut [u8]) {
    for byte in nonce {
        let (next, overflow) = byte.overflowing_add(1);
        *byte = next;
        if !overflow {
            break;
        }
    }
}

fn validate_salt_len(name: &str, salt: &[u8], want: usize) -> Result<(), OutboundError> {
    if salt.len() != want {
        return Err(OutboundError::BadShadowsocks(format!(
            "SS2022 {name} salt length must be {want}, got {}",
            salt.len()
        )));
    }
    Ok(())
}

fn unix_timestamp_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[allow(dead_code)]
fn _identity_context_marker() -> &'static str {
    IDENTITY_SUBKEY_CONTEXT
}
