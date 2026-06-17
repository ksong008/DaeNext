use std::io::{Cursor, Read, Write};

use crate::error::OutboundError;
use crate::shadowsocks::{self, AeadTcpSalts};

use super::dataplane::{TrojanTcpRequest, read_tcp_request_from_stream};
use super::metadata::{TrojanMetadata, TrojanNetwork};
use super::packet;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrojanGoInnerShadowsocksTcpExchangeReport {
    pub proxy: String,
    pub target: String,
    pub cipher: String,
    pub client_salt_len: usize,
    pub server_salt_len: usize,
    pub inner_shadowsocks_is_client: bool,
    pub inner_shadowsocks_request_metadata_present: bool,
    pub server_response_metadata: String,
    pub password_sha224_hex: String,
    pub command: u8,
    pub trojan_request_header_len: usize,
    pub shadowsocks_request_len: usize,
    pub shadowsocks_response_metadata_len: usize,
    pub payload_len: usize,
    pub echoed_payload: Vec<u8>,
    pub shadowsocks_chunk_validated: bool,
    pub trojan_inner_shadowsocks: bool,
    pub true_dataplane: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrojanGoInnerShadowsocksRequest {
    pub request: TrojanTcpRequest,
    pub cipher: String,
    pub client_salt_len: usize,
    pub encrypted_chunk_validated: bool,
    pub inner_shadowsocks_is_client: bool,
    pub inner_shadowsocks_request_metadata_present: bool,
}

// Trojan-Go transport dataplane tests keep layered protocol inputs explicit.
#[allow(clippy::too_many_arguments)]
pub fn tcp_exchange_over_inner_shadowsocks_stream<S>(
    stream: &mut S,
    proxy: &str,
    cipher: &str,
    shadowsocks_password: &str,
    trojan_password: &str,
    target: &str,
    _response_metadata_target: &str,
    payload: &[u8],
    salts: AeadTcpSalts<'_>,
) -> Result<TrojanGoInnerShadowsocksTcpExchangeReport, OutboundError>
where
    S: Read + Write,
{
    let spec = shadowsocks::cipher_spec(cipher)?;
    if salts.server.len() != spec.salt_len {
        return Err(OutboundError::BadTrojan(format!(
            "inner shadowsocks server salt length must be {}, got {}",
            spec.salt_len,
            salts.server.len()
        )));
    }
    let metadata = TrojanMetadata::parse("tcp", target)?;
    let target = metadata.authority();
    let request = packet::tcp_request_header(trojan_password, "tcp", &target, payload)?;
    let trojan_request_header_len = request.len().saturating_sub(payload.len());
    let shadowsocks_request =
        shadowsocks::encode_client_initial(cipher, shadowsocks_password, salts.client, &request)?;
    stream
        .write_all(&shadowsocks_request)
        .map_err(|err| OutboundError::BadTrojan(err.to_string()))?;

    let mut server_salt = vec![0_u8; spec.salt_len];
    stream
        .read_exact(&mut server_salt)
        .map_err(|err| OutboundError::BadTrojan(err.to_string()))?;
    if server_salt != salts.server {
        return Err(OutboundError::BadTrojan(
            "trojan-go inner shadowsocks server salt mismatch".to_owned(),
        ));
    }
    let mut decoder =
        shadowsocks::AeadStreamCodec::new(cipher, shadowsocks_password, &server_salt)?;
    let echoed_payload = shadowsocks::read_encrypted_chunk_from_stream(stream, &mut decoder)?;
    if echoed_payload != payload {
        return Err(OutboundError::BadTrojan(
            "trojan-go inner shadowsocks payload response mismatch".to_owned(),
        ));
    }

    Ok(TrojanGoInnerShadowsocksTcpExchangeReport {
        proxy: proxy.to_owned(),
        target,
        cipher: spec.cipher.to_owned(),
        client_salt_len: salts.client.len(),
        server_salt_len: server_salt.len(),
        inner_shadowsocks_is_client: false,
        inner_shadowsocks_request_metadata_present: false,
        server_response_metadata: String::new(),
        password_sha224_hex: packet::password_sha224_hex(trojan_password),
        command: TrojanNetwork::Tcp.byte(),
        trojan_request_header_len,
        shadowsocks_request_len: shadowsocks_request.len(),
        shadowsocks_response_metadata_len: 0,
        payload_len: payload.len(),
        echoed_payload,
        shadowsocks_chunk_validated: true,
        trojan_inner_shadowsocks: true,
        true_dataplane: true,
    })
}

pub fn read_inner_shadowsocks_trojan_request_from_stream<S>(
    stream: &mut S,
    cipher: &str,
    shadowsocks_password: &str,
    payload_len: usize,
) -> Result<TrojanGoInnerShadowsocksRequest, OutboundError>
where
    S: Read,
{
    let spec = shadowsocks::cipher_spec(cipher)?;
    let mut client_salt = vec![0_u8; spec.salt_len];
    stream
        .read_exact(&mut client_salt)
        .map_err(|err| OutboundError::BadTrojan(err.to_string()))?;
    let mut decoder =
        shadowsocks::AeadStreamCodec::new(cipher, shadowsocks_password, &client_salt)?;
    let plain = shadowsocks::read_encrypted_chunk_from_stream(stream, &mut decoder)?;
    let mut cursor = Cursor::new(&plain);
    let request = read_tcp_request_from_stream(&mut cursor, payload_len)?;
    if cursor.position() as usize != plain.len() {
        return Err(OutboundError::BadTrojan(format!(
            "trojan-go inner shadowsocks request has trailing bytes: {}",
            plain.len() - cursor.position() as usize
        )));
    }
    Ok(TrojanGoInnerShadowsocksRequest {
        request,
        cipher: spec.cipher.to_owned(),
        client_salt_len: client_salt.len(),
        encrypted_chunk_validated: true,
        inner_shadowsocks_is_client: false,
        inner_shadowsocks_request_metadata_present: false,
    })
}

pub fn encode_inner_shadowsocks_response(
    cipher: &str,
    shadowsocks_password: &str,
    salt: &[u8],
    _response_metadata_target: &str,
    payload: &[u8],
) -> Result<Vec<u8>, OutboundError> {
    let mut codec = shadowsocks::AeadStreamCodec::new(cipher, shadowsocks_password, salt)?;
    let mut out = Vec::with_capacity(salt.len() + payload.len() + 2 + shadowsocks::TAG_LEN * 2);
    out.extend_from_slice(salt);
    out.extend_from_slice(&codec.encrypt_chunk(payload)?);
    Ok(out)
}
