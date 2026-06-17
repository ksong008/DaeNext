use std::io::{Cursor, Read, Write};
use std::sync::Arc;

use rustls::ClientConnection;
use rustls::pki_types::ServerName;

use crate::error::OutboundError;
use crate::shadowsocks::{self, AeadTcpSalts};
use crate::shared_transport::{
    DEFAULT_WS_KEY, HttpUpgradeOptions, TlsLoopbackMaterial, TlsUnderlayOptions, WS_MASK_KEY,
    read_http_head, read_websocket_binary_frame, validate_http_status,
    websocket_client_binary_frame, websocket_handshake_request, websocket_server_binary_frame,
};

use super::inner_shadowsocks_dataplane::{
    TrojanGoInnerShadowsocksRequest, encode_inner_shadowsocks_response,
    read_inner_shadowsocks_trojan_request_from_stream,
};
use super::metadata::{TrojanMetadata, TrojanNetwork};
use super::packet;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrojanGoWssInnerShadowsocksTcpExchangeReport {
    pub proxy: String,
    pub target: String,
    pub ws_host: String,
    pub ws_path: String,
    pub cipher: String,
    pub client_salt_len: usize,
    pub server_salt_len: usize,
    pub response_metadata: String,
    pub password_sha224_hex: String,
    pub command: u8,
    pub payload_len: usize,
    pub echoed_payload: Vec<u8>,
    pub selected_alpn: String,
    pub websocket_request_frame_len: usize,
    pub websocket_response_payload_len: usize,
    pub tls_handshake_validated: bool,
    pub certificate_chain_validated: bool,
    pub server_name_validated: bool,
    pub alpn_validated: bool,
    pub websocket_handshake_validated: bool,
    pub websocket_binary_frame_validated: bool,
    pub inner_shadowsocks_validated: bool,
    pub trojan_wss_inner_shadowsocks: bool,
    pub true_dataplane: bool,
}

// Trojan-Go transport dataplane tests keep layered protocol inputs explicit.
#[allow(clippy::too_many_arguments)]
pub fn tcp_exchange_over_wss_inner_shadowsocks_stream<S>(
    stream: S,
    material: &TlsLoopbackMaterial,
    tls_options: &TlsUnderlayOptions,
    proxy: &str,
    cipher: &str,
    shadowsocks_password: &str,
    trojan_password: &str,
    target: &str,
    _response_metadata_target: &str,
    ws_host: &str,
    ws_path: &str,
    payload: &[u8],
    salts: AeadTcpSalts<'_>,
) -> Result<TrojanGoWssInnerShadowsocksTcpExchangeReport, OutboundError>
where
    S: Read + Write,
{
    let spec = shadowsocks::cipher_spec(cipher)?;
    let server_name = ServerName::try_from(tls_options.server_name.clone()).map_err(|err| {
        OutboundError::BadTrojan(format!(
            "invalid trojan-go wss inner shadowsocks server_name: {err}"
        ))
    })?;
    let conn =
        ClientConnection::new(Arc::clone(&material.client_config), server_name).map_err(|err| {
            OutboundError::BadTrojan(format!("trojan-go wss inner shadowsocks tls: {err}"))
        })?;
    let mut tls = rustls::StreamOwned::new(conn, stream);

    let ws_options = HttpUpgradeOptions::new(ws_host, ws_path);
    let handshake = websocket_handshake_request(&ws_options, DEFAULT_WS_KEY);
    tls.write_all(&handshake)
        .map_err(|err| OutboundError::BadTrojan(err.to_string()))?;
    let response = read_http_head(&mut tls)?;
    validate_http_status(&response, 101)?;

    let target = TrojanMetadata::parse("tcp", target)?.authority();
    let request_frame = trojan_wss_inner_shadowsocks_request_frame(
        cipher,
        shadowsocks_password,
        trojan_password,
        &target,
        payload,
        salts.client,
    )?;
    tls.write_all(&request_frame)
        .map_err(|err| OutboundError::BadTrojan(err.to_string()))?;

    let response_payload = read_websocket_binary_frame(&mut tls)?;
    let mut cursor = Cursor::new(response_payload);
    let mut server_salt = vec![0_u8; spec.salt_len];
    cursor
        .read_exact(&mut server_salt)
        .map_err(|err| OutboundError::BadTrojan(err.to_string()))?;
    if server_salt != salts.server {
        return Err(OutboundError::BadTrojan(
            "trojan-go wss inner shadowsocks server salt mismatch".to_owned(),
        ));
    }
    let mut decoder =
        shadowsocks::AeadStreamCodec::new(cipher, shadowsocks_password, &server_salt)?;
    let echoed_payload = shadowsocks::read_encrypted_chunk_from_stream(&mut cursor, &mut decoder)?;
    if echoed_payload != payload {
        return Err(OutboundError::BadTrojan(
            "trojan-go wss inner shadowsocks payload mismatch".to_owned(),
        ));
    }

    let selected_alpn = tls
        .conn
        .alpn_protocol()
        .map(|value| String::from_utf8_lossy(value).to_string())
        .unwrap_or_default();
    let alpn_validated = selected_alpn == tls_options.alpn_protocol;

    Ok(TrojanGoWssInnerShadowsocksTcpExchangeReport {
        proxy: proxy.to_owned(),
        target,
        ws_host: ws_options.host,
        ws_path: ws_options.path,
        cipher: spec.cipher.to_owned(),
        client_salt_len: salts.client.len(),
        server_salt_len: server_salt.len(),
        response_metadata: String::new(),
        password_sha224_hex: packet::password_sha224_hex(trojan_password),
        command: TrojanNetwork::Tcp.byte(),
        payload_len: payload.len(),
        echoed_payload,
        selected_alpn,
        websocket_request_frame_len: request_frame.len(),
        websocket_response_payload_len: cursor.into_inner().len(),
        tls_handshake_validated: true,
        certificate_chain_validated: true,
        server_name_validated: true,
        alpn_validated,
        websocket_handshake_validated: true,
        websocket_binary_frame_validated: true,
        inner_shadowsocks_validated: true,
        trojan_wss_inner_shadowsocks: true,
        true_dataplane: true,
    })
}

pub fn trojan_wss_inner_shadowsocks_request_frame(
    cipher: &str,
    shadowsocks_password: &str,
    trojan_password: &str,
    target: &str,
    payload: &[u8],
    client_salt: &[u8],
) -> Result<Vec<u8>, OutboundError> {
    let request = packet::tcp_request_header(trojan_password, "tcp", target, payload)?;
    let shadowsocks_request =
        shadowsocks::encode_client_initial(cipher, shadowsocks_password, client_salt, &request)?;
    websocket_client_binary_frame(&shadowsocks_request, WS_MASK_KEY)
}

pub fn trojan_wss_inner_shadowsocks_response_frame(
    cipher: &str,
    shadowsocks_password: &str,
    salt: &[u8],
    _response_metadata_target: &str,
    payload: &[u8],
) -> Result<Vec<u8>, OutboundError> {
    let response =
        encode_inner_shadowsocks_response(cipher, shadowsocks_password, salt, "", payload)?;
    websocket_server_binary_frame(&response)
}

pub fn read_inner_shadowsocks_trojan_request_from_websocket_stream<S>(
    stream: &mut S,
    cipher: &str,
    shadowsocks_password: &str,
    payload_len: usize,
) -> Result<TrojanGoInnerShadowsocksRequest, OutboundError>
where
    S: Read,
{
    let payload = read_websocket_binary_frame(stream)?;
    let mut cursor = Cursor::new(payload);
    let request = read_inner_shadowsocks_trojan_request_from_stream(
        &mut cursor,
        cipher,
        shadowsocks_password,
        payload_len,
    )?;
    if cursor.position() as usize != cursor.get_ref().len() {
        return Err(OutboundError::BadTrojan(format!(
            "trojan-go wss inner shadowsocks request has trailing bytes: {}",
            cursor.get_ref().len() - cursor.position() as usize
        )));
    }
    Ok(request)
}
