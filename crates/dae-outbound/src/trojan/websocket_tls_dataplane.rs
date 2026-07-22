use std::io::{Cursor, Read, Write};
use std::sync::Arc;

use rustls::ClientConnection;
use rustls::pki_types::ServerName;

use crate::error::OutboundError;
use crate::shared_transport::{
    DEFAULT_WS_KEY, HttpUpgradeOptions, TlsLoopbackMaterial, TlsUnderlayOptions, WS_MASK_KEY,
    read_http_head, read_websocket_binary_frame, websocket_client_binary_frame,
    websocket_handshake_request,
};

use super::dataplane::{TrojanTcpRequest, read_tcp_request_from_stream};
use super::metadata::{TrojanMetadata, TrojanNetwork};
use super::packet;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrojanGoWssTcpExchangeReport {
    pub proxy: String,
    pub target: String,
    pub ws_host: String,
    pub ws_path: String,
    pub password_sha224_hex: String,
    pub command: u8,
    pub payload_len: usize,
    pub echoed_payload: Vec<u8>,
    pub selected_alpn: String,
    pub websocket_request_frame_len: usize,
    pub websocket_response_frame_len: usize,
    pub tls_handshake_validated: bool,
    pub certificate_chain_validated: bool,
    pub server_name_validated: bool,
    pub alpn_validated: bool,
    pub websocket_handshake_validated: bool,
    pub websocket_binary_frame_validated: bool,
    pub trojan_wss: bool,
    pub true_dataplane: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrojanWebSocketRequest {
    pub request: TrojanTcpRequest,
    pub websocket_request_frame_len: usize,
}

// Trojan-Go transport dataplane tests keep layered protocol inputs explicit.
#[allow(clippy::too_many_arguments)]
pub fn tcp_exchange_over_wss_stream<S>(
    stream: S,
    material: &TlsLoopbackMaterial,
    tls_options: &TlsUnderlayOptions,
    proxy: &str,
    password: &str,
    target: &str,
    ws_host: &str,
    ws_path: &str,
    payload: &[u8],
) -> Result<TrojanGoWssTcpExchangeReport, OutboundError>
where
    S: Read + Write,
{
    let server_name = ServerName::try_from(tls_options.server_name.clone()).map_err(|err| {
        OutboundError::BadTrojan(format!("invalid trojan-go wss server_name: {err}"))
    })?;
    let conn = ClientConnection::new(Arc::clone(&material.client_config), server_name)
        .map_err(|err| OutboundError::BadTrojan(format!("trojan-go wss tls connect: {err}")))?;
    let mut tls = rustls::StreamOwned::new(conn, stream);

    let ws_options = HttpUpgradeOptions::new(ws_host, ws_path);
    let handshake = websocket_handshake_request(&ws_options, DEFAULT_WS_KEY);
    tls.write_all(&handshake)
        .map_err(|err| OutboundError::BadTrojan(err.to_string()))?;
    let response = read_http_head(&mut tls)?;
    crate::shared_transport::validate_websocket_handshake_response(
        &response,
        crate::shared_transport::WS_ACCEPT_SAMPLE,
    )?;

    let metadata = TrojanMetadata::parse("tcp", target)?;
    let target = metadata.authority();
    let request = packet::tcp_request_header(password, "tcp", &target, payload)?;
    let request_frame = websocket_client_binary_frame(&request, WS_MASK_KEY)?;
    tls.write_all(&request_frame)
        .map_err(|err| OutboundError::BadTrojan(err.to_string()))?;

    let response_payload = read_websocket_binary_frame(&mut tls)?;
    let websocket_response_frame_len = response_payload.len();
    if response_payload != payload {
        return Err(OutboundError::BadTrojan(
            "trojan-go wss payload response mismatch".to_owned(),
        ));
    }

    let selected_alpn = tls
        .conn
        .alpn_protocol()
        .map(|value| String::from_utf8_lossy(value).to_string())
        .unwrap_or_default();
    let alpn_validated = selected_alpn == tls_options.alpn_protocol;

    Ok(TrojanGoWssTcpExchangeReport {
        proxy: proxy.to_owned(),
        target,
        ws_host: ws_options.host,
        ws_path: ws_options.path,
        password_sha224_hex: packet::password_sha224_hex(password),
        command: TrojanNetwork::Tcp.byte(),
        payload_len: payload.len(),
        echoed_payload: response_payload,
        selected_alpn,
        websocket_request_frame_len: request_frame.len(),
        websocket_response_frame_len,
        tls_handshake_validated: true,
        certificate_chain_validated: true,
        server_name_validated: true,
        alpn_validated,
        websocket_handshake_validated: true,
        websocket_binary_frame_validated: true,
        trojan_wss: true,
        true_dataplane: true,
    })
}

pub fn read_tcp_request_from_websocket_stream<S>(
    stream: &mut S,
    payload_len: usize,
) -> Result<TrojanWebSocketRequest, OutboundError>
where
    S: Read,
{
    let payload = read_websocket_binary_frame(stream)?;
    let websocket_request_frame_len = payload.len();
    let mut cursor = Cursor::new(payload);
    let request = read_tcp_request_from_stream(&mut cursor, payload_len)?;
    if cursor.position() as usize != websocket_request_frame_len {
        return Err(OutboundError::BadTrojan(format!(
            "trojan-go websocket request has trailing bytes: {}",
            websocket_request_frame_len - cursor.position() as usize
        )));
    }
    Ok(TrojanWebSocketRequest {
        request,
        websocket_request_frame_len,
    })
}
