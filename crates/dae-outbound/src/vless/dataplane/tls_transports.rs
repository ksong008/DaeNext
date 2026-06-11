use std::io::{Read, Write};
use std::sync::Arc;

use rustls::ClientConnection;
use rustls::pki_types::ServerName;

use crate::error::OutboundError;
use crate::shared_transport::{
    DEFAULT_WS_KEY, HttpUpgradeOptions, TlsLoopbackMaterial, TlsUnderlayOptions, WS_MASK_KEY,
    http_upgrade_request, read_http_head, read_websocket_binary_frame, validate_http_status,
    websocket_client_binary_frame, websocket_handshake_request,
};
use crate::vmess::VMessNetwork;

use super::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VlessWssTlsExchangeReport {
    pub proxy: String,
    pub target: String,
    pub ws_host: String,
    pub ws_path: String,
    pub key_hex: String,
    pub command: u8,
    pub request_header_len: usize,
    pub response_header_len: usize,
    pub websocket_request_frame_len: usize,
    pub websocket_response_frame_len: usize,
    pub selected_alpn: String,
    pub payload_len: usize,
    pub echoed_payload: Vec<u8>,
    pub tls_handshake_validated: bool,
    pub certificate_chain_validated: bool,
    pub server_name_validated: bool,
    pub alpn_validated: bool,
    pub websocket_handshake_validated: bool,
    pub websocket_binary_frame_validated: bool,
    pub rustls_tls_lifecycle: bool,
    pub full_utls_deferred: bool,
    pub reality_deferred: bool,
    pub tls_fragment_deferred: bool,
    pub true_dataplane: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VlessHttpsHttpUpgradeTlsExchangeReport {
    pub proxy: String,
    pub target: String,
    pub httpupgrade_host: String,
    pub httpupgrade_path: String,
    pub key_hex: String,
    pub command: u8,
    pub request_header_len: usize,
    pub response_header_len: usize,
    pub httpupgrade_request_len: usize,
    pub httpupgrade_response_head_len: usize,
    pub selected_alpn: String,
    pub payload_len: usize,
    pub echoed_payload: Vec<u8>,
    pub tls_handshake_validated: bool,
    pub certificate_chain_validated: bool,
    pub server_name_validated: bool,
    pub alpn_validated: bool,
    pub httpupgrade_handshake_validated: bool,
    pub rustls_tls_lifecycle: bool,
    pub full_utls_deferred: bool,
    pub reality_deferred: bool,
    pub tls_fragment_deferred: bool,
    pub true_dataplane: bool,
}

pub fn tcp_exchange_over_wss_tls_stream<S>(
    stream: S,
    material: &TlsLoopbackMaterial,
    tls_options: &TlsUnderlayOptions,
    proxy: &str,
    key: &[u8; 16],
    target: &str,
    ws_host: &str,
    ws_path: &str,
    payload: &[u8],
) -> Result<VlessWssTlsExchangeReport, OutboundError>
where
    S: Read + Write,
{
    let mut tls = tls_client_stream(stream, material, tls_options, "VLESS WSS")?;
    let ws_options = HttpUpgradeOptions::new(ws_host, ws_path);
    let handshake = websocket_handshake_request(&ws_options, DEFAULT_WS_KEY);
    tls.write_all(&handshake)
        .map_err(|err| OutboundError::BadVless(err.to_string()))?;
    let response = read_http_head(&mut tls)?;
    validate_http_status(&response, 101)?;

    let request = packet::first_write_bytes(key, "", "tcp", target, false, payload)?;
    let request_header_len = request.len().saturating_sub(payload.len());
    let request_frame = websocket_client_binary_frame(&request, WS_MASK_KEY)?;
    tls.write_all(&request_frame)
        .map_err(|err| OutboundError::BadVless(err.to_string()))?;

    let response_payload = read_websocket_binary_frame(&mut tls)?;
    let websocket_response_frame_len = response_payload.len();
    let (response_header_len, echoed_payload) = decode_response_payload(&response_payload)?;
    if echoed_payload != payload {
        return Err(OutboundError::BadVless(
            "VLESS WSS payload response mismatch".to_owned(),
        ));
    }
    let selected_alpn = selected_alpn(tls.conn.alpn_protocol());
    let alpn_validated = selected_alpn == tls_options.alpn_protocol;

    Ok(VlessWssTlsExchangeReport {
        proxy: proxy.to_owned(),
        target: target.to_owned(),
        ws_host: ws_options.host,
        ws_path: ws_options.path,
        key_hex: hex_encode(key),
        command: VMessNetwork::Tcp.byte(),
        request_header_len,
        response_header_len,
        websocket_request_frame_len: request_frame.len(),
        websocket_response_frame_len,
        selected_alpn,
        payload_len: payload.len(),
        echoed_payload,
        tls_handshake_validated: true,
        certificate_chain_validated: true,
        server_name_validated: true,
        alpn_validated,
        websocket_handshake_validated: true,
        websocket_binary_frame_validated: true,
        rustls_tls_lifecycle: true,
        full_utls_deferred: true,
        reality_deferred: true,
        tls_fragment_deferred: true,
        true_dataplane: true,
    })
}

pub fn tcp_exchange_over_https_httpupgrade_tls_stream<S>(
    stream: S,
    material: &TlsLoopbackMaterial,
    tls_options: &TlsUnderlayOptions,
    proxy: &str,
    key: &[u8; 16],
    target: &str,
    httpupgrade_host: &str,
    httpupgrade_path: &str,
    payload: &[u8],
) -> Result<VlessHttpsHttpUpgradeTlsExchangeReport, OutboundError>
where
    S: Read + Write,
{
    let mut tls = tls_client_stream(stream, material, tls_options, "VLESS HTTPS HTTPUpgrade")?;
    let upgrade_options = HttpUpgradeOptions::new(httpupgrade_host, httpupgrade_path);
    let upgrade_request = http_upgrade_request(&upgrade_options);
    tls.write_all(&upgrade_request)
        .map_err(|err| OutboundError::BadVless(err.to_string()))?;
    let response = read_http_head(&mut tls)?;
    let httpupgrade_response_head_len = response.len();
    validate_http_status(&response, 101)?;

    let request = packet::first_write_bytes(key, "", "tcp", target, false, payload)?;
    let request_header_len = request.len().saturating_sub(payload.len());
    tls.write_all(&request)
        .map_err(|err| OutboundError::BadVless(err.to_string()))?;
    let (response_header_len, echoed_payload) =
        read_tcp_response_payload_from_stream(&mut tls, payload.len())?;
    if echoed_payload != payload {
        return Err(OutboundError::BadVless(
            "VLESS HTTPS HTTPUpgrade payload response mismatch".to_owned(),
        ));
    }
    let selected_alpn = selected_alpn(tls.conn.alpn_protocol());
    let alpn_validated = selected_alpn == tls_options.alpn_protocol;

    Ok(VlessHttpsHttpUpgradeTlsExchangeReport {
        proxy: proxy.to_owned(),
        target: target.to_owned(),
        httpupgrade_host: upgrade_options.host,
        httpupgrade_path: upgrade_options.path,
        key_hex: hex_encode(key),
        command: VMessNetwork::Tcp.byte(),
        request_header_len,
        response_header_len,
        httpupgrade_request_len: upgrade_request.len(),
        httpupgrade_response_head_len,
        selected_alpn,
        payload_len: payload.len(),
        echoed_payload,
        tls_handshake_validated: true,
        certificate_chain_validated: true,
        server_name_validated: true,
        alpn_validated,
        httpupgrade_handshake_validated: true,
        rustls_tls_lifecycle: true,
        full_utls_deferred: true,
        reality_deferred: true,
        tls_fragment_deferred: true,
        true_dataplane: true,
    })
}

fn tls_client_stream<S>(
    stream: S,
    material: &TlsLoopbackMaterial,
    tls_options: &TlsUnderlayOptions,
    label: &str,
) -> Result<rustls::StreamOwned<ClientConnection, S>, OutboundError>
where
    S: Read + Write,
{
    let server_name = ServerName::try_from(tls_options.server_name.clone())
        .map_err(|err| OutboundError::BadVless(format!("invalid {label} server_name: {err}")))?;
    let conn = ClientConnection::new(Arc::clone(&material.client_config), server_name)
        .map_err(|err| OutboundError::BadVless(format!("{label} tls connect: {err}")))?;
    Ok(rustls::StreamOwned::new(conn, stream))
}

fn selected_alpn(protocol: Option<&[u8]>) -> String {
    protocol
        .map(|value| String::from_utf8_lossy(value).to_string())
        .unwrap_or_default()
}
