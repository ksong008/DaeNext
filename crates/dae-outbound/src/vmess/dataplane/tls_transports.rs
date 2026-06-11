use std::io::{Cursor, Read, Write};
use std::sync::Arc;

use rustls::ClientConnection;
use rustls::pki_types::ServerName;

use crate::error::OutboundError;
use crate::shared_transport::{
    DEFAULT_WS_KEY, HttpUpgradeOptions, TlsLoopbackMaterial, TlsUnderlayOptions, WS_MASK_KEY,
    http_upgrade_request, read_http_head, read_websocket_binary_frame, validate_http_status,
    websocket_client_binary_frame, websocket_handshake_request,
};

use super::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VMessAeadWssTlsExchangeReport {
    pub proxy: String,
    pub target: String,
    pub ws_host: String,
    pub ws_path: String,
    pub uuid: String,
    pub cmd_key_hex: String,
    pub command: u8,
    pub security: u8,
    pub request_header_len: usize,
    pub request_chunk_len: usize,
    pub response_header_len: usize,
    pub response_chunk_len: usize,
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
    pub reality_rejected_for_vmess: bool,
    pub tls_fragment_deferred: bool,
    pub true_dataplane: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VMessAeadHttpsHttpUpgradeTlsExchangeReport {
    pub proxy: String,
    pub target: String,
    pub httpupgrade_host: String,
    pub httpupgrade_path: String,
    pub uuid: String,
    pub cmd_key_hex: String,
    pub command: u8,
    pub security: u8,
    pub request_header_len: usize,
    pub request_chunk_len: usize,
    pub response_header_len: usize,
    pub response_chunk_len: usize,
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
    pub reality_rejected_for_vmess: bool,
    pub tls_fragment_deferred: bool,
    pub true_dataplane: bool,
}

pub fn aead_tcp_exchange_over_wss_tls_stream<S>(
    stream: S,
    material: &TlsLoopbackMaterial,
    tls_options: &TlsUnderlayOptions,
    proxy: &str,
    uuid: &str,
    target: &str,
    ws_host: &str,
    ws_path: &str,
    payload: &[u8],
) -> Result<VMessAeadWssTlsExchangeReport, OutboundError>
where
    S: Read + Write,
{
    let mut tls = tls_client_stream(stream, material, tls_options, "VMess WSS")?;
    let ws_options = HttpUpgradeOptions::new(ws_host, ws_path);
    let handshake = websocket_handshake_request(&ws_options, DEFAULT_WS_KEY);
    tls.write_all(&handshake)
        .map_err(|err| OutboundError::BadVmess(err.to_string()))?;
    let response = read_http_head(&mut tls)?;
    validate_http_status(&response, 101)?;

    let packet = build_aead_request(uuid, target, VMessNetwork::Tcp, payload)?;
    let mut request_payload = Vec::with_capacity(packet.header.len() + packet.chunk.len());
    request_payload.extend_from_slice(&packet.header);
    request_payload.extend_from_slice(&packet.chunk);
    let request_frame = websocket_client_binary_frame(&request_payload, WS_MASK_KEY)?;
    tls.write_all(&request_frame)
        .map_err(|err| OutboundError::BadVmess(err.to_string()))?;

    let response_payload = read_websocket_binary_frame(&mut tls)?;
    let websocket_response_frame_len = response_payload.len();
    let mut response_cursor = Cursor::new(&response_payload);
    let (response_header_len, echoed_payload, response_chunk_len) =
        read_aead_response_header_and_chunk(&mut response_cursor, &packet.request)?;
    if response_cursor.position() as usize != response_payload.len() {
        return Err(OutboundError::BadVmess(format!(
            "VMess WSS response has trailing bytes: {}",
            response_payload.len() - response_cursor.position() as usize
        )));
    }
    if echoed_payload != payload {
        return Err(OutboundError::BadVmess(
            "VMess WSS payload response mismatch".to_owned(),
        ));
    }
    let selected_alpn = selected_alpn(tls.conn.alpn_protocol());
    let alpn_validated = selected_alpn == tls_options.alpn_protocol;

    Ok(VMessAeadWssTlsExchangeReport {
        proxy: proxy.to_owned(),
        target: target.to_owned(),
        ws_host: ws_options.host,
        ws_path: ws_options.path,
        uuid: normalize_vmess_uuid(uuid),
        cmd_key_hex: packet.request.cmd_key_hex,
        command: VMessNetwork::Tcp.byte(),
        security: VMESS_AEAD_SECURITY_AES_128_GCM,
        request_header_len: packet.header.len(),
        request_chunk_len: packet.chunk.len(),
        response_header_len,
        response_chunk_len,
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
        reality_rejected_for_vmess: true,
        tls_fragment_deferred: true,
        true_dataplane: true,
    })
}

pub fn aead_tcp_exchange_over_https_httpupgrade_tls_stream<S>(
    stream: S,
    material: &TlsLoopbackMaterial,
    tls_options: &TlsUnderlayOptions,
    proxy: &str,
    uuid: &str,
    target: &str,
    httpupgrade_host: &str,
    httpupgrade_path: &str,
    payload: &[u8],
) -> Result<VMessAeadHttpsHttpUpgradeTlsExchangeReport, OutboundError>
where
    S: Read + Write,
{
    let mut tls = tls_client_stream(stream, material, tls_options, "VMess HTTPS HTTPUpgrade")?;
    let upgrade_options = HttpUpgradeOptions::new(httpupgrade_host, httpupgrade_path);
    let upgrade_request = http_upgrade_request(&upgrade_options);
    tls.write_all(&upgrade_request)
        .map_err(|err| OutboundError::BadVmess(err.to_string()))?;
    let response = read_http_head(&mut tls)?;
    let httpupgrade_response_head_len = response.len();
    validate_http_status(&response, 101)?;

    let packet = build_aead_request(uuid, target, VMessNetwork::Tcp, payload)?;
    tls.write_all(&packet.header)
        .map_err(|err| OutboundError::BadVmess(err.to_string()))?;
    tls.write_all(&packet.chunk)
        .map_err(|err| OutboundError::BadVmess(err.to_string()))?;

    let (response_header_len, echoed_payload, response_chunk_len) =
        read_aead_response_header_and_chunk(&mut tls, &packet.request)?;
    if echoed_payload != payload {
        return Err(OutboundError::BadVmess(
            "VMess HTTPS HTTPUpgrade payload response mismatch".to_owned(),
        ));
    }
    let selected_alpn = selected_alpn(tls.conn.alpn_protocol());
    let alpn_validated = selected_alpn == tls_options.alpn_protocol;

    Ok(VMessAeadHttpsHttpUpgradeTlsExchangeReport {
        proxy: proxy.to_owned(),
        target: target.to_owned(),
        httpupgrade_host: upgrade_options.host,
        httpupgrade_path: upgrade_options.path,
        uuid: normalize_vmess_uuid(uuid),
        cmd_key_hex: packet.request.cmd_key_hex,
        command: VMessNetwork::Tcp.byte(),
        security: VMESS_AEAD_SECURITY_AES_128_GCM,
        request_header_len: packet.header.len(),
        request_chunk_len: packet.chunk.len(),
        response_header_len,
        response_chunk_len,
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
        reality_rejected_for_vmess: true,
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
        .map_err(|err| OutboundError::BadVmess(format!("invalid {label} server_name: {err}")))?;
    let conn = ClientConnection::new(Arc::clone(&material.client_config), server_name)
        .map_err(|err| OutboundError::BadVmess(format!("{label} tls connect: {err}")))?;
    Ok(rustls::StreamOwned::new(conn, stream))
}

fn selected_alpn(protocol: Option<&[u8]>) -> String {
    protocol
        .map(|value| String::from_utf8_lossy(value).to_string())
        .unwrap_or_default()
}
