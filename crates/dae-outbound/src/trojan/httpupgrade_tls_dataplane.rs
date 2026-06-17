use std::io::{Read, Write};
use std::sync::Arc;

use rustls::ClientConnection;
use rustls::pki_types::ServerName;

use crate::error::OutboundError;
use crate::shared_transport::{
    HttpUpgradeOptions, TlsLoopbackMaterial, TlsUnderlayOptions, http_upgrade_request,
    read_http_head, validate_http_status,
};

use super::metadata::{TrojanMetadata, TrojanNetwork};
use super::packet;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrojanGoHttpUpgradeTcpExchangeReport {
    pub proxy: String,
    pub target: String,
    pub httpupgrade_host: String,
    pub httpupgrade_path: String,
    pub password_sha224_hex: String,
    pub command: u8,
    pub payload_len: usize,
    pub echoed_payload: Vec<u8>,
    pub selected_alpn: String,
    pub httpupgrade_request_len: usize,
    pub tls_handshake_validated: bool,
    pub certificate_chain_validated: bool,
    pub server_name_validated: bool,
    pub alpn_validated: bool,
    pub httpupgrade_handshake_validated: bool,
    pub trojan_httpupgrade: bool,
    pub true_dataplane: bool,
}

// Trojan-Go transport dataplane tests keep layered protocol inputs explicit.
#[allow(clippy::too_many_arguments)]
pub fn tcp_exchange_over_httpupgrade_tls_stream<S>(
    stream: S,
    material: &TlsLoopbackMaterial,
    tls_options: &TlsUnderlayOptions,
    proxy: &str,
    password: &str,
    target: &str,
    httpupgrade_host: &str,
    httpupgrade_path: &str,
    payload: &[u8],
) -> Result<TrojanGoHttpUpgradeTcpExchangeReport, OutboundError>
where
    S: Read + Write,
{
    let server_name = ServerName::try_from(tls_options.server_name.clone()).map_err(|err| {
        OutboundError::BadTrojan(format!(
            "invalid trojan-go httpupgrade tls server_name: {err}"
        ))
    })?;
    let conn =
        ClientConnection::new(Arc::clone(&material.client_config), server_name).map_err(|err| {
            OutboundError::BadTrojan(format!("trojan-go httpupgrade tls connect: {err}"))
        })?;
    let mut tls = rustls::StreamOwned::new(conn, stream);

    let upgrade_options = HttpUpgradeOptions::new(httpupgrade_host, httpupgrade_path);
    let upgrade_request = http_upgrade_request(&upgrade_options);
    tls.write_all(&upgrade_request)
        .map_err(|err| OutboundError::BadTrojan(err.to_string()))?;
    let response = read_http_head(&mut tls)?;
    validate_http_status(&response, 101)?;

    let metadata = TrojanMetadata::parse("tcp", target)?;
    let target = metadata.authority();
    let request = packet::tcp_request_header(password, "tcp", &target, payload)?;
    tls.write_all(&request)
        .map_err(|err| OutboundError::BadTrojan(err.to_string()))?;

    let mut echoed_payload = vec![0_u8; payload.len()];
    tls.read_exact(&mut echoed_payload)
        .map_err(|err| OutboundError::BadTrojan(err.to_string()))?;
    if echoed_payload != payload {
        return Err(OutboundError::BadTrojan(
            "trojan-go httpupgrade payload response mismatch".to_owned(),
        ));
    }

    let selected_alpn = tls
        .conn
        .alpn_protocol()
        .map(|value| String::from_utf8_lossy(value).to_string())
        .unwrap_or_default();
    let alpn_validated = selected_alpn == tls_options.alpn_protocol;

    Ok(TrojanGoHttpUpgradeTcpExchangeReport {
        proxy: proxy.to_owned(),
        target,
        httpupgrade_host: upgrade_options.host,
        httpupgrade_path: upgrade_options.path,
        password_sha224_hex: packet::password_sha224_hex(password),
        command: TrojanNetwork::Tcp.byte(),
        payload_len: payload.len(),
        echoed_payload,
        selected_alpn,
        httpupgrade_request_len: upgrade_request.len(),
        tls_handshake_validated: true,
        certificate_chain_validated: true,
        server_name_validated: true,
        alpn_validated,
        httpupgrade_handshake_validated: true,
        trojan_httpupgrade: true,
        true_dataplane: true,
    })
}
