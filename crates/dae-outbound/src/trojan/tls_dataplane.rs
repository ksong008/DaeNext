use std::io::{Read, Write};
use std::sync::Arc;

use rustls::ClientConnection;
use rustls::pki_types::ServerName;

use crate::error::OutboundError;
use crate::shared_transport::{TlsLoopbackMaterial, TlsUnderlayOptions};

use super::dataplane::tcp_exchange_over_stream;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrojanTlsTcpExchangeReport {
    pub proxy: String,
    pub target: String,
    pub password_sha224_hex: String,
    pub command: u8,
    pub payload_len: usize,
    pub echoed_payload: Vec<u8>,
    pub selected_alpn: String,
    pub tls_handshake_validated: bool,
    pub certificate_chain_validated: bool,
    pub server_name_validated: bool,
    pub alpn_validated: bool,
    pub trojan_tls_underlay: bool,
    pub true_dataplane: bool,
}

pub fn tcp_exchange_over_tls_stream<S>(
    stream: S,
    material: &TlsLoopbackMaterial,
    tls_options: &TlsUnderlayOptions,
    proxy: &str,
    password: &str,
    target: &str,
    payload: &[u8],
) -> Result<TrojanTlsTcpExchangeReport, OutboundError>
where
    S: Read + Write,
{
    let server_name = ServerName::try_from(tls_options.server_name.clone()).map_err(|err| {
        OutboundError::BadTrojan(format!("invalid trojan tls server_name: {err}"))
    })?;
    let conn = ClientConnection::new(Arc::clone(&material.client_config), server_name)
        .map_err(|err| OutboundError::BadTrojan(format!("trojan tls connect: {err}")))?;
    let mut tls = rustls::StreamOwned::new(conn, stream);
    let inner = tcp_exchange_over_stream(&mut tls, proxy, password, target, payload)?;
    let selected_alpn = tls
        .conn
        .alpn_protocol()
        .map(|value| String::from_utf8_lossy(value).to_string())
        .unwrap_or_default();
    let alpn_validated = selected_alpn == tls_options.alpn_protocol;
    Ok(TrojanTlsTcpExchangeReport {
        proxy: inner.proxy,
        target: inner.target,
        password_sha224_hex: inner.password_sha224_hex,
        command: inner.command,
        payload_len: inner.payload_len,
        echoed_payload: inner.echoed_payload,
        selected_alpn,
        tls_handshake_validated: true,
        certificate_chain_validated: true,
        server_name_validated: true,
        alpn_validated,
        trojan_tls_underlay: true,
        true_dataplane: inner.true_dataplane,
    })
}
