use std::io::{Read, Write};
use std::sync::Arc;

use rustls::ClientConnection;
use rustls::pki_types::ServerName;

use crate::error::OutboundError;
use crate::shared_transport::{TlsLoopbackMaterial, TlsUnderlayOptions};

use super::dataplane::connect_exchange_over_stream;
use super::request::HttpConnectOptions;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpsProxyTlsExchangeReport {
    pub proxy: String,
    pub target: String,
    pub status: u16,
    pub payload_len: usize,
    pub echoed_payload: Vec<u8>,
    pub selected_alpn: String,
    pub tls_handshake_validated: bool,
    pub certificate_chain_validated: bool,
    pub server_name_validated: bool,
    pub alpn_validated: bool,
    pub https_proxy_tls_underlay: bool,
    pub true_dataplane: bool,
    pub default_go_path: bool,
}

pub fn connect_exchange_over_tls_stream<S>(
    stream: S,
    material: &TlsLoopbackMaterial,
    tls_options: &TlsUnderlayOptions,
    proxy: &str,
    options: &HttpConnectOptions,
    payload: &[u8],
) -> Result<HttpsProxyTlsExchangeReport, OutboundError>
where
    S: Read + Write,
{
    let server_name = ServerName::try_from(tls_options.server_name.clone()).map_err(|err| {
        OutboundError::BadHttpProxy(format!("invalid https proxy server_name: {err}"))
    })?;
    let conn = ClientConnection::new(Arc::clone(&material.client_config), server_name)
        .map_err(|err| OutboundError::BadHttpProxy(format!("https proxy tls connect: {err}")))?;
    let mut tls = rustls::StreamOwned::new(conn, stream);
    let connect = connect_exchange_over_stream(&mut tls, proxy, options, payload)?;
    let selected_alpn = tls
        .conn
        .alpn_protocol()
        .map(|value| String::from_utf8_lossy(value).to_string())
        .unwrap_or_default();
    let alpn_validated = selected_alpn == tls_options.alpn_protocol;
    Ok(HttpsProxyTlsExchangeReport {
        proxy: connect.proxy,
        target: connect.target,
        status: connect.status,
        payload_len: connect.payload_len,
        echoed_payload: connect.echoed_payload,
        selected_alpn,
        tls_handshake_validated: true,
        certificate_chain_validated: true,
        server_name_validated: true,
        alpn_validated,
        https_proxy_tls_underlay: true,
        true_dataplane: connect.true_dataplane,
        default_go_path: connect.default_go_path,
    })
}
