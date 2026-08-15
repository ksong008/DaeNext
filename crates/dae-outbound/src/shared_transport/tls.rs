use std::io::{Read, Write};
use std::sync::Arc;

use boring::ssl::{SslAcceptor, SslConnector, SslStream};

use crate::error::OutboundError;
use crate::shared_transport::test_support::{
    connect_tls_stream, selected_tls_alpn, self_signed_tls_identity, tls13_acceptor,
    tls13_connector,
};

pub const DEFAULT_TLS_SERVER_NAME: &str = "shared-tls.fixture.invalid";
pub const DEFAULT_TLS_ALPN: &str = "http/1.1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TlsUnderlayOptions {
    pub server_name: String,
    pub alpn_protocol: String,
    pub allow_insecure: bool,
}

impl TlsUnderlayOptions {
    pub fn new(
        server_name: impl Into<String>,
        alpn_protocol: impl Into<String>,
    ) -> Result<Self, OutboundError> {
        let server_name = server_name.into();
        let alpn_protocol = alpn_protocol.into();
        if server_name.trim().is_empty() {
            return Err(OutboundError::BadSharedTransport(
                "tls server_name must not be empty".to_owned(),
            ));
        }
        if alpn_protocol.trim().is_empty() {
            return Err(OutboundError::BadSharedTransport(
                "tls alpn_protocol must not be empty".to_owned(),
            ));
        }
        Ok(Self {
            server_name,
            alpn_protocol,
            allow_insecure: false,
        })
    }
}

pub struct TlsLoopbackMaterial {
    pub client_connector: Arc<SslConnector>,
    pub server_acceptor: Arc<SslAcceptor>,
    pub certificate_der_len: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TlsUnderlayReport {
    pub true_dataplane: bool,
    pub boringssl_underlay: bool,
    pub server_name: String,
    pub alpn_protocol: String,
    pub selected_alpn: String,
    pub payload_len: usize,
    pub echoed_payload: Vec<u8>,
    pub tls_handshake_validated: bool,
    pub certificate_chain_validated: bool,
    pub server_name_validated: bool,
    pub alpn_validated: bool,
    pub allow_insecure: bool,
    pub full_utls_deferred: bool,
    pub reality_deferred: bool,
    pub tls_fragment_deferred: bool,
    pub passthrough_udp_deferred: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TlsServerObservation {
    pub selected_alpn: String,
    pub payload_len: usize,
    pub echoed_payload: Vec<u8>,
    pub tls_handshake_validated: bool,
    pub payload_roundtrip_validated: bool,
}

#[cfg(any(test, feature = "test-support"))]
pub fn tls_loopback_material(
    options: &TlsUnderlayOptions,
) -> Result<TlsLoopbackMaterial, OutboundError> {
    let identity = self_signed_tls_identity(&[options.server_name.as_str()])?;
    let certificate_der_len = identity.certificate_der()?.len();
    let alpn = vec![options.alpn_protocol.as_bytes().to_vec()];

    Ok(TlsLoopbackMaterial {
        client_connector: Arc::new(tls13_connector(&identity, &alpn)?),
        server_acceptor: Arc::new(tls13_acceptor(&identity, &alpn)?),
        certificate_der_len,
    })
}

impl TlsLoopbackMaterial {
    pub fn connect<S>(&self, stream: S, server_name: &str) -> Result<SslStream<S>, OutboundError>
    where
        S: Read + Write,
    {
        connect_tls_stream(&self.client_connector, server_name, stream)
    }
}

pub fn tls_client_echo_exchange<S>(
    stream: S,
    material: &TlsLoopbackMaterial,
    options: &TlsUnderlayOptions,
    payload: &[u8],
) -> Result<TlsUnderlayReport, OutboundError>
where
    S: Read + Write,
{
    let mut tls = material.connect(stream, &options.server_name)?;
    tls.write_all(payload)
        .map_err(|err| OutboundError::BadSharedTransport(format!("tls client write: {err}")))?;
    tls.flush()
        .map_err(|err| OutboundError::BadSharedTransport(format!("tls client flush: {err}")))?;
    let mut echoed_payload = vec![0_u8; payload.len()];
    tls.read_exact(&mut echoed_payload)
        .map_err(|err| OutboundError::BadSharedTransport(format!("tls client read: {err}")))?;
    let selected_alpn = selected_tls_alpn(tls.ssl());
    let alpn_validated = selected_alpn == options.alpn_protocol;
    Ok(TlsUnderlayReport {
        true_dataplane: echoed_payload == payload,
        boringssl_underlay: true,
        server_name: options.server_name.clone(),
        alpn_protocol: options.alpn_protocol.clone(),
        selected_alpn,
        payload_len: payload.len(),
        echoed_payload,
        tls_handshake_validated: true,
        certificate_chain_validated: true,
        server_name_validated: true,
        alpn_validated,
        allow_insecure: options.allow_insecure,
        full_utls_deferred: true,
        reality_deferred: true,
        tls_fragment_deferred: true,
        passthrough_udp_deferred: true,
    })
}

pub fn tls_server_echo<S>(
    stream: S,
    server_acceptor: Arc<SslAcceptor>,
    expected_payload_len: usize,
) -> Result<TlsServerObservation, OutboundError>
where
    S: Read + Write,
{
    let mut tls = server_acceptor
        .accept(stream)
        .map_err(|err| OutboundError::BadSharedTransport(format!("server tls accept: {err}")))?;
    let mut payload = vec![0_u8; expected_payload_len];
    tls.read_exact(&mut payload)
        .map_err(|err| OutboundError::BadSharedTransport(format!("tls server read: {err}")))?;
    tls.write_all(&payload)
        .map_err(|err| OutboundError::BadSharedTransport(format!("tls server write: {err}")))?;
    tls.flush()
        .map_err(|err| OutboundError::BadSharedTransport(format!("tls server flush: {err}")))?;
    Ok(TlsServerObservation {
        selected_alpn: selected_tls_alpn(tls.ssl()),
        payload_len: payload.len(),
        echoed_payload: payload,
        tls_handshake_validated: true,
        payload_roundtrip_validated: true,
    })
}
