use std::io::{Read, Write};
use std::sync::Arc;

use rcgen::generate_simple_self_signed;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection};

use crate::error::OutboundError;

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
    pub client_config: Arc<ClientConfig>,
    pub server_config: Arc<ServerConfig>,
    pub certificate_der_len: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TlsUnderlayReport {
    pub true_dataplane: bool,
    pub rustls_underlay: bool,
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

pub fn tls_loopback_material(
    options: &TlsUnderlayOptions,
) -> Result<TlsLoopbackMaterial, OutboundError> {
    let certified = generate_simple_self_signed(vec![options.server_name.clone()])
        .map_err(|err| OutboundError::BadSharedTransport(format!("generate tls cert: {err}")))?;
    let cert_der = certified.cert.der().clone();
    let certificate_der_len = cert_der.len();
    let key_der =
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der()));

    let mut server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der)
        .map_err(|err| OutboundError::BadSharedTransport(format!("server tls config: {err}")))?;
    server_config.alpn_protocols = vec![options.alpn_protocol.as_bytes().to_vec()];

    let mut roots = RootCertStore::empty();
    roots
        .add(cert_der)
        .map_err(|err| OutboundError::BadSharedTransport(format!("client tls roots: {err}")))?;
    let mut client_config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_config.alpn_protocols = vec![options.alpn_protocol.as_bytes().to_vec()];

    Ok(TlsLoopbackMaterial {
        client_config: Arc::new(client_config),
        server_config: Arc::new(server_config),
        certificate_der_len,
    })
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
    let server_name = ServerName::try_from(options.server_name.clone()).map_err(|err| {
        OutboundError::BadSharedTransport(format!("invalid tls server_name: {err}"))
    })?;
    let conn = ClientConnection::new(Arc::clone(&material.client_config), server_name)
        .map_err(|err| OutboundError::BadSharedTransport(format!("client tls connect: {err}")))?;
    let mut tls = rustls::StreamOwned::new(conn, stream);
    tls.write_all(payload)
        .map_err(|err| OutboundError::BadSharedTransport(format!("tls client write: {err}")))?;
    tls.flush()
        .map_err(|err| OutboundError::BadSharedTransport(format!("tls client flush: {err}")))?;
    let mut echoed_payload = vec![0_u8; payload.len()];
    tls.read_exact(&mut echoed_payload)
        .map_err(|err| OutboundError::BadSharedTransport(format!("tls client read: {err}")))?;
    let selected_alpn = selected_alpn(tls.conn.alpn_protocol());
    let alpn_validated = selected_alpn == options.alpn_protocol;
    Ok(TlsUnderlayReport {
        true_dataplane: echoed_payload == payload,
        rustls_underlay: true,
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
    server_config: Arc<ServerConfig>,
    expected_payload_len: usize,
) -> Result<TlsServerObservation, OutboundError>
where
    S: Read + Write,
{
    let conn = ServerConnection::new(server_config)
        .map_err(|err| OutboundError::BadSharedTransport(format!("server tls accept: {err}")))?;
    let mut tls = rustls::StreamOwned::new(conn, stream);
    let mut payload = vec![0_u8; expected_payload_len];
    tls.read_exact(&mut payload)
        .map_err(|err| OutboundError::BadSharedTransport(format!("tls server read: {err}")))?;
    tls.write_all(&payload)
        .map_err(|err| OutboundError::BadSharedTransport(format!("tls server write: {err}")))?;
    tls.flush()
        .map_err(|err| OutboundError::BadSharedTransport(format!("tls server flush: {err}")))?;
    Ok(TlsServerObservation {
        selected_alpn: selected_alpn(tls.conn.alpn_protocol()),
        payload_len: payload.len(),
        echoed_payload: payload,
        tls_handshake_validated: true,
        payload_roundtrip_validated: true,
    })
}

fn selected_alpn(protocol: Option<&[u8]>) -> String {
    protocol
        .map(|value| String::from_utf8_lossy(value).to_string())
        .unwrap_or_default()
}
