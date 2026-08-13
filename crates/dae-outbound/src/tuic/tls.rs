use std::sync::Arc;
use std::time::Duration;

use quinn::crypto::rustls::{HandshakeData, QuicClientConfig, QuicServerConfig};
use rcgen::generate_simple_self_signed;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};

use crate::error::OutboundError;

pub const DEFAULT_TUIC_ALPN: &str = "h3";
pub const DEFAULT_TUIC_SERVER_NAME: &str = "localhost";
pub const DEFAULT_TUIC_KEEPALIVE_SECS: u64 = 3;
pub const DEFAULT_TUIC_HANDSHAKE_IDLE_TIMEOUT_SECS: u64 = 8;
pub const DEFAULT_TUIC_INITIAL_STREAM_RECEIVE_WINDOW: u64 = 2 * 1024 * 1024;
pub const DEFAULT_TUIC_MAX_STREAM_RECEIVE_WINDOW: u64 = 32 * 1024 * 1024;
pub const DEFAULT_TUIC_INITIAL_CONNECTION_RECEIVE_WINDOW: u64 = 32 * 1024 * 1024;
pub const DEFAULT_TUIC_MAX_CONNECTION_RECEIVE_WINDOW: u64 = 64 * 1024 * 1024;
pub const DEFAULT_TUIC_MAX_UDP_RELAY_PACKET_SIZE: usize = 1400;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TuicCongestionController {
    Bbr,
    Cubic,
    NewReno,
}

impl TuicCongestionController {
    pub fn from_config(value: &str) -> Result<Self, OutboundError> {
        match value.trim().to_ascii_lowercase().as_str() {
            "" | "bbr" => Ok(Self::Bbr),
            "cubic" => Ok(Self::Cubic),
            "new_reno" | "new-reno" | "reno" => Ok(Self::NewReno),
            _ => Err(bad_tls(
                "TUIC congestion controller is not supported by the resident QUIC executor",
            )),
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bbr => "bbr",
            Self::Cubic => "cubic",
            Self::NewReno => "new_reno",
        }
    }
}

#[derive(Debug)]
struct AcceptAnyServerCertVerifier {
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl AcceptAnyServerCertVerifier {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            provider: Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
        })
    }
}

impl ServerCertVerifier for AcceptAnyServerCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

pub(super) fn build_tuic_server_config(
    server_name: &str,
    alpn: &[String],
) -> Result<quinn::ServerConfig, OutboundError> {
    let certified = generate_simple_self_signed(vec![server_name.to_owned()])
        .map_err(|err| bad_tls(format!("generate TUIC cert: {err}")))?;
    let cert_der = certified.cert.der().clone();
    let key_der =
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der()));
    let mut crypto =
        rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .map_err(|err| bad_tls(format!("TUIC server cert config: {err}")))?;
    crypto.alpn_protocols = alpn_protocols(alpn);
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(
        QuicServerConfig::try_from(crypto)
            .map_err(|err| bad_tls(format!("TUIC server QUIC TLS: {err}")))?,
    ));
    config.transport_config(Arc::new(tuic_transport_config(None)?));
    Ok(config)
}

pub(super) fn build_tuic_client_config(
    alpn: &[String],
    allow_insecure: bool,
) -> Result<quinn::ClientConfig, OutboundError> {
    build_tuic_client_config_with_congestion(alpn, allow_insecure, TuicCongestionController::Bbr)
}

pub(super) fn build_tuic_client_config_with_congestion(
    alpn: &[String],
    allow_insecure: bool,
    congestion: TuicCongestionController,
) -> Result<quinn::ClientConfig, OutboundError> {
    let mut crypto = if allow_insecure {
        rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .dangerous()
            .with_custom_certificate_verifier(AcceptAnyServerCertVerifier::new())
            .with_no_client_auth()
    } else {
        let roots = crate::shared_transport::system_ca_snapshot()
            .map_err(|err| bad_tls(format!("load TUIC system CA bundle: {err}")))?
            .rustls_roots();
        rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_root_certificates(roots)
            .with_no_client_auth()
    };
    crypto.alpn_protocols = alpn_protocols(alpn);
    let mut config = quinn::ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(crypto)
            .map_err(|err| bad_tls(format!("TUIC client QUIC TLS: {err}")))?,
    ));
    config.transport_config(Arc::new(tuic_transport_config(Some(congestion))?));
    Ok(config)
}

pub(super) fn normalize_alpn(alpn: &[String]) -> Vec<String> {
    if alpn.is_empty() {
        vec![DEFAULT_TUIC_ALPN.to_owned()]
    } else {
        alpn.to_vec()
    }
}

pub(super) fn selected_alpn(connection: &quinn::Connection) -> String {
    connection
        .handshake_data()
        .and_then(|data| data.downcast::<HandshakeData>().ok())
        .and_then(|data| data.protocol.clone())
        .map(|protocol| String::from_utf8_lossy(&protocol).to_string())
        .unwrap_or_default()
}

fn alpn_protocols(alpn: &[String]) -> Vec<Vec<u8>> {
    normalize_alpn(alpn)
        .into_iter()
        .map(|protocol| protocol.into_bytes())
        .collect()
}

fn tuic_transport_config(
    congestion: Option<TuicCongestionController>,
) -> Result<quinn::TransportConfig, OutboundError> {
    let mut transport = quinn::TransportConfig::default();
    if let Some(congestion) = congestion {
        match congestion {
            TuicCongestionController::Bbr => transport
                .congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default())),
            TuicCongestionController::Cubic => transport
                .congestion_controller_factory(Arc::new(quinn::congestion::CubicConfig::default())),
            TuicCongestionController::NewReno => transport.congestion_controller_factory(Arc::new(
                quinn::congestion::NewRenoConfig::default(),
            )),
        };
    }
    transport.keep_alive_interval(Some(Duration::from_secs(DEFAULT_TUIC_KEEPALIVE_SECS)));
    transport.max_idle_timeout(Some(
        Duration::from_secs(DEFAULT_TUIC_HANDSHAKE_IDLE_TIMEOUT_SECS)
            .try_into()
            .map_err(|err| bad_tls(format!("TUIC idle timeout config: {err}")))?,
    ));
    transport.datagram_receive_buffer_size(Some(64 * 1024));
    transport.datagram_send_buffer_size(64 * 1024);
    Ok(transport)
}

fn bad_tls(message: impl Into<String>) -> OutboundError {
    OutboundError::BadTuic(message.into())
}
