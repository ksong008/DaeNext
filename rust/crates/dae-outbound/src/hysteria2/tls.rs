use std::sync::{Arc, Mutex};
use std::time::Duration;

use quinn::crypto::rustls::{HandshakeData, QuicClientConfig, QuicServerConfig};
use rcgen::generate_simple_self_signed;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};

use crate::error::OutboundError;

use super::underlay::pin_sha256_matches_raw_cert;

pub const DEFAULT_HYSTERIA2_ALPN: &str = "h3";
pub const DEFAULT_HYSTERIA2_SERVER_NAME: &str = "localhost";
pub const DEFAULT_HYSTERIA2_KEEPALIVE_SECS: u64 = 10;
pub const DEFAULT_HYSTERIA2_MAX_IDLE_TIMEOUT_SECS: u64 = 30;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(super) struct RawCertVerifierState {
    pub(super) observed: bool,
    pub(super) configured_pin_sha256_normalized: String,
    pub(super) raw_cert_sha256_hex: String,
    pub(super) matched: bool,
    pub(super) cert_der_len: usize,
    pub(super) server_name: String,
}

#[derive(Debug)]
struct RecordingRawCertVerifier {
    provider: Arc<rustls::crypto::CryptoProvider>,
    configured_pin_sha256: String,
    state: Arc<Mutex<RawCertVerifierState>>,
}

impl RecordingRawCertVerifier {
    fn new(configured_pin_sha256: String, state: Arc<Mutex<RawCertVerifierState>>) -> Arc<Self> {
        Arc::new(Self {
            provider: Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
            configured_pin_sha256,
            state,
        })
    }
}

impl ServerCertVerifier for RecordingRawCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let check = pin_sha256_matches_raw_cert(&self.configured_pin_sha256, end_entity.as_ref());
        if let Ok(mut state) = self.state.lock() {
            state.observed = true;
            state.configured_pin_sha256_normalized = check.configured_pin_normal.clone();
            state.raw_cert_sha256_hex = check.raw_cert_sha256_hex.clone();
            state.matched = check.matched;
            state.cert_der_len = end_entity.as_ref().len();
            state.server_name = server_name.to_str().into_owned();
        }
        if !check.matched {
            return Err(rustls::Error::General(
                "hysteria2 pinSHA256 raw cert verification failed".to_owned(),
            ));
        }
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

pub(super) fn build_hysteria2_server_config(
    server_name: &str,
) -> Result<(quinn::ServerConfig, CertificateDer<'static>), OutboundError> {
    let certified = generate_simple_self_signed(vec![server_name.to_owned()])
        .map_err(|err| bad_tls(format!("generate Hysteria2 cert: {err}")))?;
    let cert_der = certified.cert.der().clone();
    let key_der =
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der()));
    let mut crypto =
        rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_no_client_auth()
            .with_single_cert(vec![cert_der.clone()], key_der)
            .map_err(|err| bad_tls(format!("Hysteria2 server cert config: {err}")))?;
    crypto.alpn_protocols = vec![DEFAULT_HYSTERIA2_ALPN.as_bytes().to_vec()];
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(
        QuicServerConfig::try_from(crypto)
            .map_err(|err| bad_tls(format!("Hysteria2 server QUIC TLS: {err}")))?,
    ));
    config.transport_config(Arc::new(hysteria2_transport_config()?));
    Ok((config, cert_der))
}

pub(super) fn build_hysteria2_client_config(
    configured_pin_sha256: String,
    verifier_state: Arc<Mutex<RawCertVerifierState>>,
) -> Result<quinn::ClientConfig, OutboundError> {
    let mut crypto =
        rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .dangerous()
            .with_custom_certificate_verifier(RecordingRawCertVerifier::new(
                configured_pin_sha256,
                verifier_state,
            ))
            .with_no_client_auth();
    crypto.alpn_protocols = vec![DEFAULT_HYSTERIA2_ALPN.as_bytes().to_vec()];
    let mut config = quinn::ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(crypto)
            .map_err(|err| bad_tls(format!("Hysteria2 client QUIC TLS: {err}")))?,
    ));
    config.transport_config(Arc::new(hysteria2_transport_config()?));
    Ok(config)
}

pub(super) fn selected_alpn(connection: &quinn::Connection) -> String {
    connection
        .handshake_data()
        .and_then(|data| data.downcast::<HandshakeData>().ok())
        .and_then(|data| data.protocol.clone())
        .map(|protocol| String::from_utf8_lossy(&protocol).to_string())
        .unwrap_or_default()
}

fn hysteria2_transport_config() -> Result<quinn::TransportConfig, OutboundError> {
    let mut transport = quinn::TransportConfig::default();
    transport.keep_alive_interval(Some(Duration::from_secs(DEFAULT_HYSTERIA2_KEEPALIVE_SECS)));
    transport.max_idle_timeout(Some(
        Duration::from_secs(DEFAULT_HYSTERIA2_MAX_IDLE_TIMEOUT_SECS)
            .try_into()
            .map_err(|err| bad_tls(format!("Hysteria2 idle timeout config: {err}")))?,
    ));
    transport.datagram_receive_buffer_size(Some(64 * 1024));
    transport.datagram_send_buffer_size(64 * 1024);
    Ok(transport)
}

fn bad_tls(message: impl Into<String>) -> OutboundError {
    OutboundError::BadHysteria2(message.into())
}
