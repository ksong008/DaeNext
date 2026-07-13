use std::sync::Arc;

use quinn::crypto::rustls::QuicClientConfig;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, RootCertStore, SignatureScheme};

use super::*;

pub(super) fn build_connect_udp_h3_client_config(
    proxy: &ResidentProxyPlan,
    runtime: ResidentConnectUdpRuntimePlan,
) -> Result<quinn::ClientConfig, String> {
    if proxy.tls != "quic"
        || proxy.alpn.as_slice() != ["h3"]
        || proxy.tls_fragment.is_some()
        || proxy.utls_fingerprint.is_some()
        || proxy.reality.is_some()
        || proxy.mptcp
    {
        return Err(
            "CONNECT-UDP H3 requires the explicit QUIC TLS + ALPN h3 source contract".to_owned(),
        );
    }
    let mut crypto = if proxy.allow_insecure {
        rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .dangerous()
            .with_custom_certificate_verifier(AcceptAnyConnectUdpH3Verifier::new())
            .with_no_client_auth()
    } else {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_root_certificates(roots)
            .with_no_client_auth()
    };
    crypto.alpn_protocols = proxy
        .alpn
        .iter()
        .map(|protocol| protocol.as_bytes().to_vec())
        .collect();
    let mut config = quinn::ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(crypto)
            .map_err(|err| format!("CONNECT-UDP H3 QUIC TLS config: {err}"))?,
    ));
    config.transport_config(Arc::new(connect_udp_h3_transport_config(runtime)?));
    Ok(config)
}

fn connect_udp_h3_transport_config(
    runtime: ResidentConnectUdpRuntimePlan,
) -> Result<quinn::TransportConfig, String> {
    let mut transport = quinn::TransportConfig::default();
    transport.keep_alive_interval(Some(runtime.h3_keep_alive_interval));
    transport.max_idle_timeout(Some(
        runtime
            .h3_idle_timeout
            .try_into()
            .map_err(|err| format!("CONNECT-UDP H3 idle timeout config: {err}"))?,
    ));
    transport.datagram_receive_buffer_size(Some(runtime.h3_datagram_buffer_bytes));
    transport.datagram_send_buffer_size(runtime.h3_datagram_buffer_bytes);
    Ok(transport)
}

#[derive(Debug)]
struct AcceptAnyConnectUdpH3Verifier {
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl AcceptAnyConnectUdpH3Verifier {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            provider: Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
        })
    }
}

impl ServerCertVerifier for AcceptAnyConnectUdpH3Verifier {
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
