use std::sync::Arc;

use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    CertificateError, DigitallySignedStruct, RootCertStore, SignatureScheme, crypto::CryptoProvider,
};

use crate::error::OutboundError;

use super::tls_policy::Hysteria2TlsPolicy;

#[derive(Debug)]
pub(super) struct Hysteria2ServerCertVerifier {
    provider: Arc<CryptoProvider>,
    webpki: Option<Arc<WebPkiServerVerifier>>,
    policy: Hysteria2TlsPolicy,
}

impl Hysteria2ServerCertVerifier {
    pub(super) fn new(
        policy: &Hysteria2TlsPolicy,
        roots: Arc<RootCertStore>,
    ) -> Result<Arc<Self>, OutboundError> {
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let webpki = policy
            .requires_webpki()
            .then(|| {
                WebPkiServerVerifier::builder_with_provider(roots, Arc::clone(&provider))
                    .build()
                    .map_err(|err| {
                        OutboundError::BadHysteria2(format!(
                            "build Hysteria2 WebPKI verifier: {err}"
                        ))
                    })
            })
            .transpose()?;
        Ok(Arc::new(Self {
            provider,
            webpki,
            policy: policy.clone(),
        }))
    }
}

impl ServerCertVerifier for Hysteria2ServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if let Some(webpki) = &self.webpki {
            webpki.verify_server_cert(end_entity, intermediates, server_name, ocsp, now)?;
        }
        if !self.policy.leaf_certificate_matches(end_entity.as_ref()) {
            return Err(rustls::Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
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
