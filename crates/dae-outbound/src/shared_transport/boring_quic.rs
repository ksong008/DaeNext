//! Shared BoringSSL crypto factory for every Quinn consumer.
//!
//! Protocol modules provide typed intent (SNI is supplied to Quinn connect,
//! while ALPN, verification and 0-RTT are fixed here). They do not build or
//! mutate provider contexts themselves, which prevents DNS, HY2, TUIC,
//! Juicity, and xHTTP from drifting into subtly different TLS policies.

use std::ffi::CString;
use std::io::Read;
use std::os::raw::c_int;
use std::sync::Arc;

use boring_v4_compat::ssl::{SslAlert, SslVerifyError, SslVerifyMode};
use foreign_types::ForeignType;
use quinn_boring::QuicSslContext;
use sha2::{Digest, Sha256};

use super::{SystemCaIdentity, SystemCaSnapshot, system_ca_snapshot};
use crate::OutboundError;

pub const BORING_QUIC_PROVIDER_EVIDENCE: &str = "quinn-boringssl";
pub const BORING_QUIC_GENERATION_SESSION_CACHE_ENTRIES: usize = 256;
pub type BoringQuicSessionCache = Arc<dyn quinn_boring::SessionCache>;

pub fn new_boring_quic_session_cache() -> BoringQuicSessionCache {
    Arc::new(quinn_boring::SimpleCache::new(
        BORING_QUIC_GENERATION_SESSION_CACHE_ENTRIES,
    ))
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum BoringQuicClientHelloProfile {
    #[default]
    Generic,
    Chrome,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BoringQuicVerificationPolicy {
    SystemRoots,
    ExplicitInsecure,
    PinnedCertChainSha256(String),
    PinnedLeafSha256 {
        digest: [u8; 32],
        require_webpki: bool,
    },
}

impl BoringQuicVerificationPolicy {
    pub const fn evidence_label(&self) -> &'static str {
        match self {
            Self::SystemRoots => "system-roots",
            Self::ExplicitInsecure => "explicit-insecure",
            Self::PinnedCertChainSha256(_) => "pinned-certchain-sha256",
            Self::PinnedLeafSha256 {
                require_webpki: true,
                ..
            } => "webpki-and-pinned-raw-cert-sha256",
            Self::PinnedLeafSha256 {
                require_webpki: false,
                ..
            } => "pinned-raw-cert-sha256",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoringQuicClientPolicy {
    pub alpn: Vec<Vec<u8>>,
    pub verification: BoringQuicVerificationPolicy,
    pub zero_rtt: bool,
    pub client_hello: BoringQuicClientHelloProfile,
}

impl BoringQuicClientPolicy {
    pub fn new(alpn: impl IntoIterator<Item = impl AsRef<[u8]>>) -> Result<Self, OutboundError> {
        let alpn = alpn
            .into_iter()
            .map(|protocol| protocol.as_ref().to_vec())
            .collect::<Vec<_>>();
        validate_alpn(&alpn)?;
        Ok(Self {
            alpn,
            verification: BoringQuicVerificationPolicy::SystemRoots,
            zero_rtt: false,
            client_hello: BoringQuicClientHelloProfile::Generic,
        })
    }

    pub fn allow_insecure(mut self, allow: bool) -> Self {
        self.verification = if allow {
            BoringQuicVerificationPolicy::ExplicitInsecure
        } else {
            BoringQuicVerificationPolicy::SystemRoots
        };
        self
    }

    pub fn zero_rtt(mut self, enabled: bool) -> Self {
        self.zero_rtt = enabled;
        self
    }

    pub fn client_hello_profile(mut self, profile: BoringQuicClientHelloProfile) -> Self {
        self.client_hello = profile;
        self
    }

    pub fn pinned_certchain_sha256(mut self, pin: &str) -> Self {
        self.verification = BoringQuicVerificationPolicy::PinnedCertChainSha256(pin.to_owned());
        self
    }

    pub fn pinned_leaf_sha256(mut self, digest: [u8; 32], require_webpki: bool) -> Self {
        self.verification = BoringQuicVerificationPolicy::PinnedLeafSha256 {
            digest,
            require_webpki,
        };
        self
    }
}

/// Reads the negotiated ALPN from a live BoringSSL-backed Quinn connection.
pub fn selected_connection_alpn(connection: &quinn::Connection) -> Option<Vec<u8>> {
    if let Some(data) = connection.handshake_data() {
        if let Some(boring) = data.downcast_ref::<quinn_boring::HandshakeData>() {
            return boring.protocol.clone();
        }
        #[cfg(any(test, feature = "test-support"))]
        if let Some(rustls) = data.downcast_ref::<quinn::crypto::rustls::HandshakeData>() {
            return rustls.protocol.clone();
        }
    }
    None
}

pub fn build_boring_quic_client_config(
    policy: &BoringQuicClientPolicy,
    transport: Arc<quinn::TransportConfig>,
) -> Result<quinn::ClientConfig, OutboundError> {
    build_boring_quic_client_config_with_session_cache(policy, transport, None)
}

pub fn build_boring_quic_client_config_with_session_cache(
    policy: &BoringQuicClientPolicy,
    transport: Arc<quinn::TransportConfig>,
    session_cache: Option<BoringQuicSessionCache>,
) -> Result<quinn::ClientConfig, OutboundError> {
    let crypto = build_boring_quic_client_crypto_with_session_cache(policy, session_cache, None)?;
    let mut config = quinn::ClientConfig::new(Arc::new(crypto));
    config.transport_config(transport);
    Ok(config)
}

pub fn build_boring_quic_client_config_with_session_cache_and_system_ca_snapshot(
    policy: &BoringQuicClientPolicy,
    transport: Arc<quinn::TransportConfig>,
    session_cache: Option<BoringQuicSessionCache>,
    system_ca: Option<Arc<SystemCaSnapshot>>,
) -> Result<quinn::ClientConfig, OutboundError> {
    let crypto =
        build_boring_quic_client_crypto_with_session_cache(policy, session_cache, system_ca)?;
    let mut config = quinn::ClientConfig::new(Arc::new(crypto));
    config.transport_config(transport);
    Ok(config)
}

#[cfg(test)]
pub(crate) fn build_boring_quic_client_config_with_system_ca_snapshot(
    policy: &BoringQuicClientPolicy,
    transport: Arc<quinn::TransportConfig>,
    system_ca: Arc<SystemCaSnapshot>,
) -> Result<quinn::ClientConfig, OutboundError> {
    build_boring_quic_client_config_with_session_cache_and_system_ca_snapshot(
        policy,
        transport,
        None,
        Some(system_ca),
    )
}

/// Builds only the Quinn crypto object. Protocol code should normally use
/// [`build_boring_quic_client_config`]; this lower-level surface exists for
/// tests that must inspect the emitted ClientHello without duplicating the
/// provider policy.
#[doc(hidden)]
pub fn build_boring_quic_client_crypto(
    policy: &BoringQuicClientPolicy,
) -> Result<quinn_boring::ClientConfig, OutboundError> {
    build_boring_quic_client_crypto_with_session_cache(policy, None, None)
}

fn build_boring_quic_client_crypto_with_session_cache(
    policy: &BoringQuicClientPolicy,
    session_cache: Option<BoringQuicSessionCache>,
    system_ca_override: Option<Arc<SystemCaSnapshot>>,
) -> Result<quinn_boring::ClientConfig, OutboundError> {
    validate_alpn(&policy.alpn)?;
    let system_ca = if verification_requires_system_roots(&policy.verification) {
        Some(match system_ca_override {
            Some(system_ca) => system_ca,
            None => system_ca_snapshot().map_err(|err| {
                OutboundError::BadSharedTransport(format!(
                    "load BoringSSL QUIC system CA bundle: {err}"
                ))
            })?,
        })
    } else {
        None
    };
    let mut crypto = quinn_boring::ClientConfig::new().map_err(|err| {
        OutboundError::BadSharedTransport(format!("create BoringSSL QUIC config: {err}"))
    })?;
    if let Some(system_ca) = &system_ca {
        system_ca
            .install_boring_context(crypto.ctx_mut())
            .map_err(|err| {
                OutboundError::BadSharedTransport(format!(
                    "install BoringSSL QUIC system CA bundle: {err}"
                ))
            })?;
    }
    let verify_peer = !matches!(
        policy.verification,
        BoringQuicVerificationPolicy::ExplicitInsecure
    );
    crypto.verify_peer(verify_peer);
    if let BoringQuicVerificationPolicy::PinnedCertChainSha256(pin) = &policy.verification {
        let pin = pin.clone();
        crypto.set_custom_verify_callback(SslVerifyMode::PEER, move |ssl| {
            let mut raw_certs = Vec::new();
            if let Some(chain) = ssl.peer_cert_chain() {
                for cert in chain {
                    raw_certs.push(
                        cert.to_der()
                            .map_err(|_| SslVerifyError::Invalid(SslAlert::CERTIFICATE_UNKNOWN))?,
                    );
                }
            } else if let Some(cert) = ssl.peer_certificate() {
                raw_certs.push(
                    cert.to_der()
                        .map_err(|_| SslVerifyError::Invalid(SslAlert::CERTIFICATE_UNKNOWN))?,
                );
            }
            let refs = raw_certs.iter().map(Vec::as_slice).collect::<Vec<_>>();
            crate::juicity::verify_pinned_certchain(&refs, &pin)
                .map_err(|_| SslVerifyError::Invalid(SslAlert::CERTIFICATE_UNKNOWN))?;
            Ok(())
        });
    }
    if let BoringQuicVerificationPolicy::PinnedLeafSha256 {
        digest,
        require_webpki,
    } = &policy.verification
    {
        let digest = *digest;
        if *require_webpki {
            crypto.set_verify_callback(SslVerifyMode::PEER, move |preverify_ok, context| {
                if !preverify_ok {
                    return false;
                }
                if context.error_depth() != 0 {
                    return true;
                }
                context
                    .current_cert()
                    .and_then(|cert| cert.to_der().ok())
                    .is_some_and(|der| <[u8; 32]>::from(Sha256::digest(der)) == digest)
            });
        } else {
            crypto.set_custom_verify_callback(SslVerifyMode::PEER, move |ssl| {
                let matched = ssl
                    .peer_certificate()
                    .and_then(|cert| cert.to_der().ok())
                    .is_some_and(|der| <[u8; 32]>::from(Sha256::digest(der)) == digest);
                if matched {
                    Ok(())
                } else {
                    Err(SslVerifyError::Invalid(SslAlert::CERTIFICATE_UNKNOWN))
                }
            });
        }
    }
    crypto.set_alpn(&policy.alpn).map_err(|err| {
        OutboundError::BadSharedTransport(format!("set BoringSSL QUIC ALPN: {err}"))
    })?;
    configure_client_hello_profile(crypto.ctx_mut(), policy.client_hello)?;
    crypto.ctx_mut().enable_early_data(policy.zero_rtt);
    if let Some(session_cache) = session_cache {
        crypto.set_session_cache(session_cache);
    } else {
        crypto.set_session_cache(Arc::new(quinn_boring::NoSessionCache));
    }
    crypto.set_session_cache_namespace(session_cache_namespace(
        policy,
        system_ca.as_deref().map(|snapshot| snapshot.identity()),
    ));
    Ok(crypto)
}

fn verification_requires_system_roots(policy: &BoringQuicVerificationPolicy) -> bool {
    matches!(
        policy,
        BoringQuicVerificationPolicy::SystemRoots
            | BoringQuicVerificationPolicy::PinnedLeafSha256 {
                require_webpki: true,
                ..
            }
    )
}

fn session_cache_namespace(
    policy: &BoringQuicClientPolicy,
    system_ca: Option<&SystemCaIdentity>,
) -> Vec<u8> {
    let mut digest = Sha256::new();
    digest.update(b"dae/boring-quic-session-policy/v2");
    digest.update([match policy.client_hello {
        BoringQuicClientHelloProfile::Generic => 0,
        BoringQuicClientHelloProfile::Chrome => 1,
    }]);
    digest.update([u8::from(policy.zero_rtt)]);
    for protocol in &policy.alpn {
        digest.update((protocol.len() as u64).to_be_bytes());
        digest.update(protocol);
    }
    match &policy.verification {
        BoringQuicVerificationPolicy::SystemRoots => digest.update([0]),
        BoringQuicVerificationPolicy::ExplicitInsecure => digest.update([1]),
        BoringQuicVerificationPolicy::PinnedCertChainSha256(pin) => {
            digest.update([2]);
            digest.update((pin.len() as u64).to_be_bytes());
            digest.update(pin.as_bytes());
        }
        BoringQuicVerificationPolicy::PinnedLeafSha256 {
            digest: pin,
            require_webpki,
        } => {
            digest.update([3, u8::from(*require_webpki)]);
            digest.update(pin);
        }
    }
    if let Some(system_ca) = system_ca {
        update_session_cache_namespace_part(
            &mut digest,
            system_ca.path.to_string_lossy().as_bytes(),
        );
        update_session_cache_namespace_part(&mut digest, system_ca.sha256.as_bytes());
        update_session_cache_namespace_part(
            &mut digest,
            &(system_ca.certificate_count as u64).to_be_bytes(),
        );
    }
    digest.finalize().to_vec()
}

fn update_session_cache_namespace_part(digest: &mut Sha256, part: &[u8]) {
    digest.update((part.len() as u64).to_be_bytes());
    digest.update(part);
}

fn configure_client_hello_profile(
    context: &mut boring_v4_compat::ssl::SslContext,
    profile: BoringQuicClientHelloProfile,
) -> Result<(), OutboundError> {
    if profile == BoringQuicClientHelloProfile::Generic {
        return Ok(());
    }
    let curves = CString::new("X25519:P-256:P-384").expect("static curve list has no NUL");
    let configured = unsafe {
        boring_sys::SSL_CTX_set_grease_enabled(context.as_ptr(), 1);
        boring_sys::SSL_CTX_set_permute_extensions(context.as_ptr(), 1);
        boring_sys::SSL_CTX_enable_ocsp_stapling(context.as_ptr());
        boring_sys::SSL_CTX_enable_signed_cert_timestamps(context.as_ptr());
        boring_sys::SSL_CTX_set1_curves_list(context.as_ptr(), curves.as_ptr())
    };
    if configured != 1 {
        return Err(OutboundError::BadSharedTransport(format!(
            "configure BoringSSL QUIC Chrome groups: {}",
            boring_v4_compat::error::ErrorStack::get()
        )));
    }
    let compression_configured = unsafe {
        boring_sys::SSL_CTX_add_cert_compression_alg(
            context.as_ptr(),
            boring_sys::TLSEXT_cert_compression_brotli as u16,
            None,
            Some(decompress_brotli_certificate),
        )
    };
    if compression_configured != 1 {
        return Err(OutboundError::BadSharedTransport(format!(
            "configure BoringSSL QUIC Chrome certificate compression: {}",
            boring_v4_compat::error::ErrorStack::get()
        )));
    }
    Ok(())
}

unsafe extern "C" fn decompress_brotli_certificate(
    _ssl: *mut boring_sys::SSL,
    out: *mut *mut boring_sys::CRYPTO_BUFFER,
    uncompressed_len: usize,
    input: *const u8,
    input_len: usize,
) -> c_int {
    let compressed = unsafe { std::slice::from_raw_parts(input, input_len) };
    let mut decompressed = Vec::with_capacity(uncompressed_len);
    let mut decoder = brotli::Decompressor::new(compressed, 4096);
    if decoder.read_to_end(&mut decompressed).is_err() || decompressed.len() != uncompressed_len {
        return 0;
    }
    let buffer = unsafe {
        boring_sys::CRYPTO_BUFFER_new(
            decompressed.as_ptr(),
            decompressed.len(),
            std::ptr::null_mut(),
        )
    };
    if buffer.is_null() {
        return 0;
    }
    unsafe {
        *out = buffer;
    }
    1
}

fn validate_alpn(alpn: &[Vec<u8>]) -> Result<(), OutboundError> {
    if alpn.is_empty() {
        return Err(OutboundError::BadSharedTransport(
            "BoringSSL QUIC requires at least one ALPN protocol".to_owned(),
        ));
    }
    if let Some(protocol) = alpn
        .iter()
        .find(|protocol| protocol.is_empty() || protocol.len() > u8::MAX as usize)
    {
        return Err(OutboundError::BadSharedTransport(format!(
            "invalid BoringSSL QUIC ALPN length {}",
            protocol.len()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use foreign_types::ForeignTypeRef;

    use super::*;

    #[test]
    fn policy_rejects_empty_alpn_without_provider_fallback() {
        assert!(BoringQuicClientPolicy::new(Vec::<Vec<u8>>::new()).is_err());
    }

    #[test]
    fn policy_keeps_verification_and_zero_rtt_explicit() {
        let policy = BoringQuicClientPolicy::new([b"h3".as_slice()])
            .unwrap()
            .allow_insecure(true)
            .zero_rtt(true);
        assert_eq!(
            policy.verification,
            BoringQuicVerificationPolicy::ExplicitInsecure
        );
        assert!(policy.zero_rtt);
        assert_eq!(policy.client_hello, BoringQuicClientHelloProfile::Generic);
    }

    #[test]
    fn factory_builds_quinn_config_with_boring_crypto() {
        let policy = BoringQuicClientPolicy::new([b"h3".as_slice()]).unwrap();
        let system_ca = system_ca_snapshot().unwrap();
        let expected_store = system_ca.boring_store();
        let mut crypto = build_boring_quic_client_crypto(&policy).unwrap();

        assert_eq!(
            crypto.ctx_mut().cert_store().as_ptr(),
            expected_store.as_ptr()
        );
    }

    #[test]
    fn cache_namespace_separates_verification_alpn_early_data_and_profile() {
        let base = BoringQuicClientPolicy::new([b"h3".as_slice()]).unwrap();
        let insecure = base.clone().allow_insecure(true);
        let other_alpn = BoringQuicClientPolicy::new([b"hysteria".as_slice()]).unwrap();
        let early = base.clone().zero_rtt(true);
        let chrome = base
            .clone()
            .client_hello_profile(BoringQuicClientHelloProfile::Chrome);

        let base_key = session_cache_namespace(&base, None);
        for other in [insecure, other_alpn, early, chrome] {
            assert_ne!(base_key, session_cache_namespace(&other, None));
        }
    }

    #[test]
    fn webpki_policies_require_system_roots() {
        let pin = [7; 32];
        assert!(verification_requires_system_roots(
            &BoringQuicVerificationPolicy::SystemRoots
        ));
        assert!(verification_requires_system_roots(
            &BoringQuicVerificationPolicy::PinnedLeafSha256 {
                digest: pin,
                require_webpki: true,
            }
        ));
        assert!(!verification_requires_system_roots(
            &BoringQuicVerificationPolicy::ExplicitInsecure
        ));
        assert!(!verification_requires_system_roots(
            &BoringQuicVerificationPolicy::PinnedCertChainSha256("pin".to_owned())
        ));
        assert!(!verification_requires_system_roots(
            &BoringQuicVerificationPolicy::PinnedLeafSha256 {
                digest: pin,
                require_webpki: false,
            }
        ));
    }

    #[test]
    fn cache_namespace_separates_system_ca_snapshots() {
        let policy = BoringQuicClientPolicy::new([b"h3".as_slice()]).unwrap();
        let first = SystemCaIdentity {
            path: "/etc/ssl/first.pem".into(),
            sha256: "11".repeat(32),
            certificate_count: 1,
        };
        let second = SystemCaIdentity {
            path: "/etc/ssl/second.pem".into(),
            sha256: "22".repeat(32),
            certificate_count: 2,
        };

        assert_ne!(
            session_cache_namespace(&policy, Some(&first)),
            session_cache_namespace(&policy, Some(&second))
        );
    }
}
