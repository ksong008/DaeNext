use std::fmt;

use crate::error::OutboundError;
use sha2::{Digest, Sha256};

use super::link::normalize_pin_sha256;

const SHA256_HEX_LEN: usize = 64;
const HYSTERIA2_TLS_IDENTITY_DOMAIN: &[u8] = b"dae/hysteria2-tls-identity/v1";

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Hysteria2CertificateVerification {
    WebPki,
    ExplicitInsecure,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Hysteria2ApplicationProtocol {
    Http3,
}

impl Hysteria2ApplicationProtocol {
    pub const fn wire_value(self) -> &'static str {
        match self {
            Self::Http3 => "h3",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Hysteria2TrustAnchorIdentity {
    BundledWebPki,
    None,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Hysteria2ClientCertificateIdentity {
    None,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Hysteria2EncryptedClientHelloIdentity {
    Disabled,
}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct Hysteria2LeafCertificateSha256([u8; 32]);

impl Hysteria2LeafCertificateSha256 {
    fn parse(configured: &str) -> Result<Option<Self>, OutboundError> {
        if configured.trim().is_empty() {
            return Ok(None);
        }
        let normalized = normalize_pin_sha256(configured.trim());
        if normalized.len() != SHA256_HEX_LEN
            || !normalized.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(OutboundError::BadHysteria2(
                "invalid Hysteria2 pinSHA256: expected a 32-byte SHA-256 hexadecimal fingerprint"
                    .to_owned(),
            ));
        }
        let mut digest = [0_u8; 32];
        for (index, output) in digest.iter_mut().enumerate() {
            let offset = index * 2;
            *output = (hex_nibble(normalized.as_bytes()[offset]) << 4)
                | hex_nibble(normalized.as_bytes()[offset + 1]);
        }
        Ok(Some(Self(digest)))
    }

    fn matches_raw_certificate(&self, certificate_der: &[u8]) -> bool {
        let observed: [u8; 32] = Sha256::digest(certificate_der).into();
        self.0 == observed
    }
}

fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => unreachable!("validated hexadecimal fingerprint"),
    }
}

impl fmt::Debug for Hysteria2LeafCertificateSha256 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Hysteria2LeafCertificateSha256(<configured>)")
    }
}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Hysteria2TlsPolicy {
    verification: Hysteria2CertificateVerification,
    leaf_certificate_sha256: Option<Hysteria2LeafCertificateSha256>,
}

impl Hysteria2TlsPolicy {
    pub fn from_node_and_global(
        node_allow_insecure: bool,
        global_allow_insecure: bool,
        configured_pin_sha256: &str,
    ) -> Result<Self, OutboundError> {
        let verification = if node_allow_insecure || global_allow_insecure {
            Hysteria2CertificateVerification::ExplicitInsecure
        } else {
            Hysteria2CertificateVerification::WebPki
        };
        Ok(Self {
            verification,
            leaf_certificate_sha256: Hysteria2LeafCertificateSha256::parse(configured_pin_sha256)?,
        })
    }

    pub const fn verification(&self) -> Hysteria2CertificateVerification {
        self.verification
    }

    pub const fn allow_insecure(&self) -> bool {
        matches!(
            self.verification,
            Hysteria2CertificateVerification::ExplicitInsecure
        )
    }

    pub const fn has_leaf_certificate_pin(&self) -> bool {
        self.leaf_certificate_sha256.is_some()
    }

    pub(crate) fn leaf_certificate_sha256_digest(&self) -> Option<[u8; 32]> {
        self.leaf_certificate_sha256.as_ref().map(|pin| pin.0)
    }

    pub const fn requires_webpki(&self) -> bool {
        matches!(self.verification, Hysteria2CertificateVerification::WebPki)
    }

    pub fn verification_label(&self) -> &'static str {
        match (self.verification, self.has_leaf_certificate_pin()) {
            (Hysteria2CertificateVerification::WebPki, false) => "webpki",
            (Hysteria2CertificateVerification::WebPki, true) => "webpki-and-pinned-raw-cert-sha256",
            (Hysteria2CertificateVerification::ExplicitInsecure, false) => "explicit-insecure",
            (Hysteria2CertificateVerification::ExplicitInsecure, true) => "pinned-raw-cert-sha256",
        }
    }

    pub(super) fn leaf_certificate_matches(&self, certificate_der: &[u8]) -> bool {
        self.leaf_certificate_sha256
            .as_ref()
            .is_none_or(|pin| pin.matches_raw_certificate(certificate_der))
    }
}

impl fmt::Debug for Hysteria2TlsPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Hysteria2TlsPolicy")
            .field("verification", &self.verification)
            .field(
                "leaf_certificate_pin_configured",
                &self.has_leaf_certificate_pin(),
            )
            .finish()
    }
}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Hysteria2TlsIdentity {
    server_name: Box<str>,
    application_protocol: Hysteria2ApplicationProtocol,
    trust_anchor: Hysteria2TrustAnchorIdentity,
    client_certificate: Hysteria2ClientCertificateIdentity,
    encrypted_client_hello: Hysteria2EncryptedClientHelloIdentity,
    policy: Hysteria2TlsPolicy,
}

impl Hysteria2TlsIdentity {
    pub fn from_node_and_global(
        server_name: impl Into<String>,
        node_allow_insecure: bool,
        global_allow_insecure: bool,
        configured_pin_sha256: &str,
    ) -> Result<Self, OutboundError> {
        let policy = Hysteria2TlsPolicy::from_node_and_global(
            node_allow_insecure,
            global_allow_insecure,
            configured_pin_sha256,
        )?;
        let server_name = server_name.into();
        if server_name.trim().is_empty() {
            return Err(OutboundError::BadHysteria2(
                "Hysteria2 TLS server name must not be empty".to_owned(),
            ));
        }
        if rustls::pki_types::ServerName::try_from(server_name.clone()).is_err() {
            return Err(OutboundError::BadHysteria2(
                "Hysteria2 TLS server name is invalid".to_owned(),
            ));
        }
        let trust_anchor = if policy.requires_webpki() {
            Hysteria2TrustAnchorIdentity::BundledWebPki
        } else {
            Hysteria2TrustAnchorIdentity::None
        };
        Ok(Self {
            server_name: server_name.into_boxed_str(),
            application_protocol: Hysteria2ApplicationProtocol::Http3,
            trust_anchor,
            client_certificate: Hysteria2ClientCertificateIdentity::None,
            encrypted_client_hello: Hysteria2EncryptedClientHelloIdentity::Disabled,
            policy,
        })
    }

    pub fn server_name(&self) -> &str {
        &self.server_name
    }

    pub const fn application_protocol(&self) -> Hysteria2ApplicationProtocol {
        self.application_protocol
    }

    pub const fn trust_anchor(&self) -> Hysteria2TrustAnchorIdentity {
        self.trust_anchor
    }

    pub const fn client_certificate(&self) -> Hysteria2ClientCertificateIdentity {
        self.client_certificate
    }

    pub const fn encrypted_client_hello(&self) -> Hysteria2EncryptedClientHelloIdentity {
        self.encrypted_client_hello
    }

    pub const fn policy(&self) -> &Hysteria2TlsPolicy {
        &self.policy
    }

    pub fn verification_label(&self) -> &'static str {
        self.policy.verification_label()
    }

    pub fn effective_identity_sha256(&self) -> [u8; 32] {
        let mut digest = Sha256::new();
        update_identity_part(&mut digest, HYSTERIA2_TLS_IDENTITY_DOMAIN);
        update_identity_part(&mut digest, self.server_name.as_bytes());
        update_identity_part(
            &mut digest,
            self.application_protocol.wire_value().as_bytes(),
        );
        update_identity_part(
            &mut digest,
            match self.trust_anchor {
                Hysteria2TrustAnchorIdentity::BundledWebPki => b"bundled-webpki",
                Hysteria2TrustAnchorIdentity::None => b"none",
            },
        );
        update_identity_part(&mut digest, b"client-certificate-none");
        update_identity_part(&mut digest, b"encrypted-client-hello-disabled");
        update_identity_part(&mut digest, self.policy.verification_label().as_bytes());
        if let Some(pin) = &self.policy.leaf_certificate_sha256 {
            update_identity_part(&mut digest, &pin.0);
        } else {
            update_identity_part(&mut digest, &[]);
        }
        digest.finalize().into()
    }
}

fn update_identity_part(digest: &mut Sha256, value: &[u8]) {
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value);
}

impl fmt::Debug for Hysteria2TlsIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Hysteria2TlsIdentity")
            .field("server_name", &self.server_name)
            .field("application_protocol", &self.application_protocol)
            .field("trust_anchor", &self.trust_anchor)
            .field("client_certificate", &self.client_certificate)
            .field("encrypted_client_hello", &self.encrypted_client_hello)
            .field("policy", &self.policy)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PIN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn effective_policy_preserves_trust_and_pin_as_independent_dimensions() {
        let secure = Hysteria2TlsPolicy::from_node_and_global(false, false, "").unwrap();
        let secure_pin = Hysteria2TlsPolicy::from_node_and_global(false, false, PIN).unwrap();
        let insecure = Hysteria2TlsPolicy::from_node_and_global(true, false, "").unwrap();
        let inherited_insecure_pin =
            Hysteria2TlsPolicy::from_node_and_global(false, true, PIN).unwrap();

        assert_eq!(secure.verification_label(), "webpki");
        assert_eq!(
            secure_pin.verification_label(),
            "webpki-and-pinned-raw-cert-sha256"
        );
        assert_eq!(insecure.verification_label(), "explicit-insecure");
        assert_eq!(
            inherited_insecure_pin.verification_label(),
            "pinned-raw-cert-sha256"
        );
    }

    #[test]
    fn equivalent_pin_spellings_produce_the_same_effective_identity() {
        let colon_separated = PIN
            .as_bytes()
            .chunks(2)
            .map(|chunk| std::str::from_utf8(chunk).unwrap())
            .collect::<Vec<_>>()
            .join(":")
            .to_ascii_uppercase();
        let canonical =
            Hysteria2TlsIdentity::from_node_and_global("fixture.invalid", false, false, PIN)
                .unwrap();
        let alternate = Hysteria2TlsIdentity::from_node_and_global(
            "fixture.invalid",
            false,
            false,
            &colon_separated,
        )
        .unwrap();
        assert_eq!(canonical, alternate);
        assert_eq!(
            canonical.effective_identity_sha256(),
            alternate.effective_identity_sha256()
        );
    }

    #[test]
    fn effective_identity_tracks_policy_and_pin_without_source_provenance() {
        let secure =
            Hysteria2TlsIdentity::from_node_and_global("fixture.invalid", false, false, "")
                .unwrap();
        let same_secure =
            Hysteria2TlsIdentity::from_node_and_global("fixture.invalid", false, false, "")
                .unwrap();
        let secure_pin =
            Hysteria2TlsIdentity::from_node_and_global("fixture.invalid", false, false, PIN)
                .unwrap();
        let insecure =
            Hysteria2TlsIdentity::from_node_and_global("fixture.invalid", true, false, "").unwrap();

        assert_eq!(
            secure.effective_identity_sha256(),
            same_secure.effective_identity_sha256()
        );
        assert_ne!(
            secure.effective_identity_sha256(),
            secure_pin.effective_identity_sha256()
        );
        assert_ne!(
            secure.effective_identity_sha256(),
            insecure.effective_identity_sha256()
        );
    }

    #[test]
    fn malformed_pin_is_rejected_before_transport_construction() {
        for pin in ["00", "not-a-hash", "--::"] {
            assert!(Hysteria2TlsPolicy::from_node_and_global(false, false, pin).is_err());
        }
    }

    #[test]
    fn invalid_server_name_is_rejected_before_transport_construction() {
        assert!(Hysteria2TlsIdentity::from_node_and_global("bad name", false, false, "").is_err());
    }

    #[test]
    fn debug_output_redacts_the_configured_pin() {
        let policy = Hysteria2TlsPolicy::from_node_and_global(false, false, PIN).unwrap();
        let rendered = format!("{policy:?}");
        assert!(rendered.contains("leaf_certificate_pin_configured: true"));
        assert!(!rendered.contains(PIN));
    }
}
