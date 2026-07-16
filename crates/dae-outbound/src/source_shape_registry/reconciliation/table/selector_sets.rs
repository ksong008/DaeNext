use super::*;

const STANDARD_TLS_VARIANT: MaterializedTlsVariant = MaterializedTlsVariant::new(
    MaterializedSecurity::StandardTls,
    MaterializedTlsFeatures::NONE,
);
const INSECURE_TLS_VARIANT: MaterializedTlsVariant = MaterializedTlsVariant::new(
    MaterializedSecurity::InsecureTls,
    MaterializedTlsFeatures::ALLOW_INSECURE,
);
const INSECURE_FRAGMENTED_TLS_VARIANT: MaterializedTlsVariant = MaterializedTlsVariant::new(
    MaterializedSecurity::InsecureTls,
    MaterializedTlsFeatures::ALLOW_INSECURE_FRAGMENT,
);
const FRAGMENTED_TLS_VARIANT: MaterializedTlsVariant = MaterializedTlsVariant::new(
    MaterializedSecurity::FragmentedTls,
    MaterializedTlsFeatures::FRAGMENT,
);
const FINGERPRINT_TLS_VARIANT: MaterializedTlsVariant = MaterializedTlsVariant::new(
    MaterializedSecurity::FingerprintAwareTls,
    MaterializedTlsFeatures::FINGERPRINT,
);
const INSECURE_FINGERPRINT_TLS_VARIANT: MaterializedTlsVariant = MaterializedTlsVariant::new(
    MaterializedSecurity::FingerprintAwareTls,
    MaterializedTlsFeatures::ALLOW_INSECURE_FINGERPRINT,
);
const FRAGMENTED_FINGERPRINT_TLS_VARIANT: MaterializedTlsVariant = MaterializedTlsVariant::new(
    MaterializedSecurity::FingerprintAwareTls,
    MaterializedTlsFeatures::FRAGMENT_FINGERPRINT,
);
const INSECURE_FRAGMENTED_FINGERPRINT_TLS_VARIANT: MaterializedTlsVariant =
    MaterializedTlsVariant::new(
        MaterializedSecurity::FingerprintAwareTls,
        MaterializedTlsFeatures::ALLOW_INSECURE_FRAGMENT_FINGERPRINT,
    );
const REALITY_TLS_VARIANT: MaterializedTlsVariant = MaterializedTlsVariant::new(
    MaterializedSecurity::RealityRustls,
    MaterializedTlsFeatures::NONE,
);
const REALITY_FINGERPRINT_TLS_VARIANT: MaterializedTlsVariant = MaterializedTlsVariant::new(
    MaterializedSecurity::RealityFingerprint,
    MaterializedTlsFeatures::FINGERPRINT,
);
const QUIC_TLS_VARIANT: MaterializedTlsVariant =
    MaterializedTlsVariant::new(MaterializedSecurity::QuicTls, MaterializedTlsFeatures::NONE);

pub(super) const FULL_STREAM_TLS_VARIANTS: &[MaterializedTlsVariant] = &[
    STANDARD_TLS_VARIANT,
    INSECURE_TLS_VARIANT,
    INSECURE_FRAGMENTED_TLS_VARIANT,
    FRAGMENTED_TLS_VARIANT,
    FINGERPRINT_TLS_VARIANT,
    INSECURE_FINGERPRINT_TLS_VARIANT,
    FRAGMENTED_FINGERPRINT_TLS_VARIANT,
    INSECURE_FRAGMENTED_FINGERPRINT_TLS_VARIANT,
];
pub(super) const FULL_STREAM_TLS_AND_REALITY_VARIANTS: &[MaterializedTlsVariant] = &[
    STANDARD_TLS_VARIANT,
    INSECURE_TLS_VARIANT,
    INSECURE_FRAGMENTED_TLS_VARIANT,
    FRAGMENTED_TLS_VARIANT,
    FINGERPRINT_TLS_VARIANT,
    INSECURE_FINGERPRINT_TLS_VARIANT,
    FRAGMENTED_FINGERPRINT_TLS_VARIANT,
    INSECURE_FRAGMENTED_FINGERPRINT_TLS_VARIANT,
    REALITY_TLS_VARIANT,
    REALITY_FINGERPRINT_TLS_VARIANT,
];
pub(super) const STREAM_TLS_WITHOUT_FINGERPRINT_VARIANTS: &[MaterializedTlsVariant] = &[
    STANDARD_TLS_VARIANT,
    INSECURE_TLS_VARIANT,
    INSECURE_FRAGMENTED_TLS_VARIANT,
    FRAGMENTED_TLS_VARIANT,
];
pub(super) const TLS_WITHOUT_CLIENT_HELLO_MUTATION_VARIANTS: &[MaterializedTlsVariant] =
    &[STANDARD_TLS_VARIANT, INSECURE_TLS_VARIANT];
pub(super) const REALITY_TLS_VARIANTS: &[MaterializedTlsVariant] =
    &[REALITY_TLS_VARIANT, REALITY_FINGERPRINT_TLS_VARIANT];
pub(super) const SHADOWSOCKS_V2RAY_PLUGIN_TLS_VARIANTS: &[MaterializedTlsVariant] =
    &[STANDARD_TLS_VARIANT, FRAGMENTED_TLS_VARIANT];
pub(super) const INSECURE_TLS_VARIANTS: &[MaterializedTlsVariant] =
    &[INSECURE_TLS_VARIANT, INSECURE_FRAGMENTED_TLS_VARIANT];
pub(super) const FINGERPRINT_AWARE_TLS_VARIANTS: &[MaterializedTlsVariant] = &[
    FINGERPRINT_TLS_VARIANT,
    INSECURE_FINGERPRINT_TLS_VARIANT,
    FRAGMENTED_FINGERPRINT_TLS_VARIANT,
    INSECURE_FRAGMENTED_FINGERPRINT_TLS_VARIANT,
];
pub(super) const STANDARD_OR_FRAGMENTED_TLS_VARIANTS: &[MaterializedTlsVariant] =
    &[STANDARD_TLS_VARIANT, FRAGMENTED_TLS_VARIANT];
pub(super) const QUIC_TLS_VARIANTS: &[MaterializedTlsVariant] = &[QUIC_TLS_VARIANT];
pub(super) const NO_SECURITY_VARIANTS: &[MaterializedTlsVariant] = &[MaterializedTlsVariant::new(
    MaterializedSecurity::None,
    MaterializedTlsFeatures::NONE,
)];
pub(super) const AEAD_VARIANTS: &[MaterializedTlsVariant] = &[MaterializedTlsVariant::new(
    MaterializedSecurity::Aead,
    MaterializedTlsFeatures::NONE,
)];
pub(super) const AEAD_2022_VARIANTS: &[MaterializedTlsVariant] = &[MaterializedTlsVariant::new(
    MaterializedSecurity::Aead2022,
    MaterializedTlsFeatures::NONE,
)];
pub(super) const LEGACY_CIPHER_VARIANTS: &[MaterializedTlsVariant] =
    &[MaterializedTlsVariant::new(
        MaterializedSecurity::LegacyCipher,
        MaterializedTlsFeatures::NONE,
    )];
pub(super) const ALL_QUIC_VERIFICATION: &[MaterializedQuicVerification] = &[
    MaterializedQuicVerification::WebPki,
    MaterializedQuicVerification::Insecure,
    MaterializedQuicVerification::PinOnly,
    MaterializedQuicVerification::WebPkiAndPin,
];
pub(super) const XHTTP_MODES: &[MaterializedXhttpMode] = &[
    MaterializedXhttpMode::PacketUp,
    MaterializedXhttpMode::StreamUp,
    MaterializedXhttpMode::StreamOne,
];
pub(super) const NOT_XHTTP: &[MaterializedXhttpMode] = &[MaterializedXhttpMode::NotApplicable];
pub(super) const NOT_QUIC_VERIFICATION: &[MaterializedQuicVerification] =
    &[MaterializedQuicVerification::NotApplicable];
