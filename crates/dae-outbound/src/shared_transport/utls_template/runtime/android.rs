use crate::shared_transport::UTLS_FAMILY_ANDROID;
use crate::shared_transport::utls_template::UtlsTemplateMode;

use super::UtlsRuntimeTemplate;
use super::common::*;

const ANDROID_CIPHERS: &[u16] = &[
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
    TLS_RSA_WITH_AES_128_GCM_SHA256,
    TLS_RSA_WITH_AES_256_GCM_SHA384,
    TLS_RSA_WITH_AES_128_CBC_SHA,
    TLS_RSA_WITH_AES_256_CBC_SHA,
];

const ANDROID_EXTENSIONS: &[u16] = &[
    EXT_SERVER_NAME,
    EXT_EXTENDED_MASTER_SECRET,
    EXT_RENEGOTIATE,
    EXT_SUPPORTED_GROUPS,
    EXT_EC_POINT_FORMATS,
    EXT_STATUS_REQUEST,
    EXT_SIGNATURE_ALGORITHMS,
];

const ANDROID_GROUPS: &[u16] = &[GROUP_X25519, GROUP_SECP256R1, GROUP_SECP384R1];
const ANDROID_KEY_SHARES: &[u16] = &[];
const ANDROID_SIGALGS: &[u16] = &[
    SIG_ECDSA_SECP256R1_SHA256,
    SIG_RSA_PSS_RSAE_SHA256,
    SIG_RSA_PKCS1_SHA256,
    SIG_ECDSA_SECP384R1_SHA384,
    SIG_RSA_PSS_RSAE_SHA384,
    SIG_RSA_PKCS1_SHA384,
    SIG_RSA_PSS_RSAE_SHA512,
    SIG_RSA_PKCS1_SHA512,
    SIG_RSA_PKCS1_SHA1,
];

pub(super) const ANDROID_11_OKHTTP: UtlsRuntimeTemplate = UtlsRuntimeTemplate {
    name: "android_11_okhttp",
    canonical: "android_11_okhttp",
    family: UTLS_FAMILY_ANDROID,
    mode: UtlsTemplateMode::ExactFixture,
    session_id_len: BROWSER_SESSION_ID_LEN,
    cipher_suites: ANDROID_CIPHERS,
    extension_order: ANDROID_EXTENSIONS,
    supported_versions: &[],
    supported_groups: ANDROID_GROUPS,
    key_share_groups: ANDROID_KEY_SHARES,
    signature_schemes: ANDROID_SIGALGS,
    delegated_credential_signature_schemes: NO_DELEGATED_CREDENTIAL_SIGNATURE_SCHEMES,
    record_size_limit: None,
    empty_extensions: NO_EMPTY_EXTENSIONS,
    padding_target_handshake_len: None,
    capabilities: ANDROID_CAPABILITIES,
};
