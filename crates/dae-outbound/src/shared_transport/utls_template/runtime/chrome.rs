use crate::shared_transport::{UTLS_FAMILY_CHROME, UTLS_FAMILY_EDGE, UTLS_FAMILY_QQ};

use super::common::*;
use super::{UTLS_TEMPLATE_GREASE, UtlsRuntimeTemplate};
use crate::shared_transport::utls_template::UtlsTemplateMode;

const CHROME_EDGE_CIPHERS: &[u16] = &[
    UTLS_TEMPLATE_GREASE,
    TLS_AES_128_GCM_SHA256,
    TLS_AES_256_GCM_SHA384,
    TLS_CHACHA20_POLY1305_SHA256,
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
    TLS_RSA_WITH_AES_128_GCM_SHA256,
    TLS_RSA_WITH_AES_256_GCM_SHA384,
    TLS_RSA_WITH_AES_128_CBC_SHA,
    TLS_RSA_WITH_AES_256_CBC_SHA,
];

const EDGE_106_CIPHERS: &[u16] = &[
    UTLS_TEMPLATE_GREASE,
    TLS_AES_128_GCM_SHA256,
    TLS_AES_256_GCM_SHA384,
    TLS_CHACHA20_POLY1305_SHA256,
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
    TLS_RSA_WITH_AES_128_GCM_SHA256,
    TLS_RSA_WITH_AES_256_GCM_SHA384,
    TLS_RSA_WITH_AES_128_CBC_SHA,
    TLS_RSA_WITH_AES_256_CBC_SHA,
];

pub(super) const CHROME_102: UtlsRuntimeTemplate = UtlsRuntimeTemplate {
    name: "chrome_102",
    canonical: "chrome_102",
    family: UTLS_FAMILY_CHROME,
    mode: UtlsTemplateMode::ExactFixture,
    session_id_len: BROWSER_SESSION_ID_LEN,
    cipher_suites: CHROME_EDGE_CIPHERS,
    extension_order: CHROME_EDGE_EXTENSIONS,
    supported_versions: CHROME_EDGE_SUPPORTED_VERSIONS,
    supported_groups: CHROME_EDGE_GROUPS,
    key_share_groups: CHROME_EDGE_KEY_SHARES,
    signature_schemes: CHROME_EDGE_SIGALGS,
    delegated_credential_signature_schemes: NO_DELEGATED_CREDENTIAL_SIGNATURE_SCHEMES,
    record_size_limit: None,
    empty_extensions: NO_EMPTY_EXTENSIONS,
    padding_target_handshake_len: Some(508),
    capabilities: BROWSER_CAPABILITIES,
};

pub(super) const EDGE_106: UtlsRuntimeTemplate = UtlsRuntimeTemplate {
    name: "edge_106",
    canonical: "edge_106",
    family: UTLS_FAMILY_EDGE,
    mode: UtlsTemplateMode::ExactFixture,
    session_id_len: BROWSER_SESSION_ID_LEN,
    cipher_suites: EDGE_106_CIPHERS,
    extension_order: CHROME_EDGE_EXTENSIONS,
    supported_versions: CHROME_EDGE_SUPPORTED_VERSIONS,
    supported_groups: CHROME_EDGE_GROUPS,
    key_share_groups: CHROME_EDGE_KEY_SHARES,
    signature_schemes: CHROME_EDGE_SIGALGS,
    delegated_credential_signature_schemes: NO_DELEGATED_CREDENTIAL_SIGNATURE_SCHEMES,
    record_size_limit: None,
    empty_extensions: NO_EMPTY_EXTENSIONS,
    padding_target_handshake_len: Some(508),
    capabilities: BROWSER_CAPABILITIES,
};

pub(super) const QQ_11_1: UtlsRuntimeTemplate = UtlsRuntimeTemplate {
    name: "qq_11_1",
    canonical: "qq_11_1",
    family: UTLS_FAMILY_QQ,
    mode: UtlsTemplateMode::ExactFixture,
    session_id_len: BROWSER_SESSION_ID_LEN,
    cipher_suites: CHROME_EDGE_CIPHERS,
    extension_order: CHROME_EDGE_EXTENSIONS,
    supported_versions: BROWSER_FULL_SUPPORTED_VERSIONS,
    supported_groups: CHROME_EDGE_GROUPS,
    key_share_groups: CHROME_EDGE_KEY_SHARES,
    signature_schemes: CHROME_EDGE_SIGALGS,
    delegated_credential_signature_schemes: NO_DELEGATED_CREDENTIAL_SIGNATURE_SCHEMES,
    record_size_limit: None,
    empty_extensions: NO_EMPTY_EXTENSIONS,
    padding_target_handshake_len: Some(508),
    capabilities: BROWSER_CAPABILITIES,
};
