use super::{UTLS_TEMPLATE_GREASE, UtlsRuntimeTemplateCapabilities};

pub(super) const BROWSER_SESSION_ID_LEN: usize = 32;
pub(super) const NO_EMPTY_EXTENSIONS: &[u16] = &[];
pub(super) const NO_DELEGATED_CREDENTIAL_SIGNATURE_SCHEMES: &[u16] = &[];

pub(super) const TLS_AES_128_GCM_SHA256: u16 = 0x1301;
pub(super) const TLS_AES_256_GCM_SHA384: u16 = 0x1302;
pub(super) const TLS_CHACHA20_POLY1305_SHA256: u16 = 0x1303;
pub(super) const TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: u16 = 0xc02b;
pub(super) const TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: u16 = 0xc02f;
pub(super) const TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: u16 = 0xc02c;
pub(super) const TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: u16 = 0xc030;
pub(super) const TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: u16 = 0xcca9;
pub(super) const TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: u16 = 0xcca8;
pub(super) const TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA: u16 = 0xc013;
pub(super) const TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA: u16 = 0xc014;
pub(super) const TLS_RSA_WITH_AES_128_GCM_SHA256: u16 = 0x009c;
pub(super) const TLS_RSA_WITH_AES_256_GCM_SHA384: u16 = 0x009d;
pub(super) const TLS_DHE_RSA_WITH_AES_128_CBC_SHA: u16 = 0x0033;
pub(super) const TLS_DHE_RSA_WITH_AES_256_CBC_SHA: u16 = 0x0039;
pub(super) const TLS_RSA_WITH_AES_128_CBC_SHA: u16 = 0x002f;
pub(super) const TLS_RSA_WITH_AES_256_CBC_SHA: u16 = 0x0035;
pub(super) const TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA: u16 = 0xc009;
pub(super) const TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA: u16 = 0xc00a;
pub(super) const TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384: u16 = 0xc024;
pub(super) const TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256: u16 = 0xc023;
pub(super) const TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384: u16 = 0xc028;
pub(super) const TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256: u16 = 0xc027;
pub(super) const TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA: u16 = 0xc008;
pub(super) const TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA: u16 = 0xc012;
pub(super) const TLS_RSA_WITH_AES_256_CBC_SHA256: u16 = 0x003d;
pub(super) const TLS_RSA_WITH_AES_128_CBC_SHA256: u16 = 0x003c;
pub(super) const TLS_RSA_WITH_3DES_EDE_CBC_SHA: u16 = 0x000a;

pub(super) const TLS_VERSION_1_0: u16 = 0x0301;
pub(super) const TLS_VERSION_1_1: u16 = 0x0302;
pub(super) const TLS_VERSION_1_2: u16 = 0x0303;
pub(super) const TLS_VERSION_1_3: u16 = 0x0304;

pub(super) const EXT_SERVER_NAME: u16 = 0x0000;
pub(super) const EXT_EXTENDED_MASTER_SECRET: u16 = 0x0017;
pub(super) const EXT_RENEGOTIATE: u16 = 0xff01;
pub(super) const EXT_SUPPORTED_GROUPS: u16 = 0x000a;
pub(super) const EXT_EC_POINT_FORMATS: u16 = 0x000b;
pub(super) const EXT_SESSION_TICKET: u16 = 0x0023;
pub(super) const EXT_ALPN: u16 = 0x0010;
pub(super) const EXT_STATUS_REQUEST: u16 = 0x0005;
pub(super) const EXT_SIGNATURE_ALGORITHMS: u16 = 0x000d;
pub(super) const EXT_SCT: u16 = 0x0012;
pub(super) const EXT_DELEGATED_CREDENTIAL: u16 = 0x0022;
pub(super) const EXT_KEY_SHARE: u16 = 0x0033;
pub(super) const EXT_PSK_KEY_EXCHANGE_MODES: u16 = 0x002d;
pub(super) const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
pub(super) const EXT_CERT_COMPRESSION: u16 = 0x001b;
pub(super) const EXT_RECORD_SIZE_LIMIT: u16 = 0x001c;
pub(super) const EXT_ALPS_OLD: u16 = 0x4469;
pub(super) const EXT_ALPS_DRAFT_7550: u16 = 0x7550;
pub(super) const EXT_PADDING: u16 = 0x0015;

pub(super) const GROUP_X25519: u16 = 0x001d;
pub(super) const GROUP_SECP256R1: u16 = 0x0017;
pub(super) const GROUP_SECP384R1: u16 = 0x0018;
pub(super) const GROUP_SECP521R1: u16 = 0x0019;
pub(super) const GROUP_FFDHE2048: u16 = 0x0100;
pub(super) const GROUP_FFDHE3072: u16 = 0x0101;

pub(super) const SIG_ECDSA_SECP256R1_SHA256: u16 = 0x0403;
pub(super) const SIG_RSA_PSS_RSAE_SHA256: u16 = 0x0804;
pub(super) const SIG_RSA_PKCS1_SHA256: u16 = 0x0401;
pub(super) const SIG_ECDSA_SECP384R1_SHA384: u16 = 0x0503;
pub(super) const SIG_ECDSA_SECP521R1_SHA512: u16 = 0x0603;
pub(super) const SIG_RSA_PSS_RSAE_SHA384: u16 = 0x0805;
pub(super) const SIG_RSA_PKCS1_SHA384: u16 = 0x0501;
pub(super) const SIG_RSA_PSS_RSAE_SHA512: u16 = 0x0806;
pub(super) const SIG_RSA_PKCS1_SHA512: u16 = 0x0601;
pub(super) const SIG_ECDSA_SHA1: u16 = 0x0203;
pub(super) const SIG_RSA_PKCS1_SHA1: u16 = 0x0201;

pub(super) const BROWSER_CAPABILITIES: UtlsRuntimeTemplateCapabilities =
    UtlsRuntimeTemplateCapabilities {
        grease: true,
        ocsp_stapling: true,
        signed_cert_timestamps: true,
        cert_compression_brotli: true,
        alps_old_h2: true,
    };

pub(super) const BROWSER_360_CAPABILITIES: UtlsRuntimeTemplateCapabilities =
    UtlsRuntimeTemplateCapabilities {
        grease: true,
        ocsp_stapling: true,
        signed_cert_timestamps: true,
        cert_compression_brotli: true,
        alps_old_h2: false,
    };

pub(super) const APPLE_CAPABILITIES: UtlsRuntimeTemplateCapabilities =
    UtlsRuntimeTemplateCapabilities {
        grease: true,
        ocsp_stapling: true,
        signed_cert_timestamps: true,
        cert_compression_brotli: true,
        alps_old_h2: false,
    };

pub(super) const IOS_CAPABILITIES: UtlsRuntimeTemplateCapabilities =
    UtlsRuntimeTemplateCapabilities {
        grease: true,
        ocsp_stapling: true,
        signed_cert_timestamps: true,
        cert_compression_brotli: false,
        alps_old_h2: false,
    };

pub(super) const ANDROID_CAPABILITIES: UtlsRuntimeTemplateCapabilities =
    UtlsRuntimeTemplateCapabilities {
        grease: false,
        ocsp_stapling: true,
        signed_cert_timestamps: false,
        cert_compression_brotli: false,
        alps_old_h2: false,
    };

pub(super) const CHROME_EDGE_EXTENSIONS: &[u16] = &[
    UTLS_TEMPLATE_GREASE,
    EXT_SERVER_NAME,
    EXT_EXTENDED_MASTER_SECRET,
    EXT_RENEGOTIATE,
    EXT_SUPPORTED_GROUPS,
    EXT_EC_POINT_FORMATS,
    EXT_SESSION_TICKET,
    EXT_ALPN,
    EXT_STATUS_REQUEST,
    EXT_SIGNATURE_ALGORITHMS,
    EXT_SCT,
    EXT_KEY_SHARE,
    EXT_PSK_KEY_EXCHANGE_MODES,
    EXT_SUPPORTED_VERSIONS,
    EXT_CERT_COMPRESSION,
    EXT_ALPS_OLD,
    UTLS_TEMPLATE_GREASE,
    EXT_PADDING,
];

pub(super) const CHROME_EDGE_GROUPS: &[u16] = &[
    UTLS_TEMPLATE_GREASE,
    GROUP_X25519,
    GROUP_SECP256R1,
    GROUP_SECP384R1,
];

pub(super) const CHROME_EDGE_SUPPORTED_VERSIONS: &[u16] =
    &[UTLS_TEMPLATE_GREASE, TLS_VERSION_1_3, TLS_VERSION_1_2];

pub(super) const BROWSER_FULL_SUPPORTED_VERSIONS: &[u16] = &[
    UTLS_TEMPLATE_GREASE,
    TLS_VERSION_1_3,
    TLS_VERSION_1_2,
    TLS_VERSION_1_1,
    TLS_VERSION_1_0,
];

pub(super) const CHROME_EDGE_KEY_SHARES: &[u16] = &[UTLS_TEMPLATE_GREASE, GROUP_X25519];

pub(super) const CHROME_EDGE_SIGALGS: &[u16] = &[
    SIG_ECDSA_SECP256R1_SHA256,
    SIG_RSA_PSS_RSAE_SHA256,
    SIG_RSA_PKCS1_SHA256,
    SIG_ECDSA_SECP384R1_SHA384,
    SIG_RSA_PSS_RSAE_SHA384,
    SIG_RSA_PKCS1_SHA384,
    SIG_RSA_PSS_RSAE_SHA512,
    SIG_RSA_PKCS1_SHA512,
];

pub(super) const BROWSER_LEGACY_SIGALGS: &[u16] = &[
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

pub(super) const APPLE_GROUPS: &[u16] = &[
    UTLS_TEMPLATE_GREASE,
    GROUP_X25519,
    GROUP_SECP256R1,
    GROUP_SECP384R1,
    GROUP_SECP521R1,
];

pub(super) const APPLE_KEY_SHARES: &[u16] = &[UTLS_TEMPLATE_GREASE, GROUP_X25519];

pub(super) const APPLE_SIGALGS: &[u16] = &[
    SIG_ECDSA_SECP256R1_SHA256,
    SIG_RSA_PSS_RSAE_SHA256,
    SIG_RSA_PKCS1_SHA256,
    SIG_ECDSA_SECP384R1_SHA384,
    SIG_ECDSA_SHA1,
    SIG_RSA_PSS_RSAE_SHA384,
    SIG_RSA_PSS_RSAE_SHA384,
    SIG_RSA_PKCS1_SHA384,
    SIG_RSA_PSS_RSAE_SHA512,
    SIG_RSA_PKCS1_SHA512,
    SIG_RSA_PKCS1_SHA1,
];
