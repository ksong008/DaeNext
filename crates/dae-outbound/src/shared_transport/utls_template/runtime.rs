use crate::shared_transport::{UTLS_FAMILY_FIREFOX, UtlsFingerprint};

use super::UtlsTemplateMode;

mod android;
mod apple;
mod chrome;
mod common;
mod other;

pub const UTLS_TEMPLATE_GREASE: u16 = 0x0a0a;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UtlsRuntimeTemplate {
    pub name: &'static str,
    pub canonical: &'static str,
    pub family: &'static str,
    pub mode: UtlsTemplateMode,
    pub session_id_len: usize,
    pub cipher_suites: &'static [u16],
    pub extension_order: &'static [u16],
    pub supported_versions: &'static [u16],
    pub supported_groups: &'static [u16],
    pub key_share_groups: &'static [u16],
    pub signature_schemes: &'static [u16],
    pub empty_extensions: &'static [u16],
    pub padding_target_handshake_len: Option<usize>,
    pub capabilities: UtlsRuntimeTemplateCapabilities,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UtlsRuntimeTemplateCapabilities {
    pub grease: bool,
    pub ocsp_stapling: bool,
    pub signed_cert_timestamps: bool,
    pub cert_compression_brotli: bool,
    pub alps_old_h2: bool,
}

pub fn resolve_utls_runtime_template(
    fingerprint: &UtlsFingerprint,
) -> Option<&'static UtlsRuntimeTemplate> {
    match fingerprint.name {
        "360_11_0" => Some(&other::BROWSER_360_11_0),
        "chrome_102" => Some(&chrome::CHROME_102),
        "edge_106" => Some(&chrome::EDGE_106),
        "safari_16_0" => Some(&apple::SAFARI_16_0),
        "ios_14" => Some(&apple::IOS_14),
        "android_11_okhttp" => Some(&android::ANDROID_11_OKHTTP),
        "qq_11_1" => Some(&chrome::QQ_11_1),
        _ => None,
    }
}

pub fn runtime_template_mode(fingerprint: &UtlsFingerprint) -> UtlsTemplateMode {
    if fingerprint.randomized {
        return UtlsTemplateMode::Randomized;
    }
    if resolve_utls_runtime_template(fingerprint).is_some() {
        return UtlsTemplateMode::ExactFixture;
    }
    if fingerprint.family == UTLS_FAMILY_FIREFOX {
        return UtlsTemplateMode::UnsupportedExactTemplate;
    }
    UtlsTemplateMode::FamilyApproximation
}
