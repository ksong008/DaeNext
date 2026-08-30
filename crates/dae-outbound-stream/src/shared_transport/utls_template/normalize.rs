use super::{
    UtlsAlpnTemplate, UtlsPaddingTemplate, UtlsServerNameTemplate, UtlsSessionIdTemplate,
    UtlsTemplateFamily, UtlsTemplateMode, UtlsTemplateProfile, UtlsTemplateValue,
};
use crate::shared_transport::{
    UTLS_FAMILY_360, UTLS_FAMILY_ANDROID, UTLS_FAMILY_CHROME, UTLS_FAMILY_EDGE,
    UTLS_FAMILY_FIREFOX, UTLS_FAMILY_IOS, UTLS_FAMILY_QQ, UTLS_FAMILY_RANDOM, UTLS_FAMILY_SAFARI,
    UtlsClientHelloProfile, UtlsFingerprint,
};

const TLS_PADDING_EXTENSION: &str = "0015";

pub fn normalize_utls_template_profile(
    fingerprint: &UtlsFingerprint,
    profile: &UtlsClientHelloProfile,
) -> UtlsTemplateProfile {
    UtlsTemplateProfile {
        fingerprint_name: fingerprint.name.to_owned(),
        canonical_name: fingerprint.canonical.to_owned(),
        family: template_family(fingerprint.family),
        mode: template_mode(fingerprint),
        record_content_type: profile.record_content_type.clone(),
        record_version: profile.record_version.clone(),
        record_len: profile.record_len,
        handshake_type: profile.handshake_type.clone(),
        handshake_len: profile.handshake_len,
        legacy_version: profile.legacy_version.clone(),
        random_len: profile.random_len,
        session_id: UtlsSessionIdTemplate {
            len: profile.session_id_len,
        },
        cipher_suites: normalize_values(&profile.cipher_suites),
        compression_methods: normalize_values(&profile.compression_methods),
        extension_types: normalize_values(&profile.extension_types),
        sni: if profile.sni.is_some() {
            UtlsServerNameTemplate::Dynamic
        } else {
            UtlsServerNameTemplate::Absent
        },
        alpn: profile
            .alpn
            .as_ref()
            .map(|protocols| UtlsAlpnTemplate::DynamicList(protocols.clone()))
            .unwrap_or(UtlsAlpnTemplate::Absent),
        supported_versions: normalize_optional_values(&profile.supported_versions),
        supported_groups: normalize_optional_values(&profile.supported_groups),
        ec_point_formats: normalize_optional_values(&profile.ec_point_formats),
        signature_schemes: normalize_optional_values(&profile.signature_schemes),
        key_share_groups: normalize_optional_values(&profile.key_share_groups),
        padding: if profile
            .extension_types
            .iter()
            .any(|extension| extension == TLS_PADDING_EXTENSION)
        {
            UtlsPaddingTemplate::TargetHandshakeLen(profile.handshake_len)
        } else {
            UtlsPaddingTemplate::Absent
        },
    }
}

fn template_family(family: &str) -> UtlsTemplateFamily {
    match family {
        UTLS_FAMILY_CHROME => UtlsTemplateFamily::Chrome,
        UTLS_FAMILY_EDGE => UtlsTemplateFamily::Edge,
        UTLS_FAMILY_FIREFOX => UtlsTemplateFamily::Firefox,
        UTLS_FAMILY_SAFARI => UtlsTemplateFamily::Safari,
        UTLS_FAMILY_IOS => UtlsTemplateFamily::Ios,
        UTLS_FAMILY_ANDROID => UtlsTemplateFamily::Android,
        UTLS_FAMILY_RANDOM => UtlsTemplateFamily::Random,
        UTLS_FAMILY_360 => UtlsTemplateFamily::Browser360,
        UTLS_FAMILY_QQ => UtlsTemplateFamily::Qq,
        other => UtlsTemplateFamily::Other(other.to_owned()),
    }
}

fn template_mode(fingerprint: &UtlsFingerprint) -> UtlsTemplateMode {
    if fingerprint.randomized {
        UtlsTemplateMode::Randomized
    } else {
        UtlsTemplateMode::ExactFixture
    }
}

fn normalize_optional_values(values: &Option<Vec<String>>) -> Vec<UtlsTemplateValue> {
    values.as_deref().map(normalize_values).unwrap_or_default()
}

fn normalize_values(values: &[String]) -> Vec<UtlsTemplateValue> {
    values
        .iter()
        .map(|value| {
            if is_grease_u16_hex(value) {
                UtlsTemplateValue::Grease
            } else {
                UtlsTemplateValue::exact(value)
            }
        })
        .collect()
}

fn is_grease_u16_hex(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 4 {
        return false;
    }
    let Some(high) = hex_byte(&bytes[0..2]) else {
        return false;
    };
    let Some(low) = hex_byte(&bytes[2..4]) else {
        return false;
    };
    high == low && (high & 0x0f) == 0x0a
}

fn hex_byte(bytes: &[u8]) -> Option<u8> {
    Some((hex_nibble(bytes[0])? << 4) | hex_nibble(bytes[1])?)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}
