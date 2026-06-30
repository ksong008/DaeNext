use crate::shared_transport::{
    UtlsAlpnTemplate, UtlsClientHelloProfile, UtlsPaddingTemplate, UtlsServerNameTemplate,
    UtlsTemplateFamily, UtlsTemplateMode, UtlsTemplateProfile, normalize_utls_template_profile,
    parse_utls_client_hello_record_hex, resolve_utls_client_hello_id,
};

use super::*;

#[test]
fn case_utls_clienthello_fixtures_normalize_to_typed_templates() {
    let fixture = fixture("outbound/protocol/utls_clienthello_profile.json");
    let samples = fixture["samples"].as_array().unwrap();
    assert!(!samples.is_empty());

    for sample in samples {
        let fingerprint_name = sample["fingerprint"].as_str().unwrap();
        let fingerprint = resolve_utls_client_hello_id(fingerprint_name).unwrap();
        let profile = parse_utls_client_hello_record_hex(sample["record_hex"].as_str().unwrap())
            .unwrap_or_else(|err| panic!("{fingerprint_name}: {err}"));
        let template = normalize_utls_template_profile(&fingerprint, &profile);

        assert_eq!(template.fingerprint_name, fingerprint.name);
        assert_eq!(template.canonical_name, fingerprint.canonical);
        assert_eq!(template.mode, UtlsTemplateMode::ExactFixture);
        assert_eq!(template.random_len, 32);
        assert_eq!(template.session_id.len, profile.session_id_len);
        assert_eq!(template.sni, UtlsServerNameTemplate::Dynamic);
        assert_eq!(
            template.alpn,
            profile
                .alpn
                .clone()
                .map(UtlsAlpnTemplate::DynamicList)
                .unwrap_or(UtlsAlpnTemplate::Absent)
        );
        assert_eq!(
            template.padding,
            if profile
                .extension_types
                .iter()
                .any(|extension_type| extension_type == "0015")
            {
                UtlsPaddingTemplate::TargetHandshakeLen(profile.handshake_len)
            } else {
                UtlsPaddingTemplate::Absent
            }
        );
        assert_eq!(
            template_grease_count(&template),
            source_grease_count(&profile),
            "{fingerprint_name} should preserve GREASE semantics"
        );
    }
}

#[test]
fn case_utls_template_normalizer_preserves_family_without_string_matching_runtime_callers() {
    let fixture = fixture("outbound/protocol/utls_clienthello_profile.json");
    let samples = fixture["samples"].as_array().unwrap();
    let chrome = samples
        .iter()
        .find(|sample| sample["fingerprint"].as_str().unwrap() == "chrome_102")
        .unwrap();
    let safari = samples
        .iter()
        .find(|sample| sample["fingerprint"].as_str().unwrap() == "safari_16_0")
        .unwrap();

    let chrome_fingerprint = resolve_utls_client_hello_id("chrome_102").unwrap();
    let safari_fingerprint = resolve_utls_client_hello_id("safari_16_0").unwrap();
    let chrome_profile =
        parse_utls_client_hello_record_hex(chrome["record_hex"].as_str().unwrap()).unwrap();
    let safari_profile =
        parse_utls_client_hello_record_hex(safari["record_hex"].as_str().unwrap()).unwrap();

    let chrome_template = normalize_utls_template_profile(&chrome_fingerprint, &chrome_profile);
    let safari_template = normalize_utls_template_profile(&safari_fingerprint, &safari_profile);

    assert_eq!(chrome_template.family, UtlsTemplateFamily::Chrome);
    assert_eq!(safari_template.family, UtlsTemplateFamily::Safari);
    assert_ne!(
        chrome_template.extension_types,
        safari_template.extension_types
    );
}

fn template_grease_count(template: &UtlsTemplateProfile) -> usize {
    template
        .cipher_suites
        .iter()
        .chain(template.extension_types.iter())
        .chain(template.supported_versions.iter())
        .chain(template.supported_groups.iter())
        .chain(template.key_share_groups.iter())
        .filter(|value| value.is_grease())
        .count()
}

fn source_grease_count(profile: &UtlsClientHelloProfile) -> usize {
    profile
        .cipher_suites
        .iter()
        .chain(profile.extension_types.iter())
        .chain(profile.supported_versions.iter().flatten())
        .chain(profile.supported_groups.iter().flatten())
        .chain(profile.key_share_groups.iter().flatten())
        .filter(|value| is_grease_u16_hex(value))
        .count()
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
