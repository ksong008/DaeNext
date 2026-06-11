use crate::shared_transport::parse_utls_client_hello_record_hex;

use super::*;

#[test]
fn case_native_utls_clienthello_fixture_profiles_parse_exactly() {
    let fixture = fixture("outbound/protocol/utls_clienthello_profile.json");
    assert_eq!(
        fixture["name"].as_str().unwrap(),
        "utls-clienthello-profile-fixture"
    );
    assert_eq!(
        fixture["profile_family"].as_str().unwrap(),
        "utls-clienthello"
    );

    let samples = fixture["samples"].as_array().unwrap();
    assert_eq!(samples.len(), 6);
    for sample in samples {
        let fingerprint = sample["fingerprint"].as_str().unwrap();
        let expected = &sample["profile"];
        let profile = parse_utls_client_hello_record_hex(sample["record_hex"].as_str().unwrap())
            .unwrap_or_else(|err| panic!("{fingerprint}: {err}"));

        assert_eq!(
            profile.record_content_type,
            expected["record_content_type"].as_str().unwrap(),
            "{fingerprint}"
        );
        assert_eq!(
            profile.record_version,
            expected["record_version"].as_str().unwrap(),
            "{fingerprint}"
        );
        assert_eq!(
            profile.record_len,
            expected["record_len"].as_u64().unwrap() as usize,
            "{fingerprint}"
        );
        assert_eq!(
            profile.handshake_type,
            expected["handshake_type"].as_str().unwrap(),
            "{fingerprint}"
        );
        assert_eq!(
            profile.handshake_len,
            expected["handshake_len"].as_u64().unwrap() as usize,
            "{fingerprint}"
        );
        assert_eq!(
            profile.legacy_version,
            expected["legacy_version"].as_str().unwrap(),
            "{fingerprint}"
        );
        assert_eq!(
            profile.random_len,
            expected["random_len"].as_u64().unwrap() as usize,
            "{fingerprint}"
        );
        assert_eq!(
            profile.session_id_len,
            expected["session_id_len"].as_u64().unwrap() as usize,
            "{fingerprint}"
        );
        assert_eq!(
            profile.cipher_suites,
            string_vec(&expected["cipher_suites"]),
            "{fingerprint}"
        );
        assert_eq!(
            profile.compression_methods,
            string_vec(&expected["compression_methods"]),
            "{fingerprint}"
        );
        assert_eq!(
            profile.extension_types,
            string_vec(&expected["extension_types"]),
            "{fingerprint}"
        );
        assert_eq!(
            profile.sni.as_deref(),
            expected["sni"].as_str(),
            "{fingerprint}"
        );
        assert_eq!(
            profile.alpn,
            optional_string_vec(&expected["alpn"]),
            "{fingerprint}"
        );
        assert_eq!(
            profile.supported_versions,
            optional_string_vec(&expected["supported_versions"]),
            "{fingerprint}"
        );
        assert_eq!(
            profile.supported_groups,
            optional_string_vec(&expected["supported_groups"]),
            "{fingerprint}"
        );
        assert_eq!(
            profile.ec_point_formats,
            optional_string_vec(&expected["ec_point_formats"]),
            "{fingerprint}"
        );
        assert_eq!(
            profile.signature_schemes,
            optional_string_vec(&expected["signature_schemes"]),
            "{fingerprint}"
        );
        assert_eq!(
            profile.key_share_groups,
            optional_string_vec(&expected["key_share_groups"]),
            "{fingerprint}"
        );
    }
}

#[test]
fn case_native_utls_clienthello_parser_rejects_truncated_record() {
    let fixture = fixture("outbound/protocol/utls_clienthello_profile.json");
    let record_hex = fixture["samples"][0]["record_hex"].as_str().unwrap();
    let truncated = &record_hex[..record_hex.len() - 2];
    let err = parse_utls_client_hello_record_hex(truncated).unwrap_err();
    assert!(err.to_string().contains("record length mismatch"));
}

fn string_vec(value: &Value) -> Vec<String> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item.as_str().unwrap().to_owned())
        .collect()
}
