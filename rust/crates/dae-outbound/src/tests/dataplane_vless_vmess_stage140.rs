use crate::shared_transport::{
    build_synthetic_utls_client_hello_record_hex, parse_utls_client_hello_record_hex,
};

use super::*;

#[test]
fn stage140_synthetic_utls_clienthello_builder_roundtrips_fixture_profiles() {
    let fixture = fixture("outbound/protocol/stage139_go_utls_clienthello_profile.json");
    let samples = fixture["samples"].as_array().unwrap();
    let mut synthetic_count = 0;

    for sample in samples {
        let fingerprint = sample["fingerprint"].as_str().unwrap();
        let source_profile =
            parse_utls_client_hello_record_hex(sample["record_hex"].as_str().unwrap())
                .unwrap_or_else(|err| panic!("{fingerprint}: fixture parse failed: {err}"));
        let synthetic_hex = build_synthetic_utls_client_hello_record_hex(&source_profile)
            .unwrap_or_else(|err| panic!("{fingerprint}: synthetic build failed: {err}"));
        let synthetic_profile = parse_utls_client_hello_record_hex(&synthetic_hex)
            .unwrap_or_else(|err| panic!("{fingerprint}: synthetic parse failed: {err}"));

        assert_eq!(synthetic_profile, source_profile, "{fingerprint}");
        assert_eq!(synthetic_profile.record_len, source_profile.record_len);
        assert_eq!(
            synthetic_profile.handshake_len,
            source_profile.handshake_len
        );
        assert_eq!(
            synthetic_profile.extension_types,
            source_profile.extension_types
        );
        synthetic_count += 1;
    }

    assert_eq!(synthetic_count, 6);
}

#[test]
fn stage140_synthetic_utls_clienthello_builder_rejects_profiles_without_padding_room() {
    let fixture = fixture("outbound/protocol/stage139_go_utls_clienthello_profile.json");
    let sample = fixture["samples"][0]["record_hex"].as_str().unwrap();
    let mut profile = parse_utls_client_hello_record_hex(sample).unwrap();
    profile
        .extension_types
        .retain(|extension_type| extension_type != "0015");
    let err = build_synthetic_utls_client_hello_record_hex(&profile).unwrap_err();
    assert!(err.to_string().contains("needs"));
}
