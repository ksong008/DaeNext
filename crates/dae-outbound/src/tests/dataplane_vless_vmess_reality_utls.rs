use crate::shared_transport::{
    RealityAeadAlgorithm, SyntheticRealityUtlsMutationOptions, parse_utls_client_hello_record_hex,
    synthetic_reality_utls_mutation_report,
};

use super::*;

#[test]
fn case_synthetic_reality_utls_raw_mutation_preserves_profiles() {
    let fixture = fixture("outbound/protocol/utls_clienthello_profile.json");
    let samples = fixture["samples"].as_array().unwrap();
    let mut report_count = 0;
    for sample in samples {
        let fingerprint = sample["fingerprint"].as_str().unwrap();
        let profile = parse_utls_client_hello_record_hex(sample["record_hex"].as_str().unwrap())
            .unwrap_or_else(|err| panic!("{fingerprint}: fixture parse failed: {err}"));
        for algorithm in [
            RealityAeadAlgorithm::AesGcm,
            RealityAeadAlgorithm::ChaCha20Poly1305,
        ] {
            let report =
                synthetic_reality_utls_mutation_report(&case_options(profile.clone(), algorithm))
                    .unwrap_or_else(|err| {
                        panic!("{fingerprint}: synthetic REALITY mutation failed: {err}")
                    });
            assert_eq!(
                report.session_id_hello_raw_offset,
                crate::shared_transport::REALITY_SESSION_ID_RAW_OFFSET
            );
            assert_eq!(report.session_id_record_offset, 44);
            assert_eq!(
                report.session_id_len,
                crate::shared_transport::REALITY_SESSION_ID_LEN
            );
            assert!(report.mutation_applied_to_hello_raw);
            assert!(report.mutation_applied_to_record);
            assert!(report.profile_preserved_after_mutation);
            assert!(!report.full_utls_stack);
            assert!(!report.verify_peer_certificate_admitted);
            assert!(!report.spider_fallback_admitted);
            report_count += 1;
        }
    }
    assert_eq!(report_count, 12);
}

fn case_options(
    profile: crate::shared_transport::UtlsClientHelloProfile,
    algorithm: RealityAeadAlgorithm,
) -> SyntheticRealityUtlsMutationOptions {
    let sid = [0x14, 0x15, 0x16, 0x17, 0x24, 0x25, 0x26, 0x27];
    let unix_seconds = 1_717_141_141;
    let mut client_random = [0_u8; 32];
    for (index, byte) in client_random.iter_mut().enumerate() {
        *byte = (index as u8).wrapping_mul(9).wrapping_add(7);
    }
    let mut shared_secret = [0_u8; 32];
    for (index, byte) in shared_secret.iter_mut().enumerate() {
        *byte = (index as u8).wrapping_mul(13).wrapping_add(11);
    }
    SyntheticRealityUtlsMutationOptions {
        profile,
        sid,
        unix_seconds,
        client_random,
        shared_secret,
        algorithm,
    }
}
