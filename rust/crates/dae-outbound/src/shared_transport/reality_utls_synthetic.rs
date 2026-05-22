use crate::error::OutboundError;

use super::{
    REALITY_SESSION_ID_LEN, REALITY_SESSION_ID_RAW_OFFSET, RealityAeadAlgorithm,
    RealitySessionIdMutationOptions, UtlsClientHelloProfile, apply_reality_session_id_to_hello_raw,
    build_synthetic_utls_client_hello_record, mutate_reality_session_id,
    parse_utls_client_hello_record,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyntheticRealityUtlsMutationOptions {
    pub profile: UtlsClientHelloProfile,
    pub sid: [u8; 8],
    pub unix_seconds: u32,
    pub client_random: [u8; 32],
    pub shared_secret: [u8; 32],
    pub algorithm: RealityAeadAlgorithm,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyntheticRealityUtlsMutationReport {
    pub synthetic_record_len: usize,
    pub hello_raw_len: usize,
    pub session_id_hello_raw_offset: usize,
    pub session_id_record_offset: usize,
    pub session_id_len: usize,
    pub algorithm: &'static str,
    pub mutation_applied_to_hello_raw: bool,
    pub mutation_applied_to_record: bool,
    pub profile_preserved_after_mutation: bool,
    pub full_utls_stack: bool,
    pub verify_peer_certificate_admitted: bool,
    pub spider_fallback_admitted: bool,
}

pub fn synthetic_reality_utls_mutation_report(
    options: &SyntheticRealityUtlsMutationOptions,
) -> Result<SyntheticRealityUtlsMutationReport, OutboundError> {
    let mut record = build_synthetic_utls_client_hello_record(&options.profile)?;
    if record.len() < 5 {
        return Err(OutboundError::BadSharedTransport(
            "synthetic REALITY uTLS record too short".to_owned(),
        ));
    }
    let mut hello_raw = record[5..].to_vec();
    let mutation_options = RealitySessionIdMutationOptions {
        sid: options.sid,
        unix_seconds: options.unix_seconds,
        client_random: options.client_random,
        shared_secret: options.shared_secret,
        hello_raw: hello_raw.clone(),
        algorithm: options.algorithm,
    };
    let mutated = mutate_reality_session_id(&mutation_options)?;
    apply_reality_session_id_to_hello_raw(&mut hello_raw, &mutated)?;
    record[5..].copy_from_slice(&hello_raw);
    let parsed = parse_utls_client_hello_record(&record)?;
    let record_offset = 5 + REALITY_SESSION_ID_RAW_OFFSET;
    Ok(SyntheticRealityUtlsMutationReport {
        synthetic_record_len: record.len(),
        hello_raw_len: hello_raw.len(),
        session_id_hello_raw_offset: REALITY_SESSION_ID_RAW_OFFSET,
        session_id_record_offset: record_offset,
        session_id_len: REALITY_SESSION_ID_LEN,
        algorithm: match options.algorithm {
            RealityAeadAlgorithm::AesGcm => "aes-gcm",
            RealityAeadAlgorithm::ChaCha20Poly1305 => "chacha20poly1305",
        },
        mutation_applied_to_hello_raw: hello_raw
            [REALITY_SESSION_ID_RAW_OFFSET..REALITY_SESSION_ID_RAW_OFFSET + REALITY_SESSION_ID_LEN]
            == mutated,
        mutation_applied_to_record: record[record_offset..record_offset + REALITY_SESSION_ID_LEN]
            == mutated,
        profile_preserved_after_mutation: parsed == options.profile,
        full_utls_stack: false,
        verify_peer_certificate_admitted: false,
        spider_fallback_admitted: false,
    })
}
