use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use sha2::Sha256;

use crate::error::OutboundError;
use crate::shared_transport::reality::REALITY_VERSION;

pub const REALITY_SESSION_ID_LEN: usize = 32;
pub const REALITY_SESSION_ID_PLAINTEXT_LEN: usize = 16;
pub const REALITY_CLIENT_RANDOM_LEN: usize = 32;
pub const REALITY_HKDF_SALT_LEN: usize = 20;
pub const REALITY_AEAD_NONCE_LEN: usize = 12;
pub const REALITY_SESSION_ID_RAW_OFFSET: usize = 39;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RealityAeadAlgorithm {
    AesGcm,
    ChaCha20Poly1305,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RealitySessionIdMutationOptions {
    pub sid: [u8; 8],
    pub unix_seconds: u32,
    pub client_random: [u8; REALITY_CLIENT_RANDOM_LEN],
    pub shared_secret: [u8; 32],
    pub hello_raw: Vec<u8>,
    pub algorithm: RealityAeadAlgorithm,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RealitySessionIdMutationReport {
    pub plaintext_session_id_hex: String,
    pub mutated_session_id_hex: String,
    pub auth_key_hex: String,
    pub nonce_hex: String,
    pub hello_raw_len: usize,
    pub session_id_offset: usize,
    pub algorithm: &'static str,
    pub mutation_applied_to_hello_raw: bool,
    pub full_utls_stack: bool,
}

pub fn reality_session_id_plaintext(
    sid: [u8; 8],
    unix_seconds: u32,
) -> [u8; REALITY_SESSION_ID_PLAINTEXT_LEN] {
    let mut session_id = [0_u8; REALITY_SESSION_ID_PLAINTEXT_LEN];
    session_id[..3].copy_from_slice(&REALITY_VERSION);
    session_id[3] = 0;
    session_id[4..8].copy_from_slice(&unix_seconds.to_be_bytes());
    session_id[8..16].copy_from_slice(&sid);
    session_id
}

pub fn reality_auth_key(
    shared_secret: &[u8; 32],
    client_random: &[u8; REALITY_CLIENT_RANDOM_LEN],
) -> Result<[u8; 32], OutboundError> {
    let hkdf = Hkdf::<Sha256>::new(Some(&client_random[..REALITY_HKDF_SALT_LEN]), shared_secret);
    let mut auth_key = [0_u8; 32];
    hkdf.expand(b"REALITY", &mut auth_key)
        .map_err(|err| OutboundError::BadSharedTransport(format!("REALITY hkdf: {err}")))?;
    Ok(auth_key)
}

pub fn mutate_reality_session_id(
    options: &RealitySessionIdMutationOptions,
) -> Result<[u8; REALITY_SESSION_ID_LEN], OutboundError> {
    let plaintext = reality_session_id_plaintext(options.sid, options.unix_seconds);
    let auth_key = reality_auth_key(&options.shared_secret, &options.client_random)?;
    let nonce = &options.client_random[REALITY_HKDF_SALT_LEN..];
    let payload = Payload {
        msg: &plaintext,
        aad: &options.hello_raw,
    };
    let encrypted = match options.algorithm {
        RealityAeadAlgorithm::AesGcm => Aes256Gcm::new_from_slice(&auth_key)
            .map_err(|err| OutboundError::BadSharedTransport(format!("REALITY aes-gcm: {err}")))?
            .encrypt(aes_gcm::Nonce::from_slice(nonce), payload)
            .map_err(|err| OutboundError::BadSharedTransport(format!("REALITY aes-gcm: {err}")))?,
        RealityAeadAlgorithm::ChaCha20Poly1305 => ChaCha20Poly1305::new_from_slice(&auth_key)
            .map_err(|err| {
                OutboundError::BadSharedTransport(format!("REALITY chacha20poly1305: {err}"))
            })?
            .encrypt(chacha20poly1305::Nonce::from_slice(nonce), payload)
            .map_err(|err| {
                OutboundError::BadSharedTransport(format!("REALITY chacha20poly1305: {err}"))
            })?,
    };
    if encrypted.len() != REALITY_SESSION_ID_LEN {
        return Err(OutboundError::BadSharedTransport(
            "REALITY encrypted session id length mismatch".to_owned(),
        ));
    }
    let mut out = [0_u8; REALITY_SESSION_ID_LEN];
    out.copy_from_slice(&encrypted);
    Ok(out)
}

pub fn apply_reality_session_id_to_hello_raw(
    hello_raw: &mut [u8],
    session_id: &[u8; REALITY_SESSION_ID_LEN],
) -> Result<(), OutboundError> {
    let end = REALITY_SESSION_ID_RAW_OFFSET + REALITY_SESSION_ID_LEN;
    if hello_raw.len() < end {
        return Err(OutboundError::BadSharedTransport(
            "REALITY hello raw too short for session id offset".to_owned(),
        ));
    }
    hello_raw[REALITY_SESSION_ID_RAW_OFFSET..end].copy_from_slice(session_id);
    Ok(())
}

pub fn reality_session_id_mutation_report(
    options: &RealitySessionIdMutationOptions,
) -> Result<RealitySessionIdMutationReport, OutboundError> {
    let plaintext = reality_session_id_plaintext(options.sid, options.unix_seconds);
    let auth_key = reality_auth_key(&options.shared_secret, &options.client_random)?;
    let nonce = &options.client_random[REALITY_HKDF_SALT_LEN..];
    let mutated = mutate_reality_session_id(options)?;
    let mut hello_raw = options.hello_raw.clone();
    apply_reality_session_id_to_hello_raw(&mut hello_raw, &mutated)?;
    Ok(RealitySessionIdMutationReport {
        plaintext_session_id_hex: hex_encode(&plaintext),
        mutated_session_id_hex: hex_encode(&mutated),
        auth_key_hex: hex_encode(&auth_key),
        nonce_hex: hex_encode(nonce),
        hello_raw_len: hello_raw.len(),
        session_id_offset: REALITY_SESSION_ID_RAW_OFFSET,
        algorithm: match options.algorithm {
            RealityAeadAlgorithm::AesGcm => "aes-gcm",
            RealityAeadAlgorithm::ChaCha20Poly1305 => "chacha20poly1305",
        },
        mutation_applied_to_hello_raw: hello_raw
            [REALITY_SESSION_ID_RAW_OFFSET..REALITY_SESSION_ID_RAW_OFFSET + REALITY_SESSION_ID_LEN]
            == mutated,
        full_utls_stack: false,
    })
}

pub fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}
