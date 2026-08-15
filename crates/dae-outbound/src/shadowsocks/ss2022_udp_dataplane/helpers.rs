use super::*;
pub(super) fn require_cipher_conf(cipher: &str) -> Result<CipherConf2022, OutboundError> {
    cipher_conf(cipher).ok_or_else(|| {
        OutboundError::BadShadowsocks(format!("unsupported shadowsocks 2022 cipher: {cipher}"))
    })
}

pub(super) fn parse_psk_list(
    password: &str,
    key_len: usize,
) -> Result<Vec<Vec<u8>>, OutboundError> {
    let parts = password.split(':').collect::<Vec<_>>();
    let mut psk_list = Vec::with_capacity(parts.len());
    for part in parts {
        psk_list.push(validate_base64_psk(part, key_len)?);
    }
    Ok(psk_list)
}

pub(super) fn derive_session_subkey(psk: &[u8], salt: &[u8]) -> [u8; 32] {
    let context_key = SESSION_SUBKEY_CONTEXT_KEY
        .get_or_init(|| blake3::hazmat::hash_derive_key_context(SESSION_SUBKEY_CONTEXT));
    let mut hasher = blake3::Hasher::new_from_context_key(context_key);
    hasher.update(psk);
    hasher.update(salt);
    *hasher.finalize().as_bytes()
}

pub(super) fn timestamp_out_of_tolerance(timestamp: u64, now: u64) -> bool {
    timestamp.saturating_add(TIMESTAMP_TOLERANCE_SECS) < now
        || timestamp > now.saturating_add(TIMESTAMP_TOLERANCE_SECS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cached_context_derivation_matches_blake3_wire_key() {
        let psk = [0x31_u8; 16];
        let salt = [0x72_u8; 8];
        let mut material = Vec::from(psk);
        material.extend_from_slice(&salt);

        assert_eq!(
            derive_session_subkey(&psk, &salt),
            blake3::derive_key(SESSION_SUBKEY_CONTEXT, &material)
        );
    }
}
