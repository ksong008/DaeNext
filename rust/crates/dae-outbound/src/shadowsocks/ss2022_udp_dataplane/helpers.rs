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

pub(super) fn derive_subkey(psk: &[u8], salt: &[u8], key_len: usize, context: &str) -> Vec<u8> {
    let mut key_material = Vec::with_capacity(psk.len() + salt.len());
    key_material.extend_from_slice(psk);
    key_material.extend_from_slice(salt);
    let derived = blake3::derive_key(context, &key_material);
    derived[..key_len].to_vec()
}

pub(super) fn timestamp_out_of_tolerance(timestamp: u64, now: u64) -> bool {
    timestamp.saturating_add(TIMESTAMP_TOLERANCE_SECS) < now
        || timestamp > now.saturating_add(TIMESTAMP_TOLERANCE_SECS)
}
