use super::*;
pub(super) fn require_cipher_conf(cipher: &str) -> Result<CipherConf2022, OutboundError> {
    cipher_conf(cipher).ok_or_else(|| {
        OutboundError::BadShadowsocks(format!("unsupported shadowsocks 2022 cipher: {cipher}"))
    })
}

pub(super) fn parse_single_psk(password: &str, key_len: usize) -> Result<Vec<u8>, OutboundError> {
    let parts = password.split(':').collect::<Vec<_>>();
    if parts.len() != 1 {
        return Err(OutboundError::BadShadowsocks(
            "SS2022 TCP single-PSK dataplane admits single PSK only; multi-PSK identity header remains gated".to_owned(),
        ));
    }
    validate_base64_psk(parts[0], key_len)
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

pub(super) fn increment_nonce_le(nonce: &mut [u8]) {
    for byte in nonce {
        let (next, overflow) = byte.overflowing_add(1);
        *byte = next;
        if !overflow {
            break;
        }
    }
}

pub(super) fn validate_salt_len(name: &str, salt: &[u8], want: usize) -> Result<(), OutboundError> {
    if salt.len() != want {
        return Err(OutboundError::BadShadowsocks(format!(
            "SS2022 {name} salt length must be {want}, got {}",
            salt.len()
        )));
    }
    Ok(())
}

pub fn unix_timestamp_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[allow(dead_code)]
pub(super) fn _identity_context_marker() -> &'static str {
    IDENTITY_SUBKEY_CONTEXT
}
