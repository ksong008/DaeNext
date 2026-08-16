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

/// Increment the fixed-size SS2022 TCP nonce without carrying a dynamic slice
/// length through the record hot path.  SS2022 TCP admits a 96-bit nonce and
/// treats it as a little-endian counter; the early returns preserve the exact
/// carry semantics of `increment_nonce_le` while allowing the compiler to
/// specialize the twelve-byte layout.
#[inline(always)]
pub(super) fn increment_nonce_le_12(nonce: &mut [u8; 12]) {
    let (next, overflow) = nonce[0].overflowing_add(1);
    nonce[0] = next;
    if !overflow {
        return;
    }
    let (next, overflow) = nonce[1].overflowing_add(1);
    nonce[1] = next;
    if !overflow {
        return;
    }
    let (next, overflow) = nonce[2].overflowing_add(1);
    nonce[2] = next;
    if !overflow {
        return;
    }
    let (next, overflow) = nonce[3].overflowing_add(1);
    nonce[3] = next;
    if !overflow {
        return;
    }
    let (next, overflow) = nonce[4].overflowing_add(1);
    nonce[4] = next;
    if !overflow {
        return;
    }
    let (next, overflow) = nonce[5].overflowing_add(1);
    nonce[5] = next;
    if !overflow {
        return;
    }
    let (next, overflow) = nonce[6].overflowing_add(1);
    nonce[6] = next;
    if !overflow {
        return;
    }
    let (next, overflow) = nonce[7].overflowing_add(1);
    nonce[7] = next;
    if !overflow {
        return;
    }
    let (next, overflow) = nonce[8].overflowing_add(1);
    nonce[8] = next;
    if !overflow {
        return;
    }
    let (next, overflow) = nonce[9].overflowing_add(1);
    nonce[9] = next;
    if !overflow {
        return;
    }
    let (next, overflow) = nonce[10].overflowing_add(1);
    nonce[10] = next;
    if !overflow {
        return;
    }
    nonce[11] = nonce[11].wrapping_add(1);
}

#[cfg(test)]
mod tests {
    use super::increment_nonce_le_12;

    #[test]
    fn nonce_increment_is_little_endian_with_full_carry() {
        let mut nonce = [0_u8; 12];
        increment_nonce_le_12(&mut nonce);
        assert_eq!(nonce, [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

        nonce = [0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        increment_nonce_le_12(&mut nonce);
        assert_eq!(nonce, [0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

        nonce = [0xff; 12];
        increment_nonce_le_12(&mut nonce);
        assert_eq!(nonce, [0; 12]);
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
