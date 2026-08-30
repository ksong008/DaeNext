use super::*;

pub(super) fn put_eauth_id(
    cmd_key: &[u8; 16],
    unix_timestamp: u64,
    random: [u8; 4],
) -> Result<[u8; 16], OutboundError> {
    let mut plain = [0_u8; 16];
    plain[..8].copy_from_slice(&unix_timestamp.to_be_bytes());
    plain[8..12].copy_from_slice(&random);
    let checksum = crc32_ieee(&plain[..12]);
    plain[12..].copy_from_slice(&checksum.to_be_bytes());
    aes128_block_encrypt(&kdf16(cmd_key, &[KDF_SALT_AUTH_ID_ENCRYPTION_KEY]), &plain)
}

pub(super) fn decrypt_eauth_id(
    cmd_key: &[u8; 16],
    encrypted: &[u8; 16],
) -> Result<(u64, bool), OutboundError> {
    let plain = aes128_block_decrypt(
        &kdf16(cmd_key, &[KDF_SALT_AUTH_ID_ENCRYPTION_KEY]),
        encrypted,
    )?;
    let timestamp = u64::from_be_bytes([
        plain[0], plain[1], plain[2], plain[3], plain[4], plain[5], plain[6], plain[7],
    ]);
    let want = u32::from_be_bytes([plain[12], plain[13], plain[14], plain[15]]);
    Ok((timestamp, crc32_ieee(&plain[..12]) == want))
}

pub(super) fn aes128_block_encrypt(
    key: &[u8; 16],
    input: &[u8; 16],
) -> Result<[u8; 16], OutboundError> {
    let cipher = <Aes128 as BlockKeyInit>::new_from_slice(key)
        .map_err(|err| OutboundError::BadVmess(err.to_string()))?;
    let mut block = GenericArray::clone_from_slice(input);
    cipher.encrypt_block(&mut block);
    let mut out = [0_u8; 16];
    out.copy_from_slice(&block);
    Ok(out)
}

pub(super) fn aes128_block_decrypt(
    key: &[u8; 16],
    input: &[u8; 16],
) -> Result<[u8; 16], OutboundError> {
    let cipher = <Aes128 as BlockKeyInit>::new_from_slice(key)
        .map_err(|err| OutboundError::BadVmess(err.to_string()))?;
    let mut block = GenericArray::clone_from_slice(input);
    cipher.decrypt_block(&mut block);
    let mut out = [0_u8; 16];
    out.copy_from_slice(&block);
    Ok(out)
}

pub(super) fn aes128_gcm_encrypt(
    key: &[u8; 16],
    nonce: &[u8; 12],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, OutboundError> {
    let cipher =
        Aes128Gcm::new_from_slice(key).map_err(|err| OutboundError::BadVmess(err.to_string()))?;
    cipher
        .encrypt(
            AesNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|err| OutboundError::BadVmess(err.to_string()))
}

pub(super) fn aes128_gcm_decrypt(
    key: &[u8; 16],
    nonce: &[u8; 12],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, OutboundError> {
    let cipher =
        Aes128Gcm::new_from_slice(key).map_err(|err| OutboundError::BadVmess(err.to_string()))?;
    cipher
        .decrypt(
            AesNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|err| OutboundError::BadVmess(err.to_string()))
}

#[derive(Clone)]
pub(super) enum HashSpec {
    Sha256,
    Hmac { hash: Box<HashSpec>, key: Vec<u8> },
}

pub(super) fn kdf(key: &[u8], path: &[&[u8]]) -> [u8; 32] {
    let mut spec = HashSpec::Hmac {
        hash: Box::new(HashSpec::Sha256),
        key: KDF_SALT_VMESS_AEAD_KDF.to_vec(),
    };
    for item in path {
        spec = HashSpec::Hmac {
            hash: Box::new(spec),
            key: item.to_vec(),
        };
    }
    hash_digest(&spec, key)
}

pub(super) fn kdf16(key: &[u8], path: &[&[u8]]) -> [u8; 16] {
    let digest = kdf(key, path);
    let mut out = [0_u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

pub(super) fn kdf12(key: &[u8], path: &[&[u8]]) -> [u8; 12] {
    let digest = kdf(key, path);
    let mut out = [0_u8; 12];
    out.copy_from_slice(&digest[..12]);
    out
}

pub(super) fn hash_digest(spec: &HashSpec, data: &[u8]) -> [u8; 32] {
    match spec {
        HashSpec::Sha256 => {
            let mut hasher = Sha256::new();
            Digest::update(&mut hasher, data);
            let digest = hasher.finalize();
            let mut out = [0_u8; 32];
            out.copy_from_slice(&digest);
            out
        }
        HashSpec::Hmac { hash, key } => hmac_digest(hash, key, data),
    }
}

pub(super) fn hmac_digest(hash: &HashSpec, key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut key_block = [0_u8; 64];
    if key.len() > 64 {
        key_block[..32].copy_from_slice(&hash_digest(hash, key));
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }
    let mut inner_pad = [0x36_u8; 64];
    let mut outer_pad = [0x5c_u8; 64];
    for i in 0..64 {
        inner_pad[i] ^= key_block[i];
        outer_pad[i] ^= key_block[i];
    }
    let mut inner_input = Vec::with_capacity(64 + data.len());
    inner_input.extend_from_slice(&inner_pad);
    inner_input.extend_from_slice(data);
    let inner = hash_digest(hash, &inner_input);
    let mut outer_input = Vec::with_capacity(96);
    outer_input.extend_from_slice(&outer_pad);
    outer_input.extend_from_slice(&inner);
    hash_digest(hash, &outer_input)
}

pub(super) fn sha256_16(input: &[u8; 16]) -> [u8; 16] {
    let digest = Sha256::digest(input);
    let mut out = [0_u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

pub(super) fn crc32_ieee(input: &[u8]) -> u32 {
    let mut crc = 0xffff_ffff_u32;
    for byte in input {
        crc ^= *byte as u32;
        for _ in 0..8 {
            if crc & 1 == 1 {
                crc = (crc >> 1) ^ 0xedb8_8320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

pub(super) fn fnv1a32(input: &[u8]) -> u32 {
    let mut hash = 0x811c_9dc5_u32;
    for byte in input {
        hash ^= *byte as u32;
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash
}

pub(super) fn parse_uuid_bytes(input: &str) -> Result<[u8; 16], OutboundError> {
    let mut hex = String::with_capacity(32);
    for ch in input.chars() {
        if ch == '-' {
            continue;
        }
        if !ch.is_ascii_hexdigit() {
            return Err(OutboundError::BadVmess(format!(
                "bad VMess UUID character: {ch:?}"
            )));
        }
        hex.push(ch);
    }
    if hex.len() != 32 {
        return Err(OutboundError::BadVmess(format!(
            "bad VMess UUID length: {}",
            input.len()
        )));
    }
    let mut out = [0_u8; 16];
    for (idx, byte) in out.iter_mut().enumerate() {
        let start = idx * 2;
        *byte = u8::from_str_radix(&hex[start..start + 2], 16)
            .map_err(|err| OutboundError::BadVmess(err.to_string()))?;
    }
    Ok(out)
}

pub(super) fn unix_timestamp_now() -> Result<u64, OutboundError> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| OutboundError::BadVmess(err.to_string()))?
        .as_secs())
}

pub(super) fn read_exact(
    stream: &mut impl Read,
    buf: &mut [u8],
    context: &str,
) -> Result<(), OutboundError> {
    stream
        .read_exact(buf)
        .map_err(|err| OutboundError::BadVmess(format!("read {context} failed: {err}")))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_uuid_bytes_accepts_canonical_hex_uuid() {
        let parsed = parse_uuid_bytes("7c12c745-63a5-433d-9e60-022e469b5bd4").unwrap();
        assert_eq!(parsed.len(), 16);
    }

    #[test]
    fn parse_uuid_bytes_rejects_non_hex_chars_without_panicking() {
        // 32 characters including a 3-byte UTF-8 char ('€'). The old
        // implementation sliced the dedashed string by byte offsets and panicked
        // on a mid-character boundary; it must now return BadVmess instead.
        let input = "\u{20ac}1234567890123456789012345678901";
        assert_eq!(input.len(), 34);
        assert_eq!(input.chars().count(), 32);

        let err =
            parse_uuid_bytes(input).expect_err("non-hex VMess UUID must be rejected, not panic");
        assert!(matches!(err, OutboundError::BadVmess(_)));

        // Plain non-hex ASCII characters are also rejected up front.
        let err = parse_uuid_bytes("gggggggggggggggggggggggggggggggg")
            .expect_err("non-hex ASCII VMess UUID must be rejected");
        assert!(matches!(err, OutboundError::BadVmess(_)));
    }
}
