use super::*;
pub(super) fn encode_udp_identity_headers(
    psk_list: &[Vec<u8>],
    separate_header: &[u8; 16],
) -> Result<Vec<u8>, OutboundError> {
    if psk_list.len() <= 1 {
        return Ok(Vec::new());
    }
    let mut out = Vec::with_capacity((psk_list.len() - 1) * AES_BLOCK_LEN);
    for window in psk_list.windows(2) {
        out.extend_from_slice(&encode_udp_identity_header(
            &window[0],
            &window[1],
            separate_header,
        )?);
    }
    Ok(out)
}

pub(super) fn validate_udp_identity_headers(
    psk_list: &[Vec<u8>],
    separate_header: &[u8; 16],
    observed: &[u8],
) -> Result<(), OutboundError> {
    if psk_list.len() <= 1 {
        return Ok(());
    }
    let mut offset = 0;
    for window in psk_list.windows(2) {
        let expected = encode_udp_identity_header(&window[0], &window[1], separate_header)?;
        if observed.len() < offset + AES_BLOCK_LEN
            || observed[offset..offset + AES_BLOCK_LEN] != expected
        {
            return Err(OutboundError::BadShadowsocks(
                "SS2022 UDP identity header mismatch".to_owned(),
            ));
        }
        offset += AES_BLOCK_LEN;
    }
    Ok(())
}

pub(super) fn encode_udp_identity_header(
    current_psk: &[u8],
    next_psk: &[u8],
    separate_header: &[u8; 16],
) -> Result<[u8; 16], OutboundError> {
    let mut next_hash = [0_u8; 64];
    let mut hasher = blake3::Hasher::new();
    hasher.update(next_psk);
    hasher.finalize_xof().fill(&mut next_hash);
    let mut plain = [0_u8; 16];
    for index in 0..AES_BLOCK_LEN {
        plain[index] = next_hash[index] ^ separate_header[index];
    }
    encrypt_aes_block(current_psk, &plain)
}

pub(super) fn separate_header(session_id: [u8; 8], packet_id: u64) -> [u8; 16] {
    let mut header = [0_u8; 16];
    header[..8].copy_from_slice(&session_id);
    header[8..].copy_from_slice(&packet_id.to_be_bytes());
    header
}

pub(super) fn encrypt_aes_block(key: &[u8], plaintext: &[u8]) -> Result<[u8; 16], OutboundError> {
    Ss2022AesBlockCipher::new(key)?.encrypt_block(plaintext)
}

impl Ss2022AesBlockCipher {
    pub(super) fn new(key: &[u8]) -> Result<Self, OutboundError> {
        match key.len() {
            16 => Aes128::new_from_slice(key).map(Self::Aes128).map_err(|_| {
                OutboundError::BadShadowsocks("bad SS2022 aes-128 block key".to_owned())
            }),
            32 => Aes256::new_from_slice(key).map(Self::Aes256).map_err(|_| {
                OutboundError::BadShadowsocks("bad SS2022 aes-256 block key".to_owned())
            }),
            _ => Err(OutboundError::BadShadowsocks(format!(
                "unsupported SS2022 AES block key length: {}",
                key.len()
            ))),
        }
    }

    pub(super) fn encrypt_block(&self, plaintext: &[u8]) -> Result<[u8; 16], OutboundError> {
        if plaintext.len() != AES_BLOCK_LEN {
            return Err(OutboundError::BadShadowsocks(
                "SS2022 AES block plaintext must be 16 bytes".to_owned(),
            ));
        }
        let mut block = aes::cipher::generic_array::GenericArray::clone_from_slice(plaintext);
        match self {
            Self::Aes128(cipher) => cipher.encrypt_block(&mut block),
            Self::Aes256(cipher) => cipher.encrypt_block(&mut block),
        }
        let mut out = [0_u8; 16];
        out.copy_from_slice(&block);
        Ok(out)
    }

    pub(super) fn decrypt_block(&self, ciphertext: &[u8]) -> Result<[u8; 16], OutboundError> {
        if ciphertext.len() != AES_BLOCK_LEN {
            return Err(OutboundError::BadShadowsocks(
                "SS2022 AES block ciphertext must be 16 bytes".to_owned(),
            ));
        }
        let mut block = aes::cipher::generic_array::GenericArray::clone_from_slice(ciphertext);
        match self {
            Self::Aes128(cipher) => cipher.decrypt_block(&mut block),
            Self::Aes256(cipher) => cipher.decrypt_block(&mut block),
        }
        let mut out = [0_u8; 16];
        out.copy_from_slice(&block);
        Ok(out)
    }
}

pub(super) fn decrypt_aes_block(key: &[u8], ciphertext: &[u8]) -> Result<[u8; 16], OutboundError> {
    Ss2022AesBlockCipher::new(key)?.decrypt_block(ciphertext)
}
