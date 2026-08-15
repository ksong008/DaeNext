use super::*;
pub(super) fn seal_separate_payload(
    conf: &CipherConf2022,
    upsk: &[u8],
    separate_header: &[u8; 16],
    message: &[u8],
) -> Result<Vec<u8>, OutboundError> {
    let subkey = derive_session_subkey(upsk, &separate_header[..8]);
    let cipher = Ss2022SeparatePayloadCipher::new(conf.cipher, &subkey[..conf.key_len])?;
    cipher.encrypt(&separate_header[4..16], message)
}

pub(super) fn separate_payload_cipher(
    conf: &CipherConf2022,
    upsk: &[u8],
    session_id: &[u8; 8],
) -> Result<Ss2022SeparatePayloadCipher, OutboundError> {
    let subkey = derive_session_subkey(upsk, session_id);
    Ss2022SeparatePayloadCipher::new(conf.cipher, &subkey[..conf.key_len])
}

pub(super) fn open_separate_payload(
    conf: &CipherConf2022,
    upsk: &[u8],
    separate_header: &[u8; 16],
    input: &[u8],
) -> Result<Vec<u8>, OutboundError> {
    let subkey = derive_session_subkey(upsk, &separate_header[..8]);
    let cipher = Ss2022SeparatePayloadCipher::new(conf.cipher, &subkey[..conf.key_len])?;
    cipher.decrypt(&separate_header[4..16], input)
}

pub(super) enum Ss2022SeparatePayloadCipher {
    Aes128(Aes128Gcm),
    Aes256(Aes256Gcm),
}

impl Ss2022SeparatePayloadCipher {
    pub(super) fn new(cipher: &str, key: &[u8]) -> Result<Self, OutboundError> {
        match cipher {
            "2022-blake3-aes-128-gcm" => Ok(Self::Aes128(Aes128Gcm::new_from_slice(key).map_err(
                |_| OutboundError::BadShadowsocks("bad SS2022 aes-128 UDP key".to_owned()),
            )?)),
            "2022-blake3-aes-256-gcm" => Ok(Self::Aes256(Aes256Gcm::new_from_slice(key).map_err(
                |_| OutboundError::BadShadowsocks("bad SS2022 aes-256 UDP key".to_owned()),
            )?)),
            _ => Err(OutboundError::BadShadowsocks(format!(
                "SS2022 cipher does not use separate UDP payload AEAD: {cipher}"
            ))),
        }
    }

    pub(super) fn encrypt(&self, nonce: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, OutboundError> {
        match self {
            Self::Aes128(cipher) => cipher
                .encrypt(aes_gcm::Nonce::from_slice(nonce), plaintext)
                .map_err(|_| OutboundError::BadShadowsocks("SS2022 UDP encrypt failed".to_owned())),
            Self::Aes256(cipher) => cipher
                .encrypt(aes_gcm::Nonce::from_slice(nonce), plaintext)
                .map_err(|_| OutboundError::BadShadowsocks("SS2022 UDP encrypt failed".to_owned())),
        }
    }

    pub(super) fn decrypt(
        &self,
        nonce: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, OutboundError> {
        match self {
            Self::Aes128(cipher) => cipher
                .decrypt(aes_gcm::Nonce::from_slice(nonce), ciphertext)
                .map_err(|_| OutboundError::BadShadowsocks("SS2022 UDP decrypt failed".to_owned())),
            Self::Aes256(cipher) => cipher
                .decrypt(aes_gcm::Nonce::from_slice(nonce), ciphertext)
                .map_err(|_| OutboundError::BadShadowsocks("SS2022 UDP decrypt failed".to_owned())),
        }
    }
}
