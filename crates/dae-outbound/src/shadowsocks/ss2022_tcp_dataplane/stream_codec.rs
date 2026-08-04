use super::*;
pub(super) struct Ss2022StreamCodec {
    pub(super) cipher: Ss2022AeadCipher,
    pub(super) nonce: Vec<u8>,
    pub(super) tag_len: usize,
}

impl Ss2022StreamCodec {
    pub(super) fn new(
        conf: &CipherConf2022,
        psk: &[u8],
        salt: &[u8],
    ) -> Result<Self, OutboundError> {
        let subkey = derive_subkey(psk, salt, conf.key_len, SESSION_SUBKEY_CONTEXT);
        Ok(Self {
            cipher: Ss2022AeadCipher::new(conf.cipher, &subkey)?,
            nonce: vec![0_u8; conf.nonce_len],
            tag_len: conf.tag_len,
        })
    }

    pub(super) fn encrypt_next(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, OutboundError> {
        let encrypted = self.cipher.encrypt(&self.nonce, plaintext)?;
        increment_nonce_le(&mut self.nonce);
        Ok(encrypted)
    }

    pub(super) fn decrypt_next(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, OutboundError> {
        let plain = self.cipher.decrypt(&self.nonce, ciphertext)?;
        increment_nonce_le(&mut self.nonce);
        Ok(plain)
    }

    pub(super) fn encrypt_next_in_place(
        &mut self,
        plaintext: &mut [u8],
        tag: &mut [u8],
    ) -> Result<(), OutboundError> {
        self.cipher.encrypt_in_place(&self.nonce, plaintext, tag)?;
        increment_nonce_le(&mut self.nonce);
        Ok(())
    }

    pub(super) fn decrypt_next_in_place(
        &mut self,
        ciphertext: &mut [u8],
        tag: &[u8],
    ) -> Result<(), OutboundError> {
        self.cipher.decrypt_in_place(&self.nonce, ciphertext, tag)?;
        increment_nonce_le(&mut self.nonce);
        Ok(())
    }
}

pub(super) enum Ss2022AeadCipher {
    Aes128(Box<Aes128Gcm>),
    Aes256(Box<Aes256Gcm>),
    ChaCha(Box<ChaCha20Poly1305>),
}

impl Ss2022AeadCipher {
    pub(super) fn new(cipher: &str, key: &[u8]) -> Result<Self, OutboundError> {
        match cipher {
            "2022-blake3-aes-128-gcm" => Ok(Self::Aes128(Box::new(
                Aes128Gcm::new_from_slice(key).map_err(|_| {
                    OutboundError::BadShadowsocks("bad SS2022 aes-128 key".to_owned())
                })?,
            ))),
            "2022-blake3-aes-256-gcm" => Ok(Self::Aes256(Box::new(
                Aes256Gcm::new_from_slice(key).map_err(|_| {
                    OutboundError::BadShadowsocks("bad SS2022 aes-256 key".to_owned())
                })?,
            ))),
            "2022-blake3-chacha20-poly1305" => Ok(Self::ChaCha(Box::new(
                ChaCha20Poly1305::new_from_slice(key).map_err(|_| {
                    OutboundError::BadShadowsocks("bad SS2022 chacha key".to_owned())
                })?,
            ))),
            _ => Err(OutboundError::BadShadowsocks(format!(
                "unsupported SS2022 cipher: {cipher}"
            ))),
        }
    }

    pub(super) fn encrypt(&self, nonce: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, OutboundError> {
        match self {
            Self::Aes128(cipher) => cipher
                .encrypt(aes_gcm::Nonce::from_slice(nonce), plaintext)
                .map_err(|_| OutboundError::BadShadowsocks("SS2022 encrypt failed".to_owned())),
            Self::Aes256(cipher) => cipher
                .encrypt(aes_gcm::Nonce::from_slice(nonce), plaintext)
                .map_err(|_| OutboundError::BadShadowsocks("SS2022 encrypt failed".to_owned())),
            Self::ChaCha(cipher) => cipher
                .encrypt(chacha20poly1305::Nonce::from_slice(nonce), plaintext)
                .map_err(|_| OutboundError::BadShadowsocks("SS2022 encrypt failed".to_owned())),
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
                .map_err(|_| OutboundError::BadShadowsocks("SS2022 decrypt failed".to_owned())),
            Self::Aes256(cipher) => cipher
                .decrypt(aes_gcm::Nonce::from_slice(nonce), ciphertext)
                .map_err(|_| OutboundError::BadShadowsocks("SS2022 decrypt failed".to_owned())),
            Self::ChaCha(cipher) => cipher
                .decrypt(chacha20poly1305::Nonce::from_slice(nonce), ciphertext)
                .map_err(|_| OutboundError::BadShadowsocks("SS2022 decrypt failed".to_owned())),
        }
    }

    fn encrypt_in_place(
        &self,
        nonce: &[u8],
        plaintext: &mut [u8],
        tag_out: &mut [u8],
    ) -> Result<(), OutboundError> {
        if tag_out.len() != 16 {
            return Err(OutboundError::BadShadowsocks(format!(
                "SS2022 tag length must be 16, got {}",
                tag_out.len()
            )));
        }
        let tag = match self {
            Self::Aes128(cipher) => {
                cipher.encrypt_in_place_detached(aes_gcm::Nonce::from_slice(nonce), &[], plaintext)
            }
            Self::Aes256(cipher) => {
                cipher.encrypt_in_place_detached(aes_gcm::Nonce::from_slice(nonce), &[], plaintext)
            }
            Self::ChaCha(cipher) => cipher.encrypt_in_place_detached(
                chacha20poly1305::Nonce::from_slice(nonce),
                &[],
                plaintext,
            ),
        }
        .map_err(|_| OutboundError::BadShadowsocks("SS2022 encrypt failed".to_owned()))?;
        tag_out.copy_from_slice(&tag);
        Ok(())
    }

    fn decrypt_in_place(
        &self,
        nonce: &[u8],
        ciphertext: &mut [u8],
        tag: &[u8],
    ) -> Result<(), OutboundError> {
        if tag.len() != 16 {
            return Err(OutboundError::BadShadowsocks(format!(
                "SS2022 tag length must be 16, got {}",
                tag.len()
            )));
        }
        let tag = GenericArray::from_slice(tag);
        match self {
            Self::Aes128(cipher) => cipher.decrypt_in_place_detached(
                aes_gcm::Nonce::from_slice(nonce),
                &[],
                ciphertext,
                tag,
            ),
            Self::Aes256(cipher) => cipher.decrypt_in_place_detached(
                aes_gcm::Nonce::from_slice(nonce),
                &[],
                ciphertext,
                tag,
            ),
            Self::ChaCha(cipher) => cipher.decrypt_in_place_detached(
                chacha20poly1305::Nonce::from_slice(nonce),
                &[],
                ciphertext,
                tag,
            ),
        }
        .map_err(|_| OutboundError::BadShadowsocks("SS2022 decrypt failed".to_owned()))
    }
}
