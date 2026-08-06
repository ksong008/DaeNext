use super::*;
pub(super) struct Ss2022StreamCodec {
    pub(super) cipher: Ss2022AeadCipher,
    pub(super) nonce: [u8; SS2022_TCP_NONCE_LEN],
}

pub(super) const SS2022_TCP_NONCE_LEN: usize = 12;

impl Ss2022StreamCodec {
    pub(super) fn new(
        conf: &CipherConf2022,
        psk: &[u8],
        salt: &[u8],
    ) -> Result<Self, OutboundError> {
        if conf.nonce_len != SS2022_TCP_NONCE_LEN {
            return Err(OutboundError::BadShadowsocks(format!(
                "SS2022 TCP nonce length must be {SS2022_TCP_NONCE_LEN}, got {}",
                conf.nonce_len
            )));
        }
        if conf.tag_len != SS2022_TCP_TAG_LEN {
            return Err(OutboundError::BadShadowsocks(format!(
                "SS2022 TCP tag length must be {SS2022_TCP_TAG_LEN}, got {}",
                conf.tag_len
            )));
        }
        let subkey = derive_subkey(psk, salt, conf.key_len, SESSION_SUBKEY_CONTEXT);
        Ok(Self {
            cipher: Ss2022AeadCipher::new(conf.cipher, &subkey)?,
            nonce: [0_u8; SS2022_TCP_NONCE_LEN],
        })
    }

    pub(super) fn encrypt_next(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, OutboundError> {
        let encrypted = self.cipher.encrypt(&self.nonce, plaintext)?;
        increment_nonce_le_12(&mut self.nonce);
        Ok(encrypted)
    }

    pub(super) fn decrypt_next(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, OutboundError> {
        let plain = self.cipher.decrypt(&self.nonce, ciphertext)?;
        increment_nonce_le_12(&mut self.nonce);
        Ok(plain)
    }

    pub(super) fn encrypt_next_in_place(
        &mut self,
        plaintext: &mut [u8],
        tag: &mut [u8],
    ) -> Result<(), OutboundError> {
        self.cipher.encrypt_in_place(&self.nonce, plaintext, tag)?;
        increment_nonce_le_12(&mut self.nonce);
        Ok(())
    }

    pub(super) fn decrypt_next_in_place(
        &mut self,
        ciphertext: &mut [u8],
        tag: &[u8],
    ) -> Result<(), OutboundError> {
        self.cipher.decrypt_in_place(&self.nonce, ciphertext, tag)?;
        increment_nonce_le_12(&mut self.nonce);
        Ok(())
    }
}

pub(super) enum Ss2022AeadCipher {
    BoringAes128(Box<AeadCtx>),
    BoringAes256(Box<AeadCtx>),
    ChaCha(Box<ChaCha20Poly1305>),
}

impl Ss2022AeadCipher {
    pub(super) fn new(cipher: &str, key: &[u8]) -> Result<Self, OutboundError> {
        match cipher {
            "2022-blake3-aes-128-gcm" => Ok(Self::BoringAes128(Box::new(
                AeadCtx::new_default_tag(&Algorithm::aes_128_gcm(), key).map_err(|err| {
                    OutboundError::BadShadowsocks(format!("bad SS2022 aes-128 key: {err}"))
                })?,
            ))),
            "2022-blake3-aes-256-gcm" => Ok(Self::BoringAes256(Box::new(
                AeadCtx::new_default_tag(&Algorithm::aes_256_gcm(), key).map_err(|err| {
                    OutboundError::BadShadowsocks(format!("bad SS2022 aes-256 key: {err}"))
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
            Self::BoringAes128(cipher) | Self::BoringAes256(cipher) => {
                let mut output = plaintext.to_vec();
                let mut tag = [0_u8; SS2022_TCP_TAG_LEN];
                cipher
                    .seal_in_place(nonce, &mut output, &mut tag, &[])
                    .map_err(|_| {
                        OutboundError::BadShadowsocks("SS2022 encrypt failed".to_owned())
                    })?;
                output.extend_from_slice(&tag);
                Ok(output)
            }
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
            Self::BoringAes128(cipher) | Self::BoringAes256(cipher) => {
                let payload_len = ciphertext
                    .len()
                    .checked_sub(SS2022_TCP_TAG_LEN)
                    .ok_or_else(|| {
                        OutboundError::BadShadowsocks(
                            "SS2022 ciphertext is shorter than its tag".to_owned(),
                        )
                    })?;
                let mut output = ciphertext[..payload_len].to_vec();
                cipher
                    .open_in_place(nonce, &mut output, &ciphertext[payload_len..], &[])
                    .map_err(|_| {
                        OutboundError::BadShadowsocks("SS2022 decrypt failed".to_owned())
                    })?;
                Ok(output)
            }
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
        if let Self::BoringAes128(cipher) | Self::BoringAes256(cipher) = self {
            cipher
                .seal_in_place(nonce, plaintext, tag_out, &[])
                .map(|_| ())
                .map_err(|_| OutboundError::BadShadowsocks("SS2022 encrypt failed".to_owned()))?;
            return Ok(());
        }
        let tag = match self {
            Self::ChaCha(cipher) => cipher.encrypt_in_place_detached(
                chacha20poly1305::Nonce::from_slice(nonce),
                &[],
                plaintext,
            ),
            Self::BoringAes128(_) | Self::BoringAes256(_) => unreachable!(),
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
        if let Self::BoringAes128(cipher) | Self::BoringAes256(cipher) = self {
            return cipher
                .open_in_place(nonce, ciphertext, tag, &[])
                .map_err(|_| OutboundError::BadShadowsocks("SS2022 decrypt failed".to_owned()));
        }
        let tag = GenericArray::from_slice(tag);
        match self {
            Self::ChaCha(cipher) => cipher.decrypt_in_place_detached(
                chacha20poly1305::Nonce::from_slice(nonce),
                &[],
                ciphertext,
                tag,
            ),
            Self::BoringAes128(_) | Self::BoringAes256(_) => unreachable!(),
        }
        .map_err(|_| OutboundError::BadShadowsocks("SS2022 decrypt failed".to_owned()))
    }
}
