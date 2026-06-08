struct Ss2022StreamCodec {
    cipher: Ss2022AeadCipher,
    nonce: Vec<u8>,
    tag_len: usize,
}

impl Ss2022StreamCodec {
    fn new(conf: &CipherConf2022, psk: &[u8], salt: &[u8]) -> Result<Self, OutboundError> {
        let subkey = derive_subkey(psk, salt, conf.key_len, SESSION_SUBKEY_CONTEXT);
        Ok(Self {
            cipher: Ss2022AeadCipher::new(conf.cipher, &subkey)?,
            nonce: vec![0_u8; conf.nonce_len],
            tag_len: conf.tag_len,
        })
    }

    fn encrypt_next(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, OutboundError> {
        let encrypted = self.cipher.encrypt(&self.nonce, plaintext)?;
        increment_nonce_le(&mut self.nonce);
        Ok(encrypted)
    }

    fn decrypt_next(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, OutboundError> {
        let plain = self.cipher.decrypt(&self.nonce, ciphertext)?;
        increment_nonce_le(&mut self.nonce);
        Ok(plain)
    }
}

enum Ss2022AeadCipher {
    Aes128(Box<Aes128Gcm>),
    Aes256(Box<Aes256Gcm>),
    ChaCha(Box<ChaCha20Poly1305>),
}

impl Ss2022AeadCipher {
    fn new(cipher: &str, key: &[u8]) -> Result<Self, OutboundError> {
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

    fn encrypt(&self, nonce: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, OutboundError> {
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

    fn decrypt(&self, nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, OutboundError> {
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
}
