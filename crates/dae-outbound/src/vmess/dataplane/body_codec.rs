use super::*;
use tokio::io::AsyncReadExt as _;

enum BodyCipher {
    Aes128Gcm(Box<Aes128Gcm>),
    Chacha20Poly1305(ChaCha20Poly1305),
    None,
    Raw,
}

pub(super) struct BodyCodec {
    cipher: BodyCipher,
    nonce: ChunkNonce,
    size: ChunkSizeMask,
}

pub(super) struct PendingOpenChunk {
    size: usize,
    padding_len: usize,
}

impl BodyCodec {
    pub(super) fn new(
        key: [u8; 16],
        iv: [u8; 16],
        security: u8,
        options: u8,
    ) -> Result<Self, OutboundError> {
        let cipher = match security {
            VMESS_AEAD_SECURITY_AES_128_GCM => BodyCipher::Aes128Gcm(Box::new(
                Aes128Gcm::new_from_slice(&key)
                    .map_err(|err| OutboundError::BadVmess(err.to_string()))?,
            )),
            VMESS_AEAD_SECURITY_CHACHA20_POLY1305 => {
                let key = chacha20_poly1305_key(&key);
                BodyCipher::Chacha20Poly1305(
                    ChaCha20Poly1305::new_from_slice(&key)
                        .map_err(|err| OutboundError::BadVmess(err.to_string()))?,
                )
            }
            VMESS_AEAD_SECURITY_NONE if options & OPTION_CHUNK_STREAM == 0 => BodyCipher::Raw,
            VMESS_AEAD_SECURITY_NONE => BodyCipher::None,
            value => {
                return Err(OutboundError::BadVmess(format!(
                    "unsupported VMess body security: {value}"
                )));
            }
        };
        Ok(Self {
            cipher,
            nonce: ChunkNonce::new(&iv),
            size: ChunkSizeMask::new(&iv, options),
        })
    }

    pub(super) fn seal_chunk(&mut self, payload: &[u8]) -> Result<Vec<u8>, OutboundError> {
        if matches!(self.cipher, BodyCipher::Raw) {
            return Ok(payload.to_vec());
        }
        if payload.len() > MAX_CHUNK_SIZE {
            return Err(OutboundError::BadVmess(format!(
                "VMess payload too large for one VMess body chunk: {} bytes",
                payload.len()
            )));
        }
        let padding_len = self.size.next_padding_len() as usize;
        let encoded = self.seal_payload(payload)?;
        let size = encoded.len() + padding_len;
        if size > u16::MAX as usize {
            return Err(OutboundError::BadVmess(format!(
                "VMess chunk too large: {size} bytes"
            )));
        }
        let mut out = Vec::with_capacity(2 + size);
        out.extend_from_slice(&self.size.encode_size(size as u16));
        out.extend_from_slice(&encoded);
        let padding_start = out.len();
        out.resize(padding_start + padding_len, 0);
        if padding_len != 0 {
            getrandom::fill(&mut out[padding_start..]).map_err(|err| {
                OutboundError::BadVmess(format!("generate VMess body padding: {err}"))
            })?;
        }
        Ok(out)
    }

    pub(super) fn open_chunk<S>(
        &mut self,
        stream: &mut S,
    ) -> Result<(Vec<u8>, usize), OutboundError>
    where
        S: Read,
    {
        if matches!(self.cipher, BodyCipher::Raw) {
            let mut payload = vec![0_u8; MAX_CHUNK_SIZE];
            let read = stream
                .read(&mut payload)
                .map_err(|err| OutboundError::BadVmess(format!("read vmess raw body: {err}")))?;
            if read == 0 {
                return Err(OutboundError::BadVmess(
                    "read vmess raw body: early eof".to_owned(),
                ));
            }
            payload.truncate(read);
            return Ok((payload, read));
        }
        let mut size_buf = [0_u8; 2];
        read_exact(stream, &mut size_buf, "vmess chunk size")?;
        let padding_len = self.size.next_padding_len() as usize;
        let size = self.size.decode_size(size_buf) as usize;
        self.validate_encoded_size(size, padding_len)?;
        let mut chunk = vec![0_u8; size];
        read_exact(stream, &mut chunk, "vmess body chunk")?;
        let encoded_len = size - padding_len;
        let payload = self.open_payload(&chunk[..encoded_len])?;
        Ok((payload, 2 + size))
    }

    pub(super) async fn open_chunk_async<S>(
        &mut self,
        stream: &mut S,
    ) -> Result<(Vec<u8>, usize), OutboundError>
    where
        S: tokio::io::AsyncRead + Unpin,
    {
        if matches!(self.cipher, BodyCipher::Raw) {
            let mut payload = vec![0_u8; MAX_CHUNK_SIZE];
            let read = stream
                .read(&mut payload)
                .await
                .map_err(|err| OutboundError::BadVmess(format!("read vmess raw body: {err}")))?;
            if read == 0 {
                return Err(OutboundError::BadVmess(
                    "read vmess raw body: early eof".to_owned(),
                ));
            }
            payload.truncate(read);
            return Ok((payload, read));
        }
        let mut size_buf = [0_u8; 2];
        stream
            .read_exact(&mut size_buf)
            .await
            .map_err(|err| OutboundError::BadVmess(format!("read vmess chunk size: {err}")))?;
        let padding_len = self.size.next_padding_len() as usize;
        let size = self.size.decode_size(size_buf) as usize;
        self.validate_encoded_size(size, padding_len)?;
        let mut chunk = vec![0_u8; size];
        stream
            .read_exact(&mut chunk)
            .await
            .map_err(|err| OutboundError::BadVmess(format!("read vmess body chunk: {err}")))?;
        let encoded_len = size - padding_len;
        let payload = self.open_payload(&chunk[..encoded_len])?;
        Ok((payload, 2 + size))
    }

    pub(super) fn try_open_chunk_from_buffer(
        &mut self,
        input: &mut Vec<u8>,
        pending: &mut Option<PendingOpenChunk>,
    ) -> Result<Option<Vec<u8>>, OutboundError> {
        if matches!(self.cipher, BodyCipher::Raw) {
            return if input.is_empty() {
                Ok(None)
            } else {
                Ok(Some(std::mem::take(input)))
            };
        }
        if pending.is_none() {
            if input.len() < 2 {
                return Ok(None);
            }
            let size_buf = [input[0], input[1]];
            let padding_len = self.size.next_padding_len() as usize;
            let size = self.size.decode_size(size_buf) as usize;
            self.validate_encoded_size(size, padding_len)?;
            input.drain(..2);
            *pending = Some(PendingOpenChunk { size, padding_len });
        }
        let pending_chunk = pending
            .as_ref()
            .ok_or_else(|| OutboundError::BadVmess("missing pending VMess chunk".to_owned()))?;
        if input.len() < pending_chunk.size {
            return Ok(None);
        }
        let chunk: Vec<u8> = input.drain(..pending_chunk.size).collect();
        let encoded_len = pending_chunk.size - pending_chunk.padding_len;
        let payload = self.open_payload(&chunk[..encoded_len])?;
        *pending = None;
        Ok(Some(payload))
    }

    fn authentication_overhead(&self) -> usize {
        match self.cipher {
            BodyCipher::Aes128Gcm(_) | BodyCipher::Chacha20Poly1305(_) => 16,
            BodyCipher::None | BodyCipher::Raw => 0,
        }
    }

    fn validate_encoded_size(&self, size: usize, padding_len: usize) -> Result<(), OutboundError> {
        let minimum = padding_len + self.authentication_overhead();
        if size < minimum {
            return Err(OutboundError::BadVmess(format!(
                "bad VMess chunk size {size} with padding {padding_len}"
            )));
        }
        Ok(())
    }

    fn seal_payload(&mut self, payload: &[u8]) -> Result<Vec<u8>, OutboundError> {
        match &self.cipher {
            BodyCipher::Aes128Gcm(cipher) => cipher
                .encrypt(AesNonce::from_slice(&self.nonce.next()), payload)
                .map_err(|err| OutboundError::BadVmess(err.to_string())),
            BodyCipher::Chacha20Poly1305(cipher) => cipher
                .encrypt(ChaChaNonce::from_slice(&self.nonce.next()), payload)
                .map_err(|err| OutboundError::BadVmess(err.to_string())),
            BodyCipher::None => Ok(payload.to_vec()),
            BodyCipher::Raw => unreachable!("raw VMess body bypasses chunk sealing"),
        }
    }

    fn open_payload(&mut self, payload: &[u8]) -> Result<Vec<u8>, OutboundError> {
        match &self.cipher {
            BodyCipher::Aes128Gcm(cipher) => cipher
                .decrypt(AesNonce::from_slice(&self.nonce.next()), payload)
                .map_err(|err| OutboundError::BadVmess(err.to_string())),
            BodyCipher::Chacha20Poly1305(cipher) => cipher
                .decrypt(ChaChaNonce::from_slice(&self.nonce.next()), payload)
                .map_err(|err| OutboundError::BadVmess(err.to_string())),
            BodyCipher::None => Ok(payload.to_vec()),
            BodyCipher::Raw => unreachable!("raw VMess body bypasses chunk opening"),
        }
    }
}

fn chacha20_poly1305_key(key: &[u8; 16]) -> [u8; 32] {
    let first = Md5::digest(key);
    let second = Md5::digest(first);
    let mut expanded = [0_u8; 32];
    expanded[..16].copy_from_slice(&first);
    expanded[16..].copy_from_slice(&second);
    expanded
}

pub(super) struct ChunkNonce {
    pub(super) base: [u8; 12],
    pub(super) count: u16,
}

impl ChunkNonce {
    pub(super) fn new(iv: &[u8; 16]) -> Self {
        let mut base = [0_u8; 12];
        base[2..].copy_from_slice(&iv[2..12]);
        Self { base, count: 0 }
    }

    pub(super) fn next(&mut self) -> [u8; 12] {
        let mut nonce = self.base;
        nonce[..2].copy_from_slice(&self.count.to_be_bytes());
        self.count = self.count.wrapping_add(1);
        nonce
    }
}

pub(super) struct ChunkSizeMask {
    pub(super) reader: Option<Box<dyn XofReader + Send>>,
    pub(super) global_padding: bool,
}

impl ChunkSizeMask {
    pub(super) fn new(iv: &[u8; 16], options: u8) -> Self {
        if options & OPTION_CHUNK_LENGTH_MASKING == 0 {
            return Self {
                reader: None,
                global_padding: false,
            };
        }
        let mut shake = Shake128::default();
        Update::update(&mut shake, iv);
        Self {
            reader: Some(Box::new(shake.finalize_xof())),
            global_padding: options & OPTION_GLOBAL_PADDING == OPTION_GLOBAL_PADDING,
        }
    }

    pub(super) fn next_padding_len(&mut self) -> u16 {
        if self.global_padding {
            self.next_mask() % 64
        } else {
            0
        }
    }

    pub(super) fn encode_size(&mut self, size: u16) -> [u8; 2] {
        (size ^ self.next_mask()).to_be_bytes()
    }

    pub(super) fn decode_size(&mut self, encoded: [u8; 2]) -> u16 {
        u16::from_be_bytes(encoded) ^ self.next_mask()
    }

    pub(super) fn next_mask(&mut self) -> u16 {
        let Some(reader) = self.reader.as_mut() else {
            return 0;
        };
        let mut buf = [0_u8; 2];
        reader.read(&mut buf);
        u16::from_be_bytes(buf)
    }
}
