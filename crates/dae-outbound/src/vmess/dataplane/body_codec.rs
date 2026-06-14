use super::*;
use tokio::io::AsyncReadExt as _;

pub(super) struct BodyCodec {
    pub(super) cipher: Aes128Gcm,
    pub(super) nonce: ChunkNonce,
    pub(super) size: ChunkSizeMask,
}

pub(super) struct PendingOpenChunk {
    size: usize,
    padding_len: usize,
}

impl BodyCodec {
    pub(super) fn new(key: [u8; 16], iv: [u8; 16], options: u8) -> Result<Self, OutboundError> {
        let cipher = Aes128Gcm::new_from_slice(&key)
            .map_err(|err| OutboundError::BadVmess(err.to_string()))?;
        Ok(Self {
            cipher,
            nonce: ChunkNonce::new(&iv),
            size: ChunkSizeMask::new(&iv, options),
        })
    }

    pub(super) fn seal_chunk(&mut self, payload: &[u8]) -> Result<Vec<u8>, OutboundError> {
        if payload.len() > MAX_CHUNK_SIZE {
            return Err(OutboundError::BadVmess(format!(
                "VMess payload too large for one VMess AEAD chunk: {} bytes",
                payload.len()
            )));
        }
        let padding_len = self.size.next_padding_len() as usize;
        let encrypted = self
            .cipher
            .encrypt(Nonce::from_slice(&self.nonce.next()), payload)
            .map_err(|err| OutboundError::BadVmess(err.to_string()))?;
        let size = encrypted.len() + padding_len;
        if size > u16::MAX as usize {
            return Err(OutboundError::BadVmess(format!(
                "VMess chunk too large: {size} bytes"
            )));
        }
        let mut out = Vec::with_capacity(2 + size);
        out.extend_from_slice(&self.size.encode_size(size as u16));
        out.extend_from_slice(&encrypted);
        out.extend(std::iter::repeat_n(0xa5, padding_len));
        Ok(out)
    }

    pub(super) fn open_chunk<S>(
        &mut self,
        stream: &mut S,
    ) -> Result<(Vec<u8>, usize), OutboundError>
    where
        S: Read,
    {
        let mut size_buf = [0_u8; 2];
        read_exact(stream, &mut size_buf, "vmess chunk size")?;
        let padding_len = self.size.next_padding_len() as usize;
        let size = self.size.decode_size(size_buf) as usize;
        if size < padding_len + 16 {
            return Err(OutboundError::BadVmess(format!(
                "bad VMess chunk size {size} with padding {padding_len}"
            )));
        }
        let mut chunk = vec![0_u8; size];
        read_exact(stream, &mut chunk, "vmess encrypted chunk")?;
        let encrypted_len = size - padding_len;
        let payload = self
            .cipher
            .decrypt(
                Nonce::from_slice(&self.nonce.next()),
                &chunk[..encrypted_len],
            )
            .map_err(|err| OutboundError::BadVmess(err.to_string()))?;
        Ok((payload, 2 + size))
    }

    pub(super) async fn open_chunk_async<S>(
        &mut self,
        stream: &mut S,
    ) -> Result<(Vec<u8>, usize), OutboundError>
    where
        S: tokio::io::AsyncRead + Unpin,
    {
        let mut size_buf = [0_u8; 2];
        stream
            .read_exact(&mut size_buf)
            .await
            .map_err(|err| OutboundError::BadVmess(format!("read vmess chunk size: {err}")))?;
        let padding_len = self.size.next_padding_len() as usize;
        let size = self.size.decode_size(size_buf) as usize;
        if size < padding_len + 16 {
            return Err(OutboundError::BadVmess(format!(
                "bad VMess chunk size {size} with padding {padding_len}"
            )));
        }
        let mut chunk = vec![0_u8; size];
        stream
            .read_exact(&mut chunk)
            .await
            .map_err(|err| OutboundError::BadVmess(format!("read vmess encrypted chunk: {err}")))?;
        let encrypted_len = size - padding_len;
        let payload = self
            .cipher
            .decrypt(
                Nonce::from_slice(&self.nonce.next()),
                &chunk[..encrypted_len],
            )
            .map_err(|err| OutboundError::BadVmess(err.to_string()))?;
        Ok((payload, 2 + size))
    }

    pub(super) fn try_open_chunk_from_buffer(
        &mut self,
        input: &mut Vec<u8>,
        pending: &mut Option<PendingOpenChunk>,
    ) -> Result<Option<Vec<u8>>, OutboundError> {
        if pending.is_none() {
            if input.len() < 2 {
                return Ok(None);
            }
            let size_buf = [input[0], input[1]];
            let padding_len = self.size.next_padding_len() as usize;
            let size = self.size.decode_size(size_buf) as usize;
            if size < padding_len + 16 {
                return Err(OutboundError::BadVmess(format!(
                    "bad VMess chunk size {size} with padding {padding_len}"
                )));
            }
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
        let encrypted_len = pending_chunk.size - pending_chunk.padding_len;
        let payload = self
            .cipher
            .decrypt(
                Nonce::from_slice(&self.nonce.next()),
                &chunk[..encrypted_len],
            )
            .map_err(|err| OutboundError::BadVmess(err.to_string()))?;
        *pending = None;
        Ok(Some(payload))
    }
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
