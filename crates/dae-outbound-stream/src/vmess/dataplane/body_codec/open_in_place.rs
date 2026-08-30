use std::ops::Range;

use super::*;

impl BodyCodec {
    pub(in crate::vmess::dataplane) fn try_open_chunk_in_place_from_buffer(
        &mut self,
        input: &mut [u8],
        cursor: &mut usize,
        pending: &mut Option<PendingOpenChunk>,
    ) -> Result<Option<Range<usize>>, OutboundError> {
        if *cursor > input.len() {
            return Err(OutboundError::BadVmess(
                "VMess response cursor exceeded buffered bytes".to_owned(),
            ));
        }
        if matches!(self.cipher, BodyCipher::Raw) {
            if *cursor == input.len() {
                return Ok(None);
            }
            let payload = *cursor..input.len();
            *cursor = input.len();
            return Ok(Some(payload));
        }

        if pending.is_none() {
            if input.len() - *cursor < 2 {
                return Ok(None);
            }
            let size_buf = [input[*cursor], input[*cursor + 1]];
            let padding_len = self.size.next_padding_len() as usize;
            let size = self.size.decode_size(size_buf) as usize;
            self.validate_encoded_size(size, padding_len)?;
            *cursor += 2;
            *pending = Some(PendingOpenChunk { size, padding_len });
        }

        let pending_chunk = pending
            .as_ref()
            .ok_or_else(|| OutboundError::BadVmess("missing pending VMess chunk".to_owned()))?;
        if input.len() - *cursor < pending_chunk.size {
            return Ok(None);
        }

        let chunk_start = *cursor;
        let chunk_end = chunk_start + pending_chunk.size;
        let encoded_end = chunk_end - pending_chunk.padding_len;
        let plain_len = self.open_payload_in_place(&mut input[chunk_start..encoded_end])?;
        let payload = chunk_start..chunk_start + plain_len;
        *cursor = chunk_end;
        *pending = None;
        Ok(Some(payload))
    }

    fn open_payload_in_place(&mut self, payload: &mut [u8]) -> Result<usize, OutboundError> {
        match &self.cipher {
            BodyCipher::Aes128Gcm(cipher) => {
                let plain_len = payload
                    .len()
                    .checked_sub(MAX_CHUNK_AUTHENTICATION_SIZE)
                    .ok_or_else(|| {
                        OutboundError::BadVmess(
                            "VMess AES-GCM body chunk is shorter than its tag".to_owned(),
                        )
                    })?;
                let (plain, authentication) = payload.split_at_mut(plain_len);
                cipher
                    .open_in_place(&self.nonce.next(), plain, authentication, &[])
                    .map_err(|_| {
                        OutboundError::BadVmess("VMess AES-GCM body decryption failed".to_owned())
                    })?;
                Ok(plain_len)
            }
            BodyCipher::Chacha20Poly1305(cipher) => {
                let plain_len = payload
                    .len()
                    .checked_sub(MAX_CHUNK_AUTHENTICATION_SIZE)
                    .ok_or_else(|| {
                        OutboundError::BadVmess(
                            "VMess ChaCha20-Poly1305 body chunk is shorter than its tag".to_owned(),
                        )
                    })?;
                let (plain, authentication) = payload.split_at_mut(plain_len);
                let authentication = GenericArray::from_slice(authentication);
                cipher
                    .decrypt_in_place_detached(
                        ChaChaNonce::from_slice(&self.nonce.next()),
                        &[],
                        plain,
                        authentication,
                    )
                    .map_err(|err| OutboundError::BadVmess(err.to_string()))?;
                Ok(plain_len)
            }
            BodyCipher::None => Ok(payload.len()),
            BodyCipher::Raw => unreachable!("raw VMess body bypasses chunk opening"),
        }
    }
}
