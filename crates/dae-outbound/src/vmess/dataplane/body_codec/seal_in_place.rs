use super::*;

impl BodyCodec {
    pub(in crate::vmess::dataplane) fn new_owned_chunk_buffer(&self, prefix_len: usize) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(prefix_len + VMESS_AEAD_TCP_UPLOAD_BUFFER_SIZE);
        buffer.resize(prefix_len + self.chunk_payload_offset(), 0);
        buffer
    }

    pub(in crate::vmess::dataplane) fn chunk_payload_buffer<'a>(
        &self,
        buffer: &'a mut [u8; VMESS_AEAD_TCP_UPLOAD_BUFFER_SIZE],
    ) -> &'a mut [u8] {
        let payload_offset = self.chunk_payload_offset();
        &mut buffer[payload_offset..payload_offset + MAX_CHUNK_SIZE]
    }

    pub(in crate::vmess::dataplane) fn seal_chunk_in_place(
        &mut self,
        buffer: &mut [u8; VMESS_AEAD_TCP_UPLOAD_BUFFER_SIZE],
        payload_len: usize,
    ) -> Result<usize, OutboundError> {
        if payload_len > MAX_CHUNK_SIZE {
            return Err(OutboundError::BadVmess(format!(
                "VMess payload too large for one VMess body chunk: {payload_len} bytes"
            )));
        }
        if matches!(self.cipher, BodyCipher::Raw) {
            return Ok(payload_len);
        }

        let padding_len = self.size.next_padding_len() as usize;
        let payload_offset = self.chunk_payload_offset();
        let mut authentication = [0_u8; MAX_CHUNK_AUTHENTICATION_SIZE];
        let authentication_len = self.seal_payload_in_place(
            &mut buffer[payload_offset..payload_offset + payload_len],
            &mut authentication,
        )?;
        let encoded_len = payload_len + authentication_len;
        let size = encoded_len + padding_len;
        if size > u16::MAX as usize {
            return Err(OutboundError::BadVmess(format!(
                "VMess chunk too large: {size} bytes"
            )));
        }

        let authentication_start = payload_offset + payload_len;
        buffer[authentication_start..authentication_start + authentication_len]
            .copy_from_slice(&authentication[..authentication_len]);
        buffer[..2].copy_from_slice(&self.size.encode_size(size as u16));
        let padding_start = payload_offset + encoded_len;
        if padding_len != 0 {
            getrandom::fill(&mut buffer[padding_start..padding_start + padding_len]).map_err(
                |err| OutboundError::BadVmess(format!("generate VMess body padding: {err}")),
            )?;
        }
        Ok(2 + size)
    }

    pub(in crate::vmess::dataplane) fn seal_owned_chunk_in_place(
        &mut self,
        buffer: &mut Vec<u8>,
        prefix_len: usize,
        payload_len: usize,
    ) -> Result<usize, OutboundError> {
        if payload_len > MAX_CHUNK_SIZE {
            return Err(OutboundError::BadVmess(format!(
                "VMess payload too large for one VMess body chunk: {payload_len} bytes"
            )));
        }
        let payload_offset = prefix_len
            .checked_add(self.chunk_payload_offset())
            .ok_or_else(|| OutboundError::BadVmess("VMess upload prefix overflow".to_owned()))?;
        let payload_end = payload_offset
            .checked_add(payload_len)
            .ok_or_else(|| OutboundError::BadVmess("VMess upload payload overflow".to_owned()))?;
        if buffer.len() != payload_end {
            return Err(OutboundError::BadVmess(format!(
                "VMess owned upload buffer has {} bytes, expected {payload_end}",
                buffer.len()
            )));
        }
        if matches!(self.cipher, BodyCipher::Raw) {
            return Ok(payload_len);
        }

        let padding_len = self.size.next_padding_len() as usize;
        let mut authentication = [0_u8; MAX_CHUNK_AUTHENTICATION_SIZE];
        let authentication_len = self.seal_payload_in_place(
            &mut buffer[payload_offset..payload_end],
            &mut authentication,
        )?;
        let encoded_len = payload_len + authentication_len;
        let size = encoded_len + padding_len;
        if size > u16::MAX as usize {
            return Err(OutboundError::BadVmess(format!(
                "VMess chunk too large: {size} bytes"
            )));
        }

        buffer.extend_from_slice(&authentication[..authentication_len]);
        let padding_start = buffer.len();
        buffer.resize(padding_start + padding_len, 0);
        if padding_len != 0 {
            getrandom::fill(&mut buffer[padding_start..]).map_err(|err| {
                OutboundError::BadVmess(format!("generate VMess body padding: {err}"))
            })?;
        }
        buffer[prefix_len..prefix_len + 2].copy_from_slice(&self.size.encode_size(size as u16));
        Ok(2 + size)
    }

    fn chunk_payload_offset(&self) -> usize {
        if matches!(self.cipher, BodyCipher::Raw) {
            0
        } else {
            2
        }
    }

    fn seal_payload_in_place(
        &mut self,
        payload: &mut [u8],
        authentication: &mut [u8; MAX_CHUNK_AUTHENTICATION_SIZE],
    ) -> Result<usize, OutboundError> {
        match &self.cipher {
            BodyCipher::Aes128Gcm(cipher) => {
                cipher
                    .seal_in_place(&self.nonce.next(), payload, authentication, &[])
                    .map_err(|_| {
                        OutboundError::BadVmess("VMess AES-GCM body encryption failed".to_owned())
                    })?;
                Ok(MAX_CHUNK_AUTHENTICATION_SIZE)
            }
            BodyCipher::Chacha20Poly1305(cipher) => {
                let tag = cipher
                    .encrypt_in_place_detached(
                        ChaChaNonce::from_slice(&self.nonce.next()),
                        &[],
                        payload,
                    )
                    .map_err(|err| OutboundError::BadVmess(err.to_string()))?;
                authentication.copy_from_slice(&tag);
                Ok(tag.len())
            }
            BodyCipher::None => Ok(0),
            BodyCipher::Raw => unreachable!("raw VMess body bypasses chunk sealing"),
        }
    }
}
