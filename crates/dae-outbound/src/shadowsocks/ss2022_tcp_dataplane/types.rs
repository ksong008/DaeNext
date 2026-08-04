use super::*;
pub(super) const SESSION_SUBKEY_CONTEXT: &str = "shadowsocks 2022 session subkey";
pub(super) const IDENTITY_SUBKEY_CONTEXT: &str = "shadowsocks 2022 identity subkey";
pub const SS2022_TCP_TAG_LEN: usize = 16;
pub const SS2022_TCP_RELAY_PAYLOAD_SIZE: usize = 16 * 1024;
pub const SS2022_TCP_RELAY_UPLOAD_BUFFER_SIZE: usize =
    2 + SS2022_TCP_TAG_LEN + SS2022_TCP_RELAY_PAYLOAD_SIZE + SS2022_TCP_TAG_LEN;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ss2022TcpSalts<'a> {
    pub client: &'a [u8],
    pub server: &'a [u8],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ss2022TcpExchangeReport {
    pub server: String,
    pub target: String,
    pub cipher: String,
    pub psk_count: usize,
    pub upsk_index: usize,
    pub key_len: usize,
    pub client_salt_len: usize,
    pub server_salt_len: usize,
    pub request_header_type: u8,
    pub response_header_type: u8,
    pub fixed_header_len: usize,
    pub variable_header_len: usize,
    pub target_metadata_len: usize,
    pub request_salt_echo_validated: bool,
    pub identity_header_count: usize,
    pub identity_header_bytes_len: usize,
    pub identity_header_validated: bool,
    pub payload_len: usize,
    pub echoed_payload: Vec<u8>,
    pub multi_psk_identity_header_dataplane_admitted: bool,
    pub ss2022_udp_true_dataplane_admitted: bool,
    pub true_dataplane: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ss2022TcpClientRequest {
    pub target: String,
    pub request_salt_len: usize,
    pub psk_count: usize,
    pub upsk_index: usize,
    pub request_header_type: u8,
    pub timestamp: u64,
    pub fixed_header_len: usize,
    pub variable_header_len: usize,
    pub target_metadata_len: usize,
    pub padding_len: usize,
    pub identity_header_count: usize,
    pub identity_header_bytes_len: usize,
    pub identity_header_validated: bool,
    pub payload: Vec<u8>,
}

pub struct Ss2022TcpClientStreamEncoder {
    pub(super) codec: Ss2022StreamCodec,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ss2022TcpServerStreamStart {
    pub server_salt_len: usize,
    pub response_header_type: u8,
    pub request_salt_echo_validated: bool,
    pub payload: Vec<u8>,
}

pub struct Ss2022TcpServerStreamDecoder {
    pub(super) codec: Ss2022StreamCodec,
}

impl Ss2022TcpClientStreamEncoder {
    pub fn encode_chunk(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, OutboundError> {
        let mut out = Vec::new();
        for chunk in plaintext.chunks(TCP_CHUNK_MAX_LEN) {
            out.extend_from_slice(
                &self
                    .codec
                    .encrypt_next(&(chunk.len() as u16).to_be_bytes())?,
            );
            out.extend_from_slice(&self.codec.encrypt_next(chunk)?);
        }
        Ok(out)
    }

    pub fn chunk_payload_buffer<'a>(&self, buffer: &'a mut [u8]) -> &'a mut [u8] {
        let payload_offset = 2 + self.codec.tag_len;
        let reserved_bytes = payload_offset + self.codec.tag_len;
        let payload_capacity = buffer
            .len()
            .saturating_sub(reserved_bytes)
            .min(TCP_CHUNK_MAX_LEN);
        &mut buffer[payload_offset..payload_offset + payload_capacity]
    }

    pub fn encode_chunk_in_place(
        &mut self,
        buffer: &mut [u8],
        payload_len: usize,
    ) -> Result<usize, OutboundError> {
        let tag_len = self.codec.tag_len;
        let payload_offset = 2 + tag_len;
        let wire_len = payload_offset
            .checked_add(payload_len)
            .and_then(|len| len.checked_add(tag_len))
            .ok_or_else(|| {
                OutboundError::BadShadowsocks("SS2022 upload length overflow".to_owned())
            })?;
        if payload_len > TCP_CHUNK_MAX_LEN || wire_len > buffer.len() {
            return Err(OutboundError::BadShadowsocks(format!(
                "SS2022 upload payload length {payload_len} exceeds in-place buffer capacity"
            )));
        }
        buffer[..2].copy_from_slice(&(payload_len as u16).to_be_bytes());
        let (length_wire, payload_wire) = buffer[..wire_len].split_at_mut(payload_offset);
        let (length_plain, length_tag) = length_wire.split_at_mut(2);
        self.codec.encrypt_next_in_place(length_plain, length_tag)?;
        let (payload_plain, payload_tag) = payload_wire.split_at_mut(payload_len);
        self.codec
            .encrypt_next_in_place(payload_plain, payload_tag)?;
        Ok(wire_len)
    }
}

impl Ss2022TcpServerStreamDecoder {
    pub fn read_next_chunk<S>(&mut self, stream: &mut S) -> Result<Vec<u8>, OutboundError>
    where
        S: Read,
    {
        let len_plain = read_encrypted_exact(stream, &mut self.codec, 2)?;
        let chunk_len = u16::from_be_bytes([len_plain[0], len_plain[1]]) as usize;
        read_encrypted_exact(stream, &mut self.codec, chunk_len)
    }

    pub async fn read_next_chunk_async<S>(
        &mut self,
        stream: &mut S,
    ) -> Result<Vec<u8>, OutboundError>
    where
        S: AsyncRead + Unpin,
    {
        let len_plain = read_encrypted_exact_async(stream, &mut self.codec, 2).await?;
        let chunk_len = u16::from_be_bytes([len_plain[0], len_plain[1]]) as usize;
        read_encrypted_exact_async(stream, &mut self.codec, chunk_len).await
    }

    pub async fn read_next_chunk_in_place_async<S>(
        &mut self,
        stream: &mut S,
        buffer: &mut Vec<u8>,
    ) -> Result<usize, OutboundError>
    where
        S: AsyncRead + Unpin,
    {
        if self.codec.tag_len != SS2022_TCP_TAG_LEN {
            return Err(OutboundError::BadShadowsocks(format!(
                "SS2022 stream tag length must be {SS2022_TCP_TAG_LEN}, got {}",
                self.codec.tag_len
            )));
        }
        let mut length_wire = [0_u8; 2 + SS2022_TCP_TAG_LEN];
        stream
            .read_exact(&mut length_wire)
            .await
            .map_err(|err| OutboundError::BadShadowsocks(err.to_string()))?;
        let (length_plain, length_tag) = length_wire.split_at_mut(2);
        self.codec.decrypt_next_in_place(length_plain, length_tag)?;
        let chunk_len = u16::from_be_bytes([length_plain[0], length_plain[1]]) as usize;
        buffer.resize(chunk_len + SS2022_TCP_TAG_LEN, 0);
        stream
            .read_exact(buffer)
            .await
            .map_err(|err| OutboundError::BadShadowsocks(err.to_string()))?;
        let (payload, tag) = buffer.split_at_mut(chunk_len);
        self.codec.decrypt_next_in_place(payload, tag)?;
        Ok(chunk_len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shadowsocks::ss2022::cipher_confs;
    use tokio::io::AsyncWriteExt;

    #[tokio::test(flavor = "current_thread")]
    async fn in_place_stream_chunks_match_allocating_wire_for_every_cipher() {
        for conf in cipher_confs() {
            let psk = vec![0x31; conf.key_len];
            let salt = vec![0x52; conf.salt_len];
            let mut allocating = Ss2022TcpClientStreamEncoder {
                codec: Ss2022StreamCodec::new(conf, &psk, &salt).unwrap(),
            };
            let mut in_place = Ss2022TcpClientStreamEncoder {
                codec: Ss2022StreamCodec::new(conf, &psk, &salt).unwrap(),
            };
            let mut decoder = Ss2022TcpServerStreamDecoder {
                codec: Ss2022StreamCodec::new(conf, &psk, &salt).unwrap(),
            };

            for payload_len in [1, 4097, TCP_CHUNK_MAX_LEN] {
                let payload = vec![payload_len as u8; payload_len];
                let expected = allocating.encode_chunk(&payload).unwrap();
                let mut wire = vec![0_u8; payload_len + 2 + SS2022_TCP_TAG_LEN * 2];
                in_place
                    .chunk_payload_buffer(&mut wire)
                    .copy_from_slice(&payload);
                let wire_len = in_place
                    .encode_chunk_in_place(&mut wire, payload_len)
                    .unwrap();
                assert_eq!(&wire[..wire_len], expected.as_slice(), "{}", conf.cipher);

                let (mut writer, mut reader) = tokio::io::duplex(wire_len + 1);
                writer.write_all(&wire[..wire_len]).await.unwrap();
                writer.shutdown().await.unwrap();
                let mut decoded = Vec::new();
                let decoded_len = decoder
                    .read_next_chunk_in_place_async(&mut reader, &mut decoded)
                    .await
                    .unwrap();
                assert_eq!(
                    &decoded[..decoded_len],
                    payload.as_slice(),
                    "{}",
                    conf.cipher
                );
            }
        }
    }
}
