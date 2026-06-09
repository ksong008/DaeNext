use super::*;
pub(super) const SESSION_SUBKEY_CONTEXT: &str = "shadowsocks 2022 session subkey";
pub(super) const IDENTITY_SUBKEY_CONTEXT: &str = "shadowsocks 2022 identity subkey";

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
    pub default_go_path: bool,
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
}
