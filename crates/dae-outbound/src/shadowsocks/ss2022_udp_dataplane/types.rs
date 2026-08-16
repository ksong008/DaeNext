use super::*;
pub struct Ss2022UdpEncodedPacket {
    pub wire: Vec<u8>,
    pub cipher: String,
    pub branch: &'static str,
    pub packet_type: u8,
    pub packet_id: u64,
    pub session_id: [u8; 8],
    pub client_session_id: Option<[u8; 8]>,
    pub target: String,
    pub payload_len: usize,
    pub timestamp: u64,
    pub separate_header_len: usize,
    pub packet_nonce_len: usize,
    pub identity_header_count: usize,
    pub identity_header_bytes_len: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ss2022UdpDecodedPacket {
    pub cipher: String,
    pub branch: &'static str,
    pub packet_type: u8,
    pub packet_id: u64,
    pub session_id: [u8; 8],
    pub client_session_id: Option<[u8; 8]>,
    pub target: String,
    pub target_metadata_len: usize,
    pub padding_len: usize,
    pub payload: Vec<u8>,
    pub timestamp: u64,
    pub identity_header_count: usize,
    pub identity_header_bytes_len: usize,
    pub identity_header_validated: bool,
}

#[derive(Debug)]
pub struct Ss2022UdpCodec {
    pub(super) conf: CipherConf2022,
    pub(super) cipher: String,
    pub(super) psk_list: Vec<Vec<u8>>,
    pub(super) upsk: Vec<u8>,
    pub(super) client_header_cipher: Ss2022AesBlockCipher,
    pub(super) server_header_cipher: Ss2022AesBlockCipher,
    pub(super) client_payload_cipher: Option<Ss2022SeparatePayloadCipher>,
    pub(super) server_payload_cipher: Option<([u8; 8], Ss2022SeparatePayloadCipher)>,
    pub(super) session_id: [u8; 8],
    pub(super) next_packet_id: u64,
    pub(super) server_replay: Ss2022UdpReplayTable,
}

#[allow(clippy::large_enum_variant)]
pub(super) enum Ss2022AesBlockCipher {
    Aes128(Aes128),
    Aes256(Aes256),
}

impl std::fmt::Debug for Ss2022SeparatePayloadCipher {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Aes128(_) => "Ss2022SeparatePayloadCipher::Aes128",
            Self::Aes256(_) => "Ss2022SeparatePayloadCipher::Aes256",
        })
    }
}

impl std::fmt::Debug for Ss2022AesBlockCipher {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Aes128(_) => "Ss2022AesBlockCipher::Aes128",
            Self::Aes256(_) => "Ss2022AesBlockCipher::Aes256",
        })
    }
}

#[derive(Debug, Default)]
pub struct Ss2022UdpReplayTracker {
    pub(super) replay: Ss2022UdpReplayTable,
}
