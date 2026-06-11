use base64::Engine;

use crate::error::OutboundError;
use crate::socks5::Socks5Address;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CipherConf2022 {
    pub cipher: &'static str,
    pub key_len: usize,
    pub salt_len: usize,
    pub nonce_len: usize,
    pub tag_len: usize,
    pub packet_nonce_len: usize,
    pub packet_cipher: bool,
}

pub const HEADER_TYPE_CLIENT_STREAM: u8 = 0;
pub const HEADER_TYPE_SERVER_STREAM: u8 = 1;
pub const HEADER_TYPE_CLIENT_PACKET: u8 = 0;
pub const HEADER_TYPE_SERVER_PACKET: u8 = 1;
pub const TCP_CHUNK_MAX_LEN: usize = (1 << 16) - 1;
pub const MAX_PADDING_LENGTH: usize = 900;
pub const UDP_REPLAY_WINDOW_SIZE: usize = 4096;
pub const SERVER_SESSION_RETENTION: &str = "1m0s";

pub const CIPHER_CONFS: &[CipherConf2022] = &[
    CipherConf2022 {
        cipher: "2022-blake3-aes-128-gcm",
        key_len: 16,
        salt_len: 16,
        nonce_len: 12,
        tag_len: 16,
        packet_nonce_len: 0,
        packet_cipher: false,
    },
    CipherConf2022 {
        cipher: "2022-blake3-aes-256-gcm",
        key_len: 32,
        salt_len: 32,
        nonce_len: 12,
        tag_len: 16,
        packet_nonce_len: 0,
        packet_cipher: false,
    },
    CipherConf2022 {
        cipher: "2022-blake3-chacha20-poly1305",
        key_len: 32,
        salt_len: 32,
        nonce_len: 12,
        tag_len: 16,
        packet_nonce_len: 24,
        packet_cipher: true,
    },
];

pub fn cipher_confs() -> &'static [CipherConf2022] {
    CIPHER_CONFS
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PskInfo {
    pub cipher: String,
    pub psk_count: usize,
    pub psk_key_lens: Vec<usize>,
    pub upsk_index: usize,
    pub expected_key_len: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TcpHeaderContract {
    pub fixed_header_len: usize,
    pub header_type_client_stream: u8,
    pub timestamp: u64,
    pub target: String,
    pub address_hex: String,
    pub var_header_len_min: usize,
    pub empty_initial_payload_has_padding: bool,
    pub max_padding_len: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UdpPacketIdContract {
    pub cipher: String,
    pub first_packet_id: u64,
    pub separate_header_len: usize,
    pub packet_id_big_endian: bool,
    pub replay_window_size: usize,
    pub server_session_retention: &'static str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SlidingWindowFilter {
    window_size: u64,
    latest: u64,
    seen: Vec<u64>,
    init: bool,
}

pub fn cipher_conf(cipher: &str) -> Option<CipherConf2022> {
    cipher_confs()
        .iter()
        .copied()
        .find(|conf| conf.cipher == cipher)
}

pub fn validate_psk_list(cipher: &str, password: &str) -> Result<PskInfo, OutboundError> {
    let conf = cipher_conf(cipher).ok_or_else(|| {
        OutboundError::BadShadowsocks(format!("unsupported shadowsocks 2022 cipher: {cipher}"))
    })?;
    let psk_count = password.bytes().filter(|byte| *byte == b':').count() + 1;
    let mut lens = Vec::with_capacity(psk_count);
    for part in password.split(':') {
        lens.push(validate_base64_psk_len(part, conf.key_len)?);
    }
    Ok(PskInfo {
        cipher: cipher.to_owned(),
        psk_count,
        psk_key_lens: lens,
        upsk_index: psk_count.saturating_sub(1),
        expected_key_len: conf.key_len,
    })
}

pub fn validate_base64_psk(
    psk_base64: &str,
    expected_key_len: usize,
) -> Result<Vec<u8>, OutboundError> {
    if psk_base64.is_empty() {
        return Err(OutboundError::BadShadowsocks(
            "PSK cannot be empty for AEAD-2022 methods".to_owned(),
        ));
    }
    let psk = base64::engine::general_purpose::STANDARD
        .decode(psk_base64)
        .map_err(|err| {
            OutboundError::BadShadowsocks(format!(
                "PSK must be valid base64 for AEAD-2022 methods: {err}"
            ))
        })?;
    if psk.len() != expected_key_len {
        return Err(OutboundError::BadShadowsocks(format!(
            "PSK length must be {expected_key_len} bytes for this method, got {}",
            psk.len()
        )));
    }
    Ok(psk)
}

fn validate_base64_psk_len(
    psk_base64: &str,
    expected_key_len: usize,
) -> Result<usize, OutboundError> {
    if psk_base64.is_empty() {
        return Err(OutboundError::BadShadowsocks(
            "PSK cannot be empty for AEAD-2022 methods".to_owned(),
        ));
    }
    let mut decoded = [0_u8; 64];
    let psk_len = base64::engine::general_purpose::STANDARD
        .decode_slice(psk_base64, &mut decoded)
        .map_err(|err| {
            OutboundError::BadShadowsocks(format!(
                "PSK must be valid base64 for AEAD-2022 methods: {err}"
            ))
        })?;
    if psk_len != expected_key_len {
        return Err(OutboundError::BadShadowsocks(format!(
            "PSK length must be {expected_key_len} bytes for this method, got {psk_len}"
        )));
    }
    Ok(psk_len)
}

pub fn tcp_header_contract(
    target: &str,
    timestamp: u64,
    empty_initial_payload: bool,
) -> Result<TcpHeaderContract, OutboundError> {
    let address = Socks5Address::parse(target)?;
    let address_bytes = address.encode()?;
    Ok(TcpHeaderContract {
        fixed_header_len: 11,
        header_type_client_stream: HEADER_TYPE_CLIENT_STREAM,
        timestamp,
        target: target.to_owned(),
        address_hex: hex_encode(&address_bytes),
        var_header_len_min: address_bytes.len() + 2,
        empty_initial_payload_has_padding: empty_initial_payload,
        max_padding_len: MAX_PADDING_LENGTH,
    })
}

pub fn udp_packet_id_contract(cipher: &str) -> UdpPacketIdContract {
    let mut generator = UdpPacketIdGenerator::default();
    UdpPacketIdContract {
        cipher: cipher.to_owned(),
        first_packet_id: generator.next_packet_id(),
        separate_header_len: 16,
        packet_id_big_endian: true,
        replay_window_size: UDP_REPLAY_WINDOW_SIZE,
        server_session_retention: SERVER_SESSION_RETENTION,
    }
}

#[derive(Default)]
pub struct UdpPacketIdGenerator {
    next: u64,
}

impl UdpPacketIdGenerator {
    pub fn next_packet_id(&mut self) -> u64 {
        let packet_id = self.next;
        self.next += 1;
        packet_id
    }
}

impl SlidingWindowFilter {
    pub fn new(window_size: usize) -> Self {
        let window_size = if window_size == 0 { 4096 } else { window_size } as u64;
        Self {
            window_size,
            latest: 0,
            seen: Vec::with_capacity(window_size as usize),
            init: false,
        }
    }

    pub fn check_and_update(&mut self, packet_id: u64) -> bool {
        if !self.init {
            self.latest = packet_id;
            self.seen.push(packet_id);
            self.init = true;
            return true;
        }
        if packet_id + self.window_size <= self.latest {
            return false;
        }
        if self.seen.contains(&packet_id) {
            return false;
        }
        if packet_id > self.latest {
            self.latest = packet_id;
            let cutoff = self.latest.saturating_sub(self.window_size);
            self.seen.retain(|seen_id| *seen_id > cutoff);
        }
        self.seen.push(packet_id);
        true
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}
