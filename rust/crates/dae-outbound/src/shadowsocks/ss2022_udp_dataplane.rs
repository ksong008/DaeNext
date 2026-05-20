use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit as BlockKeyInit};
use aes::{Aes128, Aes256};
use aes_gcm::aead::Aead;
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use chacha20poly1305::XChaCha20Poly1305;

use crate::error::OutboundError;
use crate::socks5::Socks5Address;

use super::ss2022::{
    CipherConf2022, HEADER_TYPE_CLIENT_PACKET, HEADER_TYPE_SERVER_PACKET, MAX_PADDING_LENGTH,
    SlidingWindowFilter, UDP_REPLAY_WINDOW_SIZE, cipher_conf, validate_base64_psk,
};

const SESSION_SUBKEY_CONTEXT: &str = "shadowsocks 2022 session subkey";
const TIMESTAMP_TOLERANCE_SECS: u64 = 30;
const AES_BLOCK_LEN: usize = 16;

#[derive(Clone, Debug, Eq, PartialEq)]
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
    conf: CipherConf2022,
    cipher: String,
    psk_list: Vec<Vec<u8>>,
    upsk: Vec<u8>,
    session_id: [u8; 8],
    next_packet_id: u64,
    server_windows: HashMap<[u8; 8], SlidingWindowFilter>,
}

#[derive(Debug, Default)]
pub struct Ss2022UdpReplayTracker {
    windows: HashMap<[u8; 8], SlidingWindowFilter>,
}

impl Ss2022UdpCodec {
    pub fn new(cipher: &str, password: &str, session_id: [u8; 8]) -> Result<Self, OutboundError> {
        let conf = require_cipher_conf(cipher)?;
        let psk_list = parse_psk_list(password, conf.key_len)?;
        let upsk = psk_list
            .last()
            .ok_or_else(|| OutboundError::BadShadowsocks("SS2022 PSK list is empty".to_owned()))?
            .clone();
        Ok(Self {
            conf,
            cipher: cipher.to_owned(),
            psk_list,
            upsk,
            session_id,
            next_packet_id: 0,
            server_windows: HashMap::new(),
        })
    }

    pub fn session_id(&self) -> [u8; 8] {
        self.session_id
    }

    pub fn psk_count(&self) -> usize {
        self.psk_list.len()
    }

    pub fn upsk_index(&self) -> usize {
        self.psk_list.len().saturating_sub(1)
    }

    pub fn encode_client_packet(
        &mut self,
        target: &str,
        payload: &[u8],
        timestamp: u64,
        packet_nonce: Option<&[u8]>,
    ) -> Result<Ss2022UdpEncodedPacket, OutboundError> {
        let packet_id = self.next_packet_id;
        self.next_packet_id += 1;
        if self.conf.packet_cipher {
            encode_merged_header_packet(
                &self.conf,
                &self.cipher,
                &self.upsk,
                packet_nonce,
                HEADER_TYPE_CLIENT_PACKET,
                self.session_id,
                packet_id,
                None,
                target,
                payload,
                timestamp,
            )
        } else {
            encode_separate_header_client_packet(
                &self.conf,
                &self.cipher,
                &self.psk_list,
                self.session_id,
                packet_id,
                target,
                payload,
                timestamp,
            )
        }
    }

    pub fn decode_server_packet(
        &mut self,
        input: &[u8],
        now: u64,
    ) -> Result<Ss2022UdpDecodedPacket, OutboundError> {
        let decoded = if self.conf.packet_cipher {
            decode_merged_header_packet(&self.conf, &self.cipher, &self.upsk, input, now)?
        } else {
            decode_separate_header_server_packet(&self.conf, &self.cipher, &self.upsk, input, now)?
        };
        if decoded.packet_type != HEADER_TYPE_SERVER_PACKET {
            return Err(OutboundError::BadShadowsocks(format!(
                "SS2022 UDP expected server packet type {}, got {}",
                HEADER_TYPE_SERVER_PACKET, decoded.packet_type
            )));
        }
        if decoded.client_session_id != Some(self.session_id) {
            return Err(OutboundError::BadShadowsocks(
                "SS2022 UDP server packet client session mismatch".to_owned(),
            ));
        }
        let window = self
            .server_windows
            .entry(decoded.session_id)
            .or_insert_with(|| SlidingWindowFilter::new(UDP_REPLAY_WINDOW_SIZE));
        if !window.check_and_update(decoded.packet_id) {
            return Err(OutboundError::BadShadowsocks(
                "SS2022 UDP replay attack detected".to_owned(),
            ));
        }
        Ok(decoded)
    }
}

impl Ss2022UdpReplayTracker {
    pub fn check(&mut self, session_id: [u8; 8], packet_id: u64) -> Result<(), OutboundError> {
        let window = self
            .windows
            .entry(session_id)
            .or_insert_with(|| SlidingWindowFilter::new(UDP_REPLAY_WINDOW_SIZE));
        if !window.check_and_update(packet_id) {
            return Err(OutboundError::BadShadowsocks(
                "SS2022 UDP replay attack detected".to_owned(),
            ));
        }
        Ok(())
    }
}

pub fn decode_client_packet(
    cipher: &str,
    password: &str,
    input: &[u8],
    now: u64,
) -> Result<Ss2022UdpDecodedPacket, OutboundError> {
    let conf = require_cipher_conf(cipher)?;
    let psk_list = parse_psk_list(password, conf.key_len)?;
    let upsk = psk_list
        .last()
        .ok_or_else(|| OutboundError::BadShadowsocks("SS2022 PSK list is empty".to_owned()))?;
    let decoded = if conf.packet_cipher {
        decode_merged_header_packet(&conf, cipher, upsk, input, now)?
    } else {
        decode_separate_header_client_packet(&conf, cipher, &psk_list, input, now)?
    };
    if decoded.packet_type != HEADER_TYPE_CLIENT_PACKET {
        return Err(OutboundError::BadShadowsocks(format!(
            "SS2022 UDP expected client packet type {}, got {}",
            HEADER_TYPE_CLIENT_PACKET, decoded.packet_type
        )));
    }
    Ok(decoded)
}

pub fn encode_server_packet(
    cipher: &str,
    password: &str,
    server_session_id: [u8; 8],
    packet_id: u64,
    client_session_id: [u8; 8],
    target: &str,
    payload: &[u8],
    timestamp: u64,
    packet_nonce: Option<&[u8]>,
) -> Result<Ss2022UdpEncodedPacket, OutboundError> {
    let conf = require_cipher_conf(cipher)?;
    let psk_list = parse_psk_list(password, conf.key_len)?;
    let upsk = psk_list
        .last()
        .ok_or_else(|| OutboundError::BadShadowsocks("SS2022 PSK list is empty".to_owned()))?;
    if conf.packet_cipher {
        encode_merged_header_packet(
            &conf,
            cipher,
            upsk,
            packet_nonce,
            HEADER_TYPE_SERVER_PACKET,
            server_session_id,
            packet_id,
            Some(client_session_id),
            target,
            payload,
            timestamp,
        )
    } else {
        encode_separate_header_server_packet(
            &conf,
            cipher,
            upsk,
            server_session_id,
            packet_id,
            client_session_id,
            target,
            payload,
            timestamp,
        )
    }
}

pub fn unix_timestamp_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn encode_separate_header_client_packet(
    conf: &CipherConf2022,
    cipher: &str,
    psk_list: &[Vec<u8>],
    session_id: [u8; 8],
    packet_id: u64,
    target: &str,
    payload: &[u8],
    timestamp: u64,
) -> Result<Ss2022UdpEncodedPacket, OutboundError> {
    let upsk = psk_list
        .last()
        .ok_or_else(|| OutboundError::BadShadowsocks("SS2022 PSK list is empty".to_owned()))?;
    let separate_header = separate_header(session_id, packet_id);
    let mut out = Vec::new();
    out.extend_from_slice(&encrypt_aes_block(&psk_list[0], &separate_header)?);
    let identity_headers = encode_udp_identity_headers(psk_list, &separate_header)?;
    out.extend_from_slice(&identity_headers);
    let message = encode_client_message(target, payload, timestamp)?;
    let sealed = seal_separate_payload(conf, upsk, &separate_header, &message)?;
    out.extend_from_slice(&sealed);
    Ok(Ss2022UdpEncodedPacket {
        wire: out,
        cipher: cipher.to_owned(),
        branch: "aes-separate-header",
        packet_type: HEADER_TYPE_CLIENT_PACKET,
        packet_id,
        session_id,
        client_session_id: None,
        target: Socks5Address::parse(target)?.authority(),
        payload_len: payload.len(),
        timestamp,
        separate_header_len: AES_BLOCK_LEN,
        packet_nonce_len: 0,
        identity_header_count: psk_list.len().saturating_sub(1),
        identity_header_bytes_len: identity_headers.len(),
    })
}

fn encode_separate_header_server_packet(
    conf: &CipherConf2022,
    cipher: &str,
    upsk: &[u8],
    server_session_id: [u8; 8],
    packet_id: u64,
    client_session_id: [u8; 8],
    target: &str,
    payload: &[u8],
    timestamp: u64,
) -> Result<Ss2022UdpEncodedPacket, OutboundError> {
    let separate_header = separate_header(server_session_id, packet_id);
    let mut out = Vec::new();
    out.extend_from_slice(&encrypt_aes_block(upsk, &separate_header)?);
    let message = encode_server_message(client_session_id, target, payload, timestamp)?;
    out.extend_from_slice(&seal_separate_payload(
        conf,
        upsk,
        &separate_header,
        &message,
    )?);
    Ok(Ss2022UdpEncodedPacket {
        wire: out,
        cipher: cipher.to_owned(),
        branch: "aes-separate-header",
        packet_type: HEADER_TYPE_SERVER_PACKET,
        packet_id,
        session_id: server_session_id,
        client_session_id: Some(client_session_id),
        target: Socks5Address::parse(target)?.authority(),
        payload_len: payload.len(),
        timestamp,
        separate_header_len: AES_BLOCK_LEN,
        packet_nonce_len: 0,
        identity_header_count: 0,
        identity_header_bytes_len: 0,
    })
}

fn decode_separate_header_client_packet(
    conf: &CipherConf2022,
    cipher: &str,
    psk_list: &[Vec<u8>],
    input: &[u8],
    now: u64,
) -> Result<Ss2022UdpDecodedPacket, OutboundError> {
    if input.len() < AES_BLOCK_LEN {
        return Err(OutboundError::BadShadowsocks(
            "SS2022 UDP packet missing separate header".to_owned(),
        ));
    }
    let separate_header = decrypt_aes_block(&psk_list[0], &input[..AES_BLOCK_LEN])?;
    let identity_len = psk_list.len().saturating_sub(1) * AES_BLOCK_LEN;
    if input.len() < AES_BLOCK_LEN + identity_len {
        return Err(OutboundError::BadShadowsocks(
            "SS2022 UDP packet missing identity header".to_owned(),
        ));
    }
    let identity = &input[AES_BLOCK_LEN..AES_BLOCK_LEN + identity_len];
    validate_udp_identity_headers(psk_list, &separate_header, identity)?;
    let upsk = psk_list
        .last()
        .ok_or_else(|| OutboundError::BadShadowsocks("SS2022 PSK list is empty".to_owned()))?;
    let payload = open_separate_payload(
        conf,
        upsk,
        &separate_header,
        &input[AES_BLOCK_LEN + identity_len..],
    )?;
    let parsed = parse_client_message(&payload, now)?;
    Ok(Ss2022UdpDecodedPacket {
        cipher: cipher.to_owned(),
        branch: "aes-separate-header",
        packet_type: parsed.packet_type,
        packet_id: u64::from_be_bytes(separate_header[8..16].try_into().expect("header len")),
        session_id: separate_header[..8].try_into().expect("header len"),
        client_session_id: None,
        target: parsed.target,
        target_metadata_len: parsed.target_metadata_len,
        padding_len: parsed.padding_len,
        payload: parsed.payload,
        timestamp: parsed.timestamp,
        identity_header_count: psk_list.len().saturating_sub(1),
        identity_header_bytes_len: identity_len,
        identity_header_validated: true,
    })
}

fn decode_separate_header_server_packet(
    conf: &CipherConf2022,
    cipher: &str,
    upsk: &[u8],
    input: &[u8],
    now: u64,
) -> Result<Ss2022UdpDecodedPacket, OutboundError> {
    if input.len() < AES_BLOCK_LEN {
        return Err(OutboundError::BadShadowsocks(
            "SS2022 UDP server packet missing separate header".to_owned(),
        ));
    }
    let separate_header = decrypt_aes_block(upsk, &input[..AES_BLOCK_LEN])?;
    let payload = open_separate_payload(conf, upsk, &separate_header, &input[AES_BLOCK_LEN..])?;
    let parsed = parse_server_message(&payload, now)?;
    Ok(Ss2022UdpDecodedPacket {
        cipher: cipher.to_owned(),
        branch: "aes-separate-header",
        packet_type: parsed.packet_type,
        packet_id: u64::from_be_bytes(separate_header[8..16].try_into().expect("header len")),
        session_id: separate_header[..8].try_into().expect("header len"),
        client_session_id: Some(parsed.client_session_id),
        target: parsed.target,
        target_metadata_len: parsed.target_metadata_len,
        padding_len: parsed.padding_len,
        payload: parsed.payload,
        timestamp: parsed.timestamp,
        identity_header_count: 0,
        identity_header_bytes_len: 0,
        identity_header_validated: true,
    })
}

fn encode_merged_header_packet(
    conf: &CipherConf2022,
    cipher: &str,
    upsk: &[u8],
    packet_nonce: Option<&[u8]>,
    packet_type: u8,
    session_id: [u8; 8],
    packet_id: u64,
    client_session_id: Option<[u8; 8]>,
    target: &str,
    payload: &[u8],
    timestamp: u64,
) -> Result<Ss2022UdpEncodedPacket, OutboundError> {
    let nonce = packet_nonce.ok_or_else(|| {
        OutboundError::BadShadowsocks("SS2022 UDP XChaCha packet nonce is required".to_owned())
    })?;
    if nonce.len() != conf.packet_nonce_len {
        return Err(OutboundError::BadShadowsocks(format!(
            "SS2022 UDP packet nonce length must be {}, got {}",
            conf.packet_nonce_len,
            nonce.len()
        )));
    }
    let mut message = Vec::new();
    message.extend_from_slice(&session_id);
    message.extend_from_slice(&packet_id.to_be_bytes());
    match packet_type {
        HEADER_TYPE_CLIENT_PACKET => {
            message.extend_from_slice(&encode_client_message(target, payload, timestamp)?);
        }
        HEADER_TYPE_SERVER_PACKET => {
            let client_session_id = client_session_id.ok_or_else(|| {
                OutboundError::BadShadowsocks(
                    "SS2022 UDP server packet requires client session id".to_owned(),
                )
            })?;
            message.extend_from_slice(&encode_server_message(
                client_session_id,
                target,
                payload,
                timestamp,
            )?);
        }
        _ => {
            return Err(OutboundError::BadShadowsocks(format!(
                "SS2022 UDP unsupported packet type: {packet_type}"
            )));
        }
    }
    let packet_cipher = XChaCha20Poly1305::new_from_slice(upsk)
        .map_err(|_| OutboundError::BadShadowsocks("bad SS2022 XChaCha packet key".to_owned()))?;
    let mut out = Vec::new();
    out.extend_from_slice(nonce);
    out.extend_from_slice(
        &packet_cipher
            .encrypt(
                chacha20poly1305::XNonce::from_slice(nonce),
                message.as_slice(),
            )
            .map_err(|_| OutboundError::BadShadowsocks("SS2022 UDP encrypt failed".to_owned()))?,
    );
    Ok(Ss2022UdpEncodedPacket {
        wire: out,
        cipher: cipher.to_owned(),
        branch: "merged-header-xchacha20-poly1305",
        packet_type,
        packet_id,
        session_id,
        client_session_id,
        target: Socks5Address::parse(target)?.authority(),
        payload_len: payload.len(),
        timestamp,
        separate_header_len: 0,
        packet_nonce_len: conf.packet_nonce_len,
        identity_header_count: 0,
        identity_header_bytes_len: 0,
    })
}

fn decode_merged_header_packet(
    conf: &CipherConf2022,
    cipher: &str,
    upsk: &[u8],
    input: &[u8],
    now: u64,
) -> Result<Ss2022UdpDecodedPacket, OutboundError> {
    if input.len() < conf.packet_nonce_len + conf.tag_len {
        return Err(OutboundError::BadShadowsocks(
            "SS2022 UDP XChaCha packet too short".to_owned(),
        ));
    }
    let (nonce, payload) = input.split_at(conf.packet_nonce_len);
    let packet_cipher = XChaCha20Poly1305::new_from_slice(upsk)
        .map_err(|_| OutboundError::BadShadowsocks("bad SS2022 XChaCha packet key".to_owned()))?;
    let plain = packet_cipher
        .decrypt(chacha20poly1305::XNonce::from_slice(nonce), payload)
        .map_err(|_| OutboundError::BadShadowsocks("SS2022 UDP decrypt failed".to_owned()))?;
    if plain.len() < 16 {
        return Err(OutboundError::BadShadowsocks(
            "SS2022 UDP merged header too short".to_owned(),
        ));
    }
    let mut session_id = [0_u8; 8];
    session_id.copy_from_slice(&plain[..8]);
    let packet_id = u64::from_be_bytes(plain[8..16].try_into().expect("header len"));
    let message = &plain[16..];
    let packet_type = *message.first().ok_or_else(|| {
        OutboundError::BadShadowsocks("SS2022 UDP merged message missing type".to_owned())
    })?;
    match packet_type {
        HEADER_TYPE_CLIENT_PACKET => {
            let parsed = parse_client_message(message, now)?;
            Ok(Ss2022UdpDecodedPacket {
                cipher: cipher.to_owned(),
                branch: "merged-header-xchacha20-poly1305",
                packet_type: parsed.packet_type,
                packet_id,
                session_id,
                client_session_id: None,
                target: parsed.target,
                target_metadata_len: parsed.target_metadata_len,
                padding_len: parsed.padding_len,
                payload: parsed.payload,
                timestamp: parsed.timestamp,
                identity_header_count: 0,
                identity_header_bytes_len: 0,
                identity_header_validated: true,
            })
        }
        HEADER_TYPE_SERVER_PACKET => {
            let parsed = parse_server_message(message, now)?;
            Ok(Ss2022UdpDecodedPacket {
                cipher: cipher.to_owned(),
                branch: "merged-header-xchacha20-poly1305",
                packet_type: parsed.packet_type,
                packet_id,
                session_id,
                client_session_id: Some(parsed.client_session_id),
                target: parsed.target,
                target_metadata_len: parsed.target_metadata_len,
                padding_len: parsed.padding_len,
                payload: parsed.payload,
                timestamp: parsed.timestamp,
                identity_header_count: 0,
                identity_header_bytes_len: 0,
                identity_header_validated: true,
            })
        }
        _ => Err(OutboundError::BadShadowsocks(format!(
            "SS2022 UDP unexpected packet type: {packet_type}"
        ))),
    }
}

fn encode_client_message(
    target: &str,
    payload: &[u8],
    timestamp: u64,
) -> Result<Vec<u8>, OutboundError> {
    let target = Socks5Address::parse(target)?;
    let mut message = Vec::new();
    message.push(HEADER_TYPE_CLIENT_PACKET);
    message.extend_from_slice(&timestamp.to_be_bytes());
    message.extend_from_slice(&0_u16.to_be_bytes());
    target.write_to(&mut message)?;
    message.extend_from_slice(payload);
    Ok(message)
}

fn encode_server_message(
    client_session_id: [u8; 8],
    target: &str,
    payload: &[u8],
    timestamp: u64,
) -> Result<Vec<u8>, OutboundError> {
    let target = Socks5Address::parse(target)?;
    let mut message = Vec::new();
    message.push(HEADER_TYPE_SERVER_PACKET);
    message.extend_from_slice(&timestamp.to_be_bytes());
    message.extend_from_slice(&client_session_id);
    message.extend_from_slice(&0_u16.to_be_bytes());
    target.write_to(&mut message)?;
    message.extend_from_slice(payload);
    Ok(message)
}

#[derive(Debug)]
struct ParsedClientMessage {
    packet_type: u8,
    timestamp: u64,
    target: String,
    target_metadata_len: usize,
    padding_len: usize,
    payload: Vec<u8>,
}

#[derive(Debug)]
struct ParsedServerMessage {
    packet_type: u8,
    timestamp: u64,
    client_session_id: [u8; 8],
    target: String,
    target_metadata_len: usize,
    padding_len: usize,
    payload: Vec<u8>,
}

fn parse_client_message(input: &[u8], now: u64) -> Result<ParsedClientMessage, OutboundError> {
    let (packet_type, timestamp, mut offset) = parse_type_timestamp(input, now)?;
    let padding_len = read_padding_len(input, &mut offset)?;
    skip_padding(input, &mut offset, padding_len)?;
    let (target, consumed) = Socks5Address::decode(&input[offset..])?;
    offset += consumed;
    Ok(ParsedClientMessage {
        packet_type,
        timestamp,
        target: target.authority(),
        target_metadata_len: consumed,
        padding_len,
        payload: input[offset..].to_vec(),
    })
}

fn parse_server_message(input: &[u8], now: u64) -> Result<ParsedServerMessage, OutboundError> {
    let (packet_type, timestamp, mut offset) = parse_type_timestamp(input, now)?;
    if input.len() < offset + 8 {
        return Err(OutboundError::BadShadowsocks(
            "SS2022 UDP server message missing client session id".to_owned(),
        ));
    }
    let mut client_session_id = [0_u8; 8];
    client_session_id.copy_from_slice(&input[offset..offset + 8]);
    offset += 8;
    let padding_len = read_padding_len(input, &mut offset)?;
    skip_padding(input, &mut offset, padding_len)?;
    let (target, consumed) = Socks5Address::decode(&input[offset..])?;
    offset += consumed;
    Ok(ParsedServerMessage {
        packet_type,
        timestamp,
        client_session_id,
        target: target.authority(),
        target_metadata_len: consumed,
        padding_len,
        payload: input[offset..].to_vec(),
    })
}

fn parse_type_timestamp(input: &[u8], now: u64) -> Result<(u8, u64, usize), OutboundError> {
    if input.len() < 9 {
        return Err(OutboundError::BadShadowsocks(
            "SS2022 UDP message too short".to_owned(),
        ));
    }
    let packet_type = input[0];
    let timestamp = u64::from_be_bytes(input[1..9].try_into().expect("timestamp len"));
    if timestamp_out_of_tolerance(timestamp, now) {
        return Err(OutboundError::BadShadowsocks(
            "SS2022 UDP replay attack: timestamp out of tolerance".to_owned(),
        ));
    }
    Ok((packet_type, timestamp, 9))
}

fn read_padding_len(input: &[u8], offset: &mut usize) -> Result<usize, OutboundError> {
    if input.len() < *offset + 2 {
        return Err(OutboundError::BadShadowsocks(
            "SS2022 UDP message missing padding length".to_owned(),
        ));
    }
    let padding_len = u16::from_be_bytes([input[*offset], input[*offset + 1]]) as usize;
    *offset += 2;
    if padding_len > MAX_PADDING_LENGTH {
        return Err(OutboundError::BadShadowsocks(format!(
            "SS2022 UDP padding too large: {padding_len}"
        )));
    }
    Ok(padding_len)
}

fn skip_padding(input: &[u8], offset: &mut usize, padding_len: usize) -> Result<(), OutboundError> {
    if input.len() < *offset + padding_len {
        return Err(OutboundError::BadShadowsocks(
            "SS2022 UDP padding overflows packet".to_owned(),
        ));
    }
    *offset += padding_len;
    Ok(())
}

fn seal_separate_payload(
    conf: &CipherConf2022,
    upsk: &[u8],
    separate_header: &[u8; 16],
    message: &[u8],
) -> Result<Vec<u8>, OutboundError> {
    let subkey = derive_subkey(
        upsk,
        &separate_header[..8],
        conf.key_len,
        SESSION_SUBKEY_CONTEXT,
    );
    let cipher = Ss2022SeparatePayloadCipher::new(conf.cipher, &subkey)?;
    cipher.encrypt(&separate_header[4..16], message)
}

fn open_separate_payload(
    conf: &CipherConf2022,
    upsk: &[u8],
    separate_header: &[u8; 16],
    input: &[u8],
) -> Result<Vec<u8>, OutboundError> {
    let subkey = derive_subkey(
        upsk,
        &separate_header[..8],
        conf.key_len,
        SESSION_SUBKEY_CONTEXT,
    );
    let cipher = Ss2022SeparatePayloadCipher::new(conf.cipher, &subkey)?;
    cipher.decrypt(&separate_header[4..16], input)
}

enum Ss2022SeparatePayloadCipher {
    Aes128(Box<Aes128Gcm>),
    Aes256(Box<Aes256Gcm>),
}

impl Ss2022SeparatePayloadCipher {
    fn new(cipher: &str, key: &[u8]) -> Result<Self, OutboundError> {
        match cipher {
            "2022-blake3-aes-128-gcm" => Ok(Self::Aes128(Box::new(
                Aes128Gcm::new_from_slice(key).map_err(|_| {
                    OutboundError::BadShadowsocks("bad SS2022 aes-128 UDP key".to_owned())
                })?,
            ))),
            "2022-blake3-aes-256-gcm" => Ok(Self::Aes256(Box::new(
                Aes256Gcm::new_from_slice(key).map_err(|_| {
                    OutboundError::BadShadowsocks("bad SS2022 aes-256 UDP key".to_owned())
                })?,
            ))),
            _ => Err(OutboundError::BadShadowsocks(format!(
                "SS2022 cipher does not use separate UDP payload AEAD: {cipher}"
            ))),
        }
    }

    fn encrypt(&self, nonce: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, OutboundError> {
        match self {
            Self::Aes128(cipher) => cipher
                .encrypt(aes_gcm::Nonce::from_slice(nonce), plaintext)
                .map_err(|_| OutboundError::BadShadowsocks("SS2022 UDP encrypt failed".to_owned())),
            Self::Aes256(cipher) => cipher
                .encrypt(aes_gcm::Nonce::from_slice(nonce), plaintext)
                .map_err(|_| OutboundError::BadShadowsocks("SS2022 UDP encrypt failed".to_owned())),
        }
    }

    fn decrypt(&self, nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, OutboundError> {
        match self {
            Self::Aes128(cipher) => cipher
                .decrypt(aes_gcm::Nonce::from_slice(nonce), ciphertext)
                .map_err(|_| OutboundError::BadShadowsocks("SS2022 UDP decrypt failed".to_owned())),
            Self::Aes256(cipher) => cipher
                .decrypt(aes_gcm::Nonce::from_slice(nonce), ciphertext)
                .map_err(|_| OutboundError::BadShadowsocks("SS2022 UDP decrypt failed".to_owned())),
        }
    }
}

fn encode_udp_identity_headers(
    psk_list: &[Vec<u8>],
    separate_header: &[u8; 16],
) -> Result<Vec<u8>, OutboundError> {
    if psk_list.len() <= 1 {
        return Ok(Vec::new());
    }
    let mut out = Vec::with_capacity((psk_list.len() - 1) * AES_BLOCK_LEN);
    for window in psk_list.windows(2) {
        out.extend_from_slice(&encode_udp_identity_header(
            &window[0],
            &window[1],
            separate_header,
        )?);
    }
    Ok(out)
}

fn validate_udp_identity_headers(
    psk_list: &[Vec<u8>],
    separate_header: &[u8; 16],
    observed: &[u8],
) -> Result<(), OutboundError> {
    if psk_list.len() <= 1 {
        return Ok(());
    }
    let mut offset = 0;
    for window in psk_list.windows(2) {
        let expected = encode_udp_identity_header(&window[0], &window[1], separate_header)?;
        if observed.len() < offset + AES_BLOCK_LEN
            || observed[offset..offset + AES_BLOCK_LEN] != expected
        {
            return Err(OutboundError::BadShadowsocks(
                "SS2022 UDP identity header mismatch".to_owned(),
            ));
        }
        offset += AES_BLOCK_LEN;
    }
    Ok(())
}

fn encode_udp_identity_header(
    current_psk: &[u8],
    next_psk: &[u8],
    separate_header: &[u8; 16],
) -> Result<[u8; 16], OutboundError> {
    let mut next_hash = [0_u8; 64];
    let mut hasher = blake3::Hasher::new();
    hasher.update(next_psk);
    hasher.finalize_xof().fill(&mut next_hash);
    let mut plain = [0_u8; 16];
    for index in 0..AES_BLOCK_LEN {
        plain[index] = next_hash[index] ^ separate_header[index];
    }
    encrypt_aes_block(current_psk, &plain)
}

fn separate_header(session_id: [u8; 8], packet_id: u64) -> [u8; 16] {
    let mut header = [0_u8; 16];
    header[..8].copy_from_slice(&session_id);
    header[8..].copy_from_slice(&packet_id.to_be_bytes());
    header
}

fn encrypt_aes_block(key: &[u8], plaintext: &[u8]) -> Result<[u8; 16], OutboundError> {
    if plaintext.len() != AES_BLOCK_LEN {
        return Err(OutboundError::BadShadowsocks(
            "SS2022 AES block plaintext must be 16 bytes".to_owned(),
        ));
    }
    let mut block = aes::cipher::generic_array::GenericArray::clone_from_slice(plaintext);
    match key.len() {
        16 => {
            let cipher = Aes128::new_from_slice(key).map_err(|_| {
                OutboundError::BadShadowsocks("bad SS2022 aes-128 block key".to_owned())
            })?;
            cipher.encrypt_block(&mut block);
        }
        32 => {
            let cipher = Aes256::new_from_slice(key).map_err(|_| {
                OutboundError::BadShadowsocks("bad SS2022 aes-256 block key".to_owned())
            })?;
            cipher.encrypt_block(&mut block);
        }
        _ => {
            return Err(OutboundError::BadShadowsocks(format!(
                "unsupported SS2022 AES block key length: {}",
                key.len()
            )));
        }
    }
    let mut out = [0_u8; 16];
    out.copy_from_slice(&block);
    Ok(out)
}

fn decrypt_aes_block(key: &[u8], ciphertext: &[u8]) -> Result<[u8; 16], OutboundError> {
    if ciphertext.len() != AES_BLOCK_LEN {
        return Err(OutboundError::BadShadowsocks(
            "SS2022 AES block ciphertext must be 16 bytes".to_owned(),
        ));
    }
    let mut block = aes::cipher::generic_array::GenericArray::clone_from_slice(ciphertext);
    match key.len() {
        16 => {
            let cipher = Aes128::new_from_slice(key).map_err(|_| {
                OutboundError::BadShadowsocks("bad SS2022 aes-128 block key".to_owned())
            })?;
            cipher.decrypt_block(&mut block);
        }
        32 => {
            let cipher = Aes256::new_from_slice(key).map_err(|_| {
                OutboundError::BadShadowsocks("bad SS2022 aes-256 block key".to_owned())
            })?;
            cipher.decrypt_block(&mut block);
        }
        _ => {
            return Err(OutboundError::BadShadowsocks(format!(
                "unsupported SS2022 AES block key length: {}",
                key.len()
            )));
        }
    }
    let mut out = [0_u8; 16];
    out.copy_from_slice(&block);
    Ok(out)
}

fn require_cipher_conf(cipher: &str) -> Result<CipherConf2022, OutboundError> {
    cipher_conf(cipher).ok_or_else(|| {
        OutboundError::BadShadowsocks(format!("unsupported shadowsocks 2022 cipher: {cipher}"))
    })
}

fn parse_psk_list(password: &str, key_len: usize) -> Result<Vec<Vec<u8>>, OutboundError> {
    let parts = password.split(':').collect::<Vec<_>>();
    let mut psk_list = Vec::with_capacity(parts.len());
    for part in parts {
        psk_list.push(validate_base64_psk(part, key_len)?);
    }
    Ok(psk_list)
}

fn derive_subkey(psk: &[u8], salt: &[u8], key_len: usize, context: &str) -> Vec<u8> {
    let mut key_material = Vec::with_capacity(psk.len() + salt.len());
    key_material.extend_from_slice(psk);
    key_material.extend_from_slice(salt);
    let derived = blake3::derive_key(context, &key_material);
    derived[..key_len].to_vec()
}

fn timestamp_out_of_tolerance(timestamp: u64, now: u64) -> bool {
    timestamp.saturating_add(TIMESTAMP_TOLERANCE_SECS) < now
        || timestamp > now.saturating_add(TIMESTAMP_TOLERANCE_SECS)
}
