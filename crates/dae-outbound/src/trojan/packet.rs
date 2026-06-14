use sha2::{Digest, Sha224};

use crate::error::OutboundError;

use super::metadata::TrojanMetadata;

pub const CRLF: &[u8; 2] = b"\r\n";

pub fn password_sha224_hex(password: &str) -> String {
    hex_encode(&Sha224::digest(password.as_bytes()))
}

pub fn tcp_request_header(
    password: &str,
    network: &str,
    target: &str,
    payload: &[u8],
) -> Result<Vec<u8>, OutboundError> {
    let metadata = TrojanMetadata::parse(network, target)?;
    let metadata_bytes = metadata.encode()?;
    let mut out = Vec::with_capacity(56 + 2 + 1 + metadata_bytes.len() + 2 + payload.len());
    out.extend_from_slice(password_sha224_hex(password).as_bytes());
    out.extend_from_slice(CRLF);
    out.push(metadata.network.byte());
    out.extend_from_slice(&metadata_bytes);
    out.extend_from_slice(CRLF);
    out.extend_from_slice(payload);
    Ok(out)
}

pub fn udp_packet(target: &str, payload: &[u8]) -> Result<Vec<u8>, OutboundError> {
    if payload.len() > u16::MAX as usize {
        return Err(OutboundError::BadTrojan(format!(
            "trojan UDP payload too large: {} bytes",
            payload.len()
        )));
    }
    let metadata = TrojanMetadata::parse("udp", target)?;
    let metadata_bytes = metadata.encode()?;
    let mut out = Vec::with_capacity(metadata_bytes.len() + 4 + payload.len());
    out.extend_from_slice(&metadata_bytes);
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(CRLF);
    out.extend_from_slice(payload);
    Ok(out)
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
