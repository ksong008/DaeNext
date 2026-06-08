use super::*;
pub fn response_header_bytes() -> [u8; 2] {
    [VLESS_VERSION, 0]
}

pub fn udp_response_packet(payload: &[u8]) -> Result<Vec<u8>, OutboundError> {
    if payload.len() > u16::MAX as usize {
        return Err(OutboundError::BadVless(format!(
            "vless udp payload too long: {} bytes",
            payload.len()
        )));
    }
    let mut out = Vec::with_capacity(2 + 2 + payload.len());
    out.extend_from_slice(&response_header_bytes());
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

pub fn response_payload_bytes(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + payload.len());
    out.extend_from_slice(&response_header_bytes());
    out.extend_from_slice(payload);
    out
}
