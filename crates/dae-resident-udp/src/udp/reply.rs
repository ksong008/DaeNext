use super::*;
#[cfg(any(test, feature = "test-support"))]
use dae_outbound_core::vless::contract::is_xtls_rprx_vision_flow;
#[cfg(any(test, feature = "test-support"))]
use dae_resident_transport::VisionUnpadState;

mod actor;
pub use actor::{UdpReplyDispatcher, UdpReplyHandle};

#[cfg(any(test, feature = "test-support"))]
pub fn parse_vless_udp_response(
    input: &[u8],
    flow: &str,
    user_uuid: [u8; 16],
) -> Result<Option<Vec<u8>>, String> {
    if input.len() < 2 {
        return Ok(None);
    }
    if input[0] != VLESS_RESPONSE_VERSION {
        return Err(format!("unexpected VLESS response version: {}", input[0]));
    }
    let header_len = 2 + input[1] as usize;
    if input.len() < header_len {
        return Ok(None);
    }
    if is_xtls_rprx_vision_flow(flow) {
        if input.len() == header_len {
            return Ok(None);
        }
        let mut unpadder = VisionUnpadder::new(user_uuid);
        let payload = unpadder.consume(&input[header_len..])?;
        if payload.is_empty() && !matches!(unpadder.state, VisionUnpadState::Raw) {
            return Ok(None);
        }
        return parse_xudp_response_payload(&payload);
    }
    if input.len() < header_len + 2 {
        return Ok(None);
    }
    let payload_len = u16::from_be_bytes([input[header_len], input[header_len + 1]]) as usize;
    if input.len() < header_len + 2 + payload_len {
        return Ok(None);
    }
    Ok(Some(
        input[header_len + 2..header_len + 2 + payload_len].to_vec(),
    ))
}

#[cfg(any(test, feature = "test-support"))]
pub fn parse_xudp_response_payload(input: &[u8]) -> Result<Option<Vec<u8>>, String> {
    Ok(parse_xudp_response_frame(input)?.map(|(payload, _)| payload))
}

pub fn parse_xudp_response_frame(input: &[u8]) -> Result<Option<(Vec<u8>, usize)>, String> {
    if input.len() < 2 {
        return Ok(None);
    }
    let metadata_len = u16::from_be_bytes([input[0], input[1]]) as usize;
    let payload_len_offset = 2 + metadata_len;
    if input.len() < payload_len_offset + 2 {
        return Ok(None);
    }
    let payload_len =
        u16::from_be_bytes([input[payload_len_offset], input[payload_len_offset + 1]]) as usize;
    let payload_offset = payload_len_offset + 2;
    if input.len() < payload_offset + payload_len {
        return Ok(None);
    }
    Ok(Some((
        input[payload_offset..payload_offset + payload_len].to_vec(),
        payload_offset + payload_len,
    )))
}
