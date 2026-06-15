use crate::error::OutboundError;
use crate::vmess::{VMessMetadata, VMessNetwork};

use super::contract::is_xtls_rprx_vision_flow;

pub fn request_header(
    key: &[u8; 16],
    flow: &str,
    network: &str,
    target: &str,
    mux: bool,
    payload: &[u8],
) -> Result<Vec<u8>, OutboundError> {
    let metadata = VMessMetadata::parse(network, target)?;
    let addons = addons_bytes(flow);
    let mut out = Vec::new();
    out.push(0);
    out.extend_from_slice(key);
    if addons.len() > u8::MAX as usize {
        return Err(OutboundError::BadVless(format!(
            "vless addons too long: {} bytes",
            addons.len()
        )));
    }
    out.push(addons.len() as u8);
    out.extend_from_slice(&addons);
    if mux {
        out.push(VMessNetwork::Mux.byte());
    } else {
        out.push(metadata.network.byte());
        out.extend_from_slice(&metadata.port().to_be_bytes());
        out.push(metadata.metadata_type().byte());
        metadata.write_addr_to(&mut out)?;
    }
    out.extend_from_slice(payload);
    Ok(out)
}

pub fn first_write_bytes(
    key: &[u8; 16],
    flow: &str,
    network: &str,
    target: &str,
    mux: bool,
    payload: &[u8],
) -> Result<Vec<u8>, OutboundError> {
    if network == "udp" && !is_xtls_rprx_vision_flow(flow) {
        let mut len_payload = Vec::with_capacity(2);
        len_payload.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        let mut out = request_header(key, flow, network, target, mux, &len_payload)?;
        out.extend_from_slice(payload);
        return Ok(out);
    }
    request_header(key, flow, network, target, mux, payload)
}

pub fn addons_bytes(flow: &str) -> Vec<u8> {
    if flow.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    out.push(0x0a);
    write_varint(flow.len() as u64, &mut out);
    out.extend_from_slice(flow.as_bytes());
    out
}

fn write_varint(mut value: u64, out: &mut Vec<u8>) {
    while value >= 0x80 {
        out.push((value as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}
