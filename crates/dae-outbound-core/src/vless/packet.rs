use crate::error::OutboundError;
use crate::vmess::{VMessMetadata, VMessNetwork};

use super::contract::{XTLS_RPRX_VISION, is_xtls_rprx_vision_flow};

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
        if payload.len() > u16::MAX as usize {
            return Err(OutboundError::BadVless(format!(
                "vless udp payload too long: {} bytes",
                payload.len()
            )));
        }
        let mut len_payload = Vec::with_capacity(2);
        len_payload.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        let mut out = request_header(key, flow, network, target, mux, &len_payload)?;
        out.extend_from_slice(payload);
        return Ok(out);
    }
    request_header(key, flow, network, target, mux, payload)
}

pub fn addons_bytes(flow: &str) -> Vec<u8> {
    let flow = if is_xtls_rprx_vision_flow(flow) {
        XTLS_RPRX_VISION
    } else {
        flow
    };
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vision_udp443_policy_uses_the_official_wire_flow() {
        use super::super::contract::XTLS_RPRX_VISION_UDP443;
        for mux in [false, true] {
            let request =
                |flow| request_header(&[0; 16], flow, "tcp", "192.0.2.1:443", mux, &[]).unwrap();
            assert_eq!(request(XTLS_RPRX_VISION), request(XTLS_RPRX_VISION_UDP443));
        }
    }

    #[test]
    fn udp_first_write_rejects_oversized_payload_instead_of_truncating() {
        let key = [0_u8; 16];
        let oversized = vec![0_u8; u16::MAX as usize + 1];
        let err = first_write_bytes(&key, "", "udp", "fixture.invalid:53", false, &oversized)
            .unwrap_err()
            .to_string();
        assert!(err.contains("udp payload too long"));

        let max = vec![0_u8; u16::MAX as usize];
        assert!(first_write_bytes(&key, "", "udp", "fixture.invalid:53", false, &max).is_ok());
    }
}
