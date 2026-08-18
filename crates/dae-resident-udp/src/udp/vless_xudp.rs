use super::*;

#[cfg(any(test, feature = "test-support"))]
pub fn build_vless_udp_request(
    proxy: &ResidentProxyPlan,
    original_dst: SocketAddr,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    let key = proxy.vless_key()?;
    if proxy.execution_plan().protocol != ResidentProtocolShape::VlessVision {
        return packet::first_write_bytes(
            &key,
            &proxy.flow,
            "udp",
            &original_dst.to_string(),
            false,
            payload,
        )
        .map_err(|err| format!("build VLESS UDP request: {err}"));
    }
    let mut request = packet::request_header(&key, &proxy.flow, "tcp", XUDP_MUX_TARGET, true, &[])
        .map_err(|err| format!("build VLESS Vision XUDP mux request header: {err}"))?;
    let frame = xudp_new_frame(original_dst, payload)?;
    let mut uuid_sent = false;
    request.extend_from_slice(&vision_padding_block(
        &frame,
        VISION_COMMAND_CONTINUE,
        key,
        &mut uuid_sent,
        false,
    ));
    Ok(request)
}

pub fn xudp_new_frame(original_dst: SocketAddr, payload: &[u8]) -> Result<Vec<u8>, String> {
    let addr_len = match original_dst {
        SocketAddr::V4(_) => 4,
        SocketAddr::V6(_) => 16,
    };
    let mut metadata = Vec::with_capacity(2 + 3 + 2 + 1 + addr_len);
    metadata.extend_from_slice(&0_u16.to_be_bytes());
    metadata.push(XUDP_COMMAND_NEW);
    metadata.push(XUDP_OPTION_DATA);
    metadata.push(XUDP_NETWORK_UDP);
    metadata.extend_from_slice(&original_dst.port().to_be_bytes());
    match original_dst {
        SocketAddr::V4(addr) => {
            metadata.push(1);
            metadata.extend_from_slice(&addr.ip().octets());
        }
        SocketAddr::V6(addr) => {
            metadata.push(3);
            metadata.extend_from_slice(&addr.ip().octets());
        }
    }
    xudp_frame(metadata, payload)
}

pub fn xudp_keep_frame(payload: &[u8]) -> Result<Vec<u8>, String> {
    let mut metadata = Vec::with_capacity(4);
    metadata.extend_from_slice(&0_u16.to_be_bytes());
    metadata.push(XUDP_COMMAND_KEEP);
    metadata.push(XUDP_OPTION_DATA);
    xudp_frame(metadata, payload)
}

fn xudp_frame(metadata: Vec<u8>, payload: &[u8]) -> Result<Vec<u8>, String> {
    if payload.len() > u16::MAX as usize {
        return Err(format!("XUDP payload too large: {} bytes", payload.len()));
    }
    if metadata.len() > u16::MAX as usize {
        return Err(format!("XUDP metadata too large: {} bytes", metadata.len()));
    }
    let mut frame = Vec::with_capacity(2 + metadata.len() + 2 + payload.len());
    frame.extend_from_slice(&(metadata.len() as u16).to_be_bytes());
    frame.extend_from_slice(&metadata);
    frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    frame.extend_from_slice(payload);
    Ok(frame)
}
