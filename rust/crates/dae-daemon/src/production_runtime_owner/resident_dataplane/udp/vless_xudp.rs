fn flush_tls_writes_for_udp(client: &mut VlessTlsClient) -> Result<(), String> {
    let stop = AtomicBool::new(false);
    super::client::flush_tls_writes(client, &stop)
}

fn build_vless_udp_request(
    proxy: &ResidentProxyPlan,
    original_dst: SocketAddrV4,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    let key = proxy.vless_key()?;
    if proxy.flow != XTLS_RPRX_VISION {
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
    let frame = xudp_frame(original_dst, payload)?;
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

fn xudp_frame(original_dst: SocketAddrV4, payload: &[u8]) -> Result<Vec<u8>, String> {
    if payload.len() > u16::MAX as usize {
        return Err(format!("XUDP payload too large: {} bytes", payload.len()));
    }
    let mut metadata = Vec::with_capacity(2 + 3 + 2 + 1 + 4);
    metadata.extend_from_slice(&0_u16.to_be_bytes());
    metadata.push(XUDP_COMMAND_NEW);
    metadata.push(XUDP_OPTION_DATA);
    metadata.push(XUDP_NETWORK_UDP);
    metadata.extend_from_slice(&original_dst.port().to_be_bytes());
    metadata.push(1);
    metadata.extend_from_slice(&original_dst.ip().octets());
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
