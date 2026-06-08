use super::*;
pub fn aead_tcp_exchange_over_stream<S>(
    stream: &mut S,
    proxy: &str,
    uuid: &str,
    target: &str,
    payload: &[u8],
) -> Result<VMessAeadTcpExchangeReport, OutboundError>
where
    S: Read + Write,
{
    let packet = build_aead_request(uuid, target, VMessNetwork::Tcp, payload)?;
    stream
        .write_all(&packet.header)
        .map_err(|err| OutboundError::BadVmess(err.to_string()))?;
    stream
        .write_all(&packet.chunk)
        .map_err(|err| OutboundError::BadVmess(err.to_string()))?;

    let (response_header_len, echoed_payload, response_chunk_len) =
        read_aead_response_header_and_chunk(stream, &packet.request)?;
    if echoed_payload != payload {
        return Err(OutboundError::BadVmess(
            "VMess AEAD TCP payload response mismatch".to_owned(),
        ));
    }

    Ok(VMessAeadTcpExchangeReport {
        proxy: proxy.to_owned(),
        target: target.to_owned(),
        uuid: normalize_vmess_uuid(uuid),
        cmd_key_hex: packet.request.cmd_key_hex,
        command: VMessNetwork::Tcp.byte(),
        security: VMESS_AEAD_SECURITY_AES_128_GCM,
        request_header_len: packet.header.len(),
        request_chunk_len: packet.chunk.len(),
        response_header_len,
        response_chunk_len,
        payload_len: payload.len(),
        echoed_payload,
        true_dataplane: true,
        default_go_path: true,
    })
}
