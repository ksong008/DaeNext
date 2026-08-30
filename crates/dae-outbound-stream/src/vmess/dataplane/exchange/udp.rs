use super::*;
pub fn aead_udp_over_tcp_exchange_over_stream<S>(
    stream: &mut S,
    proxy: &str,
    uuid: &str,
    target: &str,
    payload: &[u8],
) -> Result<VMessAeadUdpOverTcpExchangeReport, OutboundError>
where
    S: Read + Write,
{
    let packet = build_aead_request(uuid, target, VMessNetwork::Udp, payload)?;
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
            "VMess AEAD UDP-over-TCP payload response mismatch".to_owned(),
        ));
    }

    Ok(VMessAeadUdpOverTcpExchangeReport {
        proxy: proxy.to_owned(),
        target: target.to_owned(),
        uuid: normalize_vmess_uuid(uuid),
        cmd_key_hex: packet.request.cmd_key_hex,
        command: VMessNetwork::Udp.byte(),
        security: VMESS_AEAD_SECURITY_AES_128_GCM,
        request_header_len: packet.header.len(),
        request_chunk_len: packet.chunk.len(),
        response_header_len,
        response_chunk_len,
        payload_len: payload.len(),
        packet_len: payload.len(),
        echoed_payload,
        true_dataplane: true,
    })
}

pub fn aead_packet_addr_udp_exchange_over_stream<S>(
    stream: &mut S,
    proxy: &str,
    uuid: &str,
    packet_target: &str,
    payload: &[u8],
) -> Result<VMessAeadPacketAddrUdpExchangeReport, OutboundError>
where
    S: Read + Write,
{
    let request_target = packet_addr_magic_target(packet_target)?;
    let packet_payload = put_packet_addr_payload(packet_target, payload)?;
    let packet = build_aead_request(uuid, &request_target, VMessNetwork::Udp, &packet_payload)?;
    stream
        .write_all(&packet.header)
        .map_err(|err| OutboundError::BadVmess(err.to_string()))?;
    stream
        .write_all(&packet.chunk)
        .map_err(|err| OutboundError::BadVmess(err.to_string()))?;

    let (response_header_len, echoed_packet, response_chunk_len) =
        read_aead_response_header_and_chunk(stream, &packet.request)?;
    let (echoed_target, packet_addr_len, echoed_payload) =
        parse_packet_addr_payload(&echoed_packet)?;
    if echoed_target != packet_target {
        return Err(OutboundError::BadVmess(format!(
            "VMess packet-addr target mismatch: got {echoed_target}, want {packet_target}"
        )));
    }
    if echoed_payload != payload {
        return Err(OutboundError::BadVmess(
            "VMess packet-addr UDP payload response mismatch".to_owned(),
        ));
    }

    Ok(VMessAeadPacketAddrUdpExchangeReport {
        proxy: proxy.to_owned(),
        request_target,
        packet_target: packet_target.to_owned(),
        uuid: normalize_vmess_uuid(uuid),
        cmd_key_hex: packet.request.cmd_key_hex,
        command: VMessNetwork::Udp.byte(),
        security: VMESS_AEAD_SECURITY_AES_128_GCM,
        request_header_len: packet.header.len(),
        request_chunk_len: packet.chunk.len(),
        response_header_len,
        response_chunk_len,
        payload_len: payload.len(),
        packet_addr_len,
        packet_len: packet_payload.len(),
        echoed_payload,
        true_dataplane: true,
    })
}
