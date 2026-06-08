use super::*;
pub fn aead_mux_exchange_over_stream<S>(
    stream: &mut S,
    proxy: &str,
    uuid: &str,
    mux_id: [u8; 2],
    mux_target: &str,
    network: &str,
    payload: &[u8],
) -> Result<VMessAeadMuxExchangeReport, OutboundError>
where
    S: Read + Write,
{
    let request_target = "0.0.0.0:0";
    let metadata = VMessMetadata::parse(network, mux_target)?;
    let options = MuxFrameOptions::new(mux_id, metadata.hostname(), metadata.port(), network);
    let new_frame = mux_new_frame(&options)?;
    let data_frame = mux_data_frame(mux_id, payload)?;
    let end_frame = mux_end_frame(mux_id);
    let packet = build_aead_request_chunks(
        uuid,
        request_target,
        VMessNetwork::Mux,
        &[&new_frame, &data_frame, &end_frame],
    )?;
    stream
        .write_all(&packet.header)
        .map_err(|err| OutboundError::BadVmess(err.to_string()))?;
    for chunk in &packet.chunks {
        stream
            .write_all(chunk)
            .map_err(|err| OutboundError::BadVmess(err.to_string()))?;
    }

    let (response_header_len, response_payload, response_chunk_len) =
        read_aead_response_header_and_chunk(stream, &packet.request)?;
    let echoed = read_mux_frame_from_bytes(&response_payload)?;
    if echoed.id != mux_id
        || echoed.status != crate::shared_transport::mux::SESSION_STATUS_KEEP
        || echoed.option != crate::shared_transport::mux::OPTION_DATA
    {
        return Err(OutboundError::BadVmess(format!(
            "VMess mux response frame mismatch: id={:?} status={} option={}",
            echoed.id, echoed.status, echoed.option
        )));
    }
    if echoed.payload != payload {
        return Err(OutboundError::BadVmess(
            "VMess mux payload response mismatch".to_owned(),
        ));
    }

    Ok(VMessAeadMuxExchangeReport {
        proxy: proxy.to_owned(),
        request_target: request_target.to_owned(),
        mux_target: mux_target.to_owned(),
        uuid: normalize_vmess_uuid(uuid),
        cmd_key_hex: packet.request.cmd_key_hex,
        command: VMessNetwork::Mux.byte(),
        security: VMESS_AEAD_SECURITY_AES_128_GCM,
        mux_id_hex: hex_encode(&mux_id),
        request_header_len: packet.header.len(),
        request_chunk_len: packet.request.request_chunk_len,
        response_header_len,
        response_chunk_len,
        payload_len: payload.len(),
        echoed_payload: echoed.payload,
        new_frame_validated: true,
        data_frame_validated: true,
        end_frame_sent: true,
        true_dataplane: true,
        default_go_path: true,
    })
}
