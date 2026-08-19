use super::*;

pub fn build_juicity_stream_packet_request(target: &str, frame: &[u8]) -> Result<Vec<u8>, String> {
    let metadata = dae_outbound::trojan::TrojanMetadata::parse("udp", target)
        .map_err(|err| format!("build Juicity UDP metadata: {err}"))?;
    let metadata = metadata
        .encode()
        .map_err(|err| format!("encode Juicity UDP metadata: {err}"))?;
    let mut out = Vec::with_capacity(1 + metadata.len() + frame.len());
    out.push(3);
    out.extend_from_slice(&metadata);
    out.extend_from_slice(frame);
    Ok(out)
}

pub(super) async fn read_juicity_stream_packet_response(
    recv: &mut quinn::RecvStream,
    response: &mut Vec<u8>,
    response_cursor: &mut usize,
    mode: UdpStreamReadMode,
) -> Result<Option<JuicityStreamPacketPayload>, String> {
    const READ_CHUNK_BYTES: usize = 4 * 1024;
    const RESPONSE_BUFFER_LIMIT: usize = JUICITY_STREAM_PACKET_MAX_FRAME_LEN + READ_CHUNK_BYTES;
    let mut buf = [0_u8; READ_CHUNK_BYTES];
    loop {
        match decode_stream_packet_payload_prefix(&response[*response_cursor..]) {
            Ok(Some((frame, consumed))) => {
                *response_cursor += consumed;
                compact_juicity_response_buffer(response, response_cursor);
                return Ok(Some(frame));
            }
            Ok(None) => {}
            Err(err) => return Err(format!("decode Juicity UDP stream packet: {err}")),
        }
        compact_juicity_response_buffer(response, response_cursor);
        if response.len() >= RESPONSE_BUFFER_LIMIT {
            return Err(format!(
                "Juicity UDP stream response exceeds the bounded frame buffer ({RESPONSE_BUFFER_LIMIT} bytes)"
            ));
        }
        let read_limit = (RESPONSE_BUFFER_LIMIT - response.len()).min(buf.len());
        match read_udp_stream_once(
            recv,
            &mut buf[..read_limit],
            mode,
            "read Juicity UDP stream response",
        )
        .await?
        {
            Some(read) => response.extend_from_slice(&buf[..read]),
            None => return Ok(None),
        }
    }
}

fn compact_juicity_response_buffer(response: &mut Vec<u8>, cursor: &mut usize) {
    if *cursor == 0 {
        return;
    }
    if *cursor >= response.len() {
        response.clear();
        *cursor = 0;
        return;
    }
    if *cursor >= 8192 && cursor.saturating_mul(2) >= response.len() {
        response.drain(..*cursor);
        *cursor = 0;
    }
}
