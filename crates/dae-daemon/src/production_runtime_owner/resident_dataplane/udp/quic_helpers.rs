use super::*;

pub(in crate::production_runtime_owner::resident_dataplane) fn build_juicity_stream_packet_request(
    target: &str,
    frame: &[u8],
) -> Result<Vec<u8>, String> {
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
) -> Result<JuicityStreamPacketFrame, String> {
    const READ_CHUNK_BYTES: usize = 4 * 1024;
    const RESPONSE_BUFFER_LIMIT: usize = JUICITY_STREAM_PACKET_MAX_FRAME_LEN + READ_CHUNK_BYTES;
    let mut buf = [0_u8; READ_CHUNK_BYTES];
    loop {
        match decode_stream_packet_frame_prefix(response) {
            Ok(Some((frame, consumed))) => {
                response.drain(..consumed);
                return Ok(frame);
            }
            Ok(None) => {}
            Err(err) => return Err(format!("decode Juicity UDP stream packet: {err}")),
        }
        if response.len() >= RESPONSE_BUFFER_LIMIT {
            return Err(format!(
                "Juicity UDP stream response exceeds the bounded frame buffer ({RESPONSE_BUFFER_LIMIT} bytes)"
            ));
        }
        let read_limit = (RESPONSE_BUFFER_LIMIT - response.len()).min(buf.len());
        match recv
            .read(&mut buf[..read_limit])
            .await
            .map_err(|err| format!("read Juicity UDP stream response: {err}"))?
        {
            Some(0) => {
                return Err("Juicity UDP stream returned an empty read".to_owned());
            }
            Some(read) => response.extend_from_slice(&buf[..read]),
            None => {
                return Err(
                    "Juicity UDP stream closed before a complete packet frame was decoded"
                        .to_owned(),
                );
            }
        }
    }
}
