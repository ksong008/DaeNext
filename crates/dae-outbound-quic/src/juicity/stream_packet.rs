use dae_outbound_core::error::OutboundError;
use dae_outbound_core::trojan::TrojanMetadata;

pub const JUICITY_STREAM_PACKET_MAX_METADATA_LEN: usize = 1 + 1 + u8::MAX as usize + 2;
pub const JUICITY_STREAM_PACKET_MAX_FRAME_LEN: usize =
    JUICITY_STREAM_PACKET_MAX_METADATA_LEN + 2 + u16::MAX as usize;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JuicityStreamPacketFrame {
    pub target: String,
    pub metadata_len: usize,
    pub payload_len: usize,
    pub encoded: Vec<u8>,
}

impl JuicityStreamPacketFrame {
    pub fn payload(&self) -> &[u8] {
        let start = self.metadata_len + 2;
        self.encoded
            .get(start..start + self.payload_len)
            .unwrap_or_default()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JuicityStreamPacketPayload {
    pub target: String,
    pub payload: Vec<u8>,
}

pub fn seal_stream_packet_frame(
    target: &str,
    payload: &[u8],
) -> Result<JuicityStreamPacketFrame, OutboundError> {
    let (metadata, metadata_bytes) = encode_stream_packet_metadata(target, payload.len())?;
    let mut encoded = Vec::with_capacity(metadata_bytes.len() + 2 + payload.len());
    encoded.extend_from_slice(&metadata_bytes);
    encoded.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    encoded.extend_from_slice(payload);
    Ok(JuicityStreamPacketFrame {
        target: metadata.authority(),
        metadata_len: metadata_bytes.len(),
        payload_len: payload.len(),
        encoded,
    })
}

pub fn encode_stream_packet_frame(target: &str, payload: &[u8]) -> Result<Vec<u8>, OutboundError> {
    Ok(seal_stream_packet_frame(target, payload)?.encoded)
}

pub fn decode_stream_packet_frame(input: &[u8]) -> Result<JuicityStreamPacketFrame, OutboundError> {
    let (address, metadata_len) = dae_outbound_core::socks5::Socks5Address::decode(input)?;
    if input.len() < metadata_len + 2 {
        return Err(OutboundError::BadJuicity(
            "juicity stream packet frame missing length".to_owned(),
        ));
    }
    let payload_len = u16::from_be_bytes([input[metadata_len], input[metadata_len + 1]]) as usize;
    let payload_start = metadata_len + 2;
    let packet_len = payload_start + payload_len;
    if input.len() != packet_len {
        return Err(OutboundError::BadJuicity(format!(
            "juicity stream packet frame length mismatch: got {}, want {}",
            input.len(),
            packet_len
        )));
    }
    Ok(JuicityStreamPacketFrame {
        target: address.authority(),
        metadata_len,
        payload_len,
        encoded: input.to_vec(),
    })
}

pub fn stream_packet_frame_len(input: &[u8]) -> Result<Option<usize>, OutboundError> {
    let Some(atyp) = input.first().copied() else {
        return Ok(None);
    };
    let metadata_len = match atyp {
        1 => 1 + 4 + 2,
        4 => 1 + 16 + 2,
        3 => {
            let Some(domain_len) = input.get(1).copied() else {
                return Ok(None);
            };
            1 + 1 + domain_len as usize + 2
        }
        _ => {
            return Err(OutboundError::BadJuicity(format!(
                "juicity stream packet address type is invalid: {atyp}"
            )));
        }
    };
    if input.len() < metadata_len + 2 {
        return Ok(None);
    }
    let payload_len = u16::from_be_bytes([input[metadata_len], input[metadata_len + 1]]) as usize;
    Ok(Some(metadata_len + 2 + payload_len))
}

pub fn decode_stream_packet_frame_prefix(
    input: &[u8],
) -> Result<Option<(JuicityStreamPacketFrame, usize)>, OutboundError> {
    let Some(frame_len) = stream_packet_frame_len(input)? else {
        return Ok(None);
    };
    if input.len() < frame_len {
        return Ok(None);
    }
    decode_stream_packet_frame(&input[..frame_len]).map(|frame| Some((frame, frame_len)))
}

pub fn decode_stream_packet_payload_prefix(
    input: &[u8],
) -> Result<Option<(JuicityStreamPacketPayload, usize)>, OutboundError> {
    let Some(frame_len) = stream_packet_frame_len(input)? else {
        return Ok(None);
    };
    if input.len() < frame_len {
        return Ok(None);
    }
    let frame = &input[..frame_len];
    let (address, metadata_len) = dae_outbound_core::socks5::Socks5Address::decode(frame)?;
    let payload_start = metadata_len + 2;
    Ok(Some((
        JuicityStreamPacketPayload {
            target: address.authority(),
            payload: frame[payload_start..].to_vec(),
        },
        frame_len,
    )))
}

fn encode_stream_packet_metadata(
    target: &str,
    payload_len: usize,
) -> Result<(TrojanMetadata, Vec<u8>), OutboundError> {
    if payload_len > u16::MAX as usize {
        return Err(OutboundError::BadJuicity(format!(
            "juicity stream packet payload too large: {payload_len} bytes"
        )));
    }
    let metadata = TrojanMetadata::parse("udp", target)?;
    if metadata.port() == 0 {
        return Err(OutboundError::BadJuicity(
            "juicity stream packet frame requires nonzero UDP target port".to_owned(),
        ));
    }
    let metadata_bytes = metadata.encode()?;
    Ok((metadata, metadata_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_packet_wire_roundtrips_and_preserves_trailing_frame() {
        let first = seal_stream_packet_frame("192.0.2.10:53", b"first").unwrap();
        let second = seal_stream_packet_frame("[2001:db8::10]:5353", b"second").unwrap();
        let mut joined = first.encoded.clone();
        joined.extend_from_slice(&second.encoded);

        let (decoded, consumed) = decode_stream_packet_frame_prefix(&joined).unwrap().unwrap();
        assert_eq!(decoded.target, first.target);
        assert_eq!(decoded.payload(), b"first");
        assert_eq!(consumed, first.encoded.len());
        assert_eq!(
            decode_stream_packet_frame(&second.encoded)
                .unwrap()
                .payload(),
            b"second"
        );
    }

    #[test]
    fn stream_packet_wire_rejects_port_zero_and_oversized_payload() {
        assert!(seal_stream_packet_frame("192.0.2.10:0", b"payload").is_err());
        assert!(
            seal_stream_packet_frame("192.0.2.10:53", &vec![0; u16::MAX as usize + 1]).is_err()
        );
    }

    #[test]
    fn stream_packet_wire_bound_matches_address_and_length_widths() {
        assert_eq!(JUICITY_STREAM_PACKET_MAX_METADATA_LEN, 259);
        assert_eq!(
            JUICITY_STREAM_PACKET_MAX_FRAME_LEN,
            JUICITY_STREAM_PACKET_MAX_METADATA_LEN + 2 + u16::MAX as usize
        );
    }
}
