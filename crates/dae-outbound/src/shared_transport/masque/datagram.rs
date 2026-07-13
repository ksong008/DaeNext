use bytes::Bytes;

use super::{
    CONNECT_UDP_CONTEXT_ID, MasqueCodecError, decode_quic_varint_prefix, encode_quic_varint,
    quic_varint_encoded_len,
};

const MAX_HTTP3_REQUEST_STREAM_ID: u64 = (1_u64 << 62) - 4;
const MAX_QUARTER_STREAM_ID: u64 = MAX_HTTP3_REQUEST_STREAM_ID / 4;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct MasqueQuarterStreamId(u64);

impl MasqueQuarterStreamId {
    pub fn from_http3_stream_id(stream_id: u64) -> Result<Self, MasqueCodecError> {
        if stream_id > MAX_HTTP3_REQUEST_STREAM_ID || stream_id & 0b11 != 0 {
            return Err(MasqueCodecError::InvalidRequestStreamId(stream_id));
        }
        Ok(Self(stream_id / 4))
    }

    pub fn from_quarter_stream_id(value: u64) -> Result<Self, MasqueCodecError> {
        if value > MAX_QUARTER_STREAM_ID {
            return Err(MasqueCodecError::InvalidRequestStreamId(
                value.saturating_mul(4),
            ));
        }
        quic_varint_encoded_len(value)?;
        Ok(Self(value))
    }

    pub fn value(self) -> u64 {
        self.0
    }

    pub fn http3_stream_id(self) -> u64 {
        self.0 * 4
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MasqueHttpDatagram {
    pub quarter_stream_id: MasqueQuarterStreamId,
    pub payload: Bytes,
}

pub fn encode_http_datagram(
    quarter_stream_id: MasqueQuarterStreamId,
    payload: &[u8],
    max_datagram_payload_bytes: usize,
) -> Result<Vec<u8>, MasqueCodecError> {
    validate_payload_len(payload.len(), max_datagram_payload_bytes)?;
    let mut encoded = Vec::with_capacity(payload.len().saturating_add(9));
    encode_quic_varint(quarter_stream_id.value(), &mut encoded)?;
    encode_quic_varint(CONNECT_UDP_CONTEXT_ID, &mut encoded)?;
    encoded.extend_from_slice(payload);
    Ok(encoded)
}

pub fn decode_http_datagram(
    encoded: Bytes,
    max_datagram_payload_bytes: usize,
) -> Result<MasqueHttpDatagram, MasqueCodecError> {
    let (quarter_stream_id, quarter_len) =
        decode_quic_varint_prefix(&encoded)?.ok_or(MasqueCodecError::TruncatedVarInt)?;
    let (context_id, context_len) = decode_quic_varint_prefix(&encoded[quarter_len..])?
        .ok_or(MasqueCodecError::TruncatedVarInt)?;
    if context_id != CONNECT_UDP_CONTEXT_ID {
        return Err(MasqueCodecError::UnsupportedContextId(context_id));
    }
    let payload_offset = quarter_len
        .checked_add(context_len)
        .ok_or(MasqueCodecError::LengthOverflow)?;
    let payload = encoded.slice(payload_offset..);
    validate_payload_len(payload.len(), max_datagram_payload_bytes)?;
    Ok(MasqueHttpDatagram {
        quarter_stream_id: MasqueQuarterStreamId::from_quarter_stream_id(quarter_stream_id)?,
        payload,
    })
}

fn validate_payload_len(actual: usize, limit: usize) -> Result<(), MasqueCodecError> {
    if limit == 0 {
        return Err(MasqueCodecError::InvalidLimits(
            "HTTP Datagram payload limit must be non-zero".to_owned(),
        ));
    }
    if actual > limit {
        return Err(MasqueCodecError::DatagramPayloadLimitExceeded { limit, actual });
    }
    Ok(())
}

#[cfg(test)]
mod tests;
