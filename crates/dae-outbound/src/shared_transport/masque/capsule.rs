use bytes::{Bytes, BytesMut};

use super::{MasqueCodecError, decode_quic_varint_prefix, encode_quic_varint};

pub const CONNECT_UDP_CAPSULE_TYPE: u64 = 0;
pub const CONNECT_UDP_CONTEXT_ID: u64 = 0;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MasqueCapsuleLimits {
    pub max_buffered_bytes: usize,
    pub max_capsule_payload_bytes: usize,
    pub max_datagram_payload_bytes: usize,
}

impl MasqueCapsuleLimits {
    pub fn new(
        max_buffered_bytes: usize,
        max_capsule_payload_bytes: usize,
        max_datagram_payload_bytes: usize,
    ) -> Result<Self, MasqueCodecError> {
        if max_buffered_bytes == 0
            || max_capsule_payload_bytes == 0
            || max_datagram_payload_bytes == 0
        {
            return Err(MasqueCodecError::InvalidLimits(
                "all Capsule limits must be non-zero".to_owned(),
            ));
        }
        let required_capsule_payload = max_datagram_payload_bytes
            .checked_add(1)
            .ok_or(MasqueCodecError::LengthOverflow)?;
        if max_capsule_payload_bytes < required_capsule_payload {
            return Err(MasqueCodecError::InvalidLimits(format!(
                "Capsule payload limit {max_capsule_payload_bytes} cannot hold Context ID plus datagram limit {max_datagram_payload_bytes}"
            )));
        }
        Ok(Self {
            max_buffered_bytes,
            max_capsule_payload_bytes,
            max_datagram_payload_bytes,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MasqueCapsule {
    Datagram(Bytes),
    Unknown { capsule_type: u64, payload: Bytes },
}

pub struct MasqueCapsuleDecoder {
    limits: MasqueCapsuleLimits,
    buffered: BytesMut,
}

impl MasqueCapsuleDecoder {
    pub fn new(limits: MasqueCapsuleLimits) -> Self {
        Self {
            limits,
            buffered: BytesMut::new(),
        }
    }

    pub fn push(&mut self, input: &[u8]) -> Result<Vec<MasqueCapsule>, MasqueCodecError> {
        let required = self
            .buffered
            .len()
            .checked_add(input.len())
            .ok_or(MasqueCodecError::LengthOverflow)?;
        if required > self.limits.max_buffered_bytes {
            return Err(MasqueCodecError::BufferLimitExceeded {
                limit: self.limits.max_buffered_bytes,
                required,
            });
        }
        self.buffered.extend_from_slice(input);

        let mut capsules = Vec::new();
        while let Some((capsule_type, type_len)) = decode_quic_varint_prefix(&self.buffered)? {
            let Some((payload_len, payload_len_len)) =
                decode_quic_varint_prefix(&self.buffered[type_len..])?
            else {
                break;
            };
            if payload_len > self.limits.max_capsule_payload_bytes as u64 {
                return Err(MasqueCodecError::CapsulePayloadLimitExceeded {
                    limit: self.limits.max_capsule_payload_bytes,
                    actual: payload_len,
                });
            }
            let payload_len =
                usize::try_from(payload_len).map_err(|_| MasqueCodecError::LengthOverflow)?;
            let header_len = type_len
                .checked_add(payload_len_len)
                .ok_or(MasqueCodecError::LengthOverflow)?;
            let frame_len = header_len
                .checked_add(payload_len)
                .ok_or(MasqueCodecError::LengthOverflow)?;
            if frame_len > self.limits.max_buffered_bytes {
                return Err(MasqueCodecError::BufferLimitExceeded {
                    limit: self.limits.max_buffered_bytes,
                    required: frame_len,
                });
            }
            if self.buffered.len() < frame_len {
                break;
            }
            let frame = self.buffered.split_to(frame_len).freeze();
            let payload = frame.slice(header_len..);
            capsules.push(self.decode_capsule(capsule_type, payload)?);
        }
        Ok(capsules)
    }

    pub fn buffered_len(&self) -> usize {
        self.buffered.len()
    }

    pub fn finish(self) -> Result<(), MasqueCodecError> {
        if self.buffered.is_empty() {
            Ok(())
        } else {
            Err(MasqueCodecError::TruncatedCapsule(self.buffered.len()))
        }
    }

    fn decode_capsule(
        &self,
        capsule_type: u64,
        payload: Bytes,
    ) -> Result<MasqueCapsule, MasqueCodecError> {
        if capsule_type != CONNECT_UDP_CAPSULE_TYPE {
            return Ok(MasqueCapsule::Unknown {
                capsule_type,
                payload,
            });
        }
        let (context_id, context_len) =
            decode_quic_varint_prefix(&payload)?.ok_or(MasqueCodecError::TruncatedVarInt)?;
        if context_id != CONNECT_UDP_CONTEXT_ID {
            return Err(MasqueCodecError::UnsupportedContextId(context_id));
        }
        let datagram = payload.slice(context_len..);
        if datagram.len() > self.limits.max_datagram_payload_bytes {
            return Err(MasqueCodecError::DatagramPayloadLimitExceeded {
                limit: self.limits.max_datagram_payload_bytes,
                actual: datagram.len(),
            });
        }
        Ok(MasqueCapsule::Datagram(datagram))
    }
}

pub fn encode_connect_udp_capsule(
    payload: &[u8],
    limits: MasqueCapsuleLimits,
) -> Result<Vec<u8>, MasqueCodecError> {
    if payload.len() > limits.max_datagram_payload_bytes {
        return Err(MasqueCodecError::DatagramPayloadLimitExceeded {
            limit: limits.max_datagram_payload_bytes,
            actual: payload.len(),
        });
    }
    let mut capsule_payload = Vec::with_capacity(payload.len().saturating_add(1));
    encode_quic_varint(CONNECT_UDP_CONTEXT_ID, &mut capsule_payload)?;
    capsule_payload.extend_from_slice(payload);
    encode_capsule(CONNECT_UDP_CAPSULE_TYPE, &capsule_payload, limits)
}

pub fn encode_unknown_capsule(
    capsule_type: u64,
    payload: &[u8],
    limits: MasqueCapsuleLimits,
) -> Result<Vec<u8>, MasqueCodecError> {
    if capsule_type == CONNECT_UDP_CAPSULE_TYPE {
        return Err(MasqueCodecError::InvalidCapsule(
            "unknown Capsule encoder cannot use the DATAGRAM Capsule type".to_owned(),
        ));
    }
    encode_capsule(capsule_type, payload, limits)
}

fn encode_capsule(
    capsule_type: u64,
    payload: &[u8],
    limits: MasqueCapsuleLimits,
) -> Result<Vec<u8>, MasqueCodecError> {
    if payload.len() > limits.max_capsule_payload_bytes {
        return Err(MasqueCodecError::CapsulePayloadLimitExceeded {
            limit: limits.max_capsule_payload_bytes,
            actual: payload.len() as u64,
        });
    }
    let mut encoded = Vec::new();
    encode_quic_varint(capsule_type, &mut encoded)?;
    encode_quic_varint(payload.len() as u64, &mut encoded)?;
    let required = encoded
        .len()
        .checked_add(payload.len())
        .ok_or(MasqueCodecError::LengthOverflow)?;
    if required > limits.max_buffered_bytes {
        return Err(MasqueCodecError::BufferLimitExceeded {
            limit: limits.max_buffered_bytes,
            required,
        });
    }
    encoded.reserve(payload.len());
    encoded.extend_from_slice(payload);
    Ok(encoded)
}

#[cfg(test)]
mod tests;
