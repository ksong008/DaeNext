use super::MasqueCodecError;

const QUIC_VARINT_MAX: u64 = (1_u64 << 62) - 1;

pub fn quic_varint_encoded_len(value: u64) -> Result<usize, MasqueCodecError> {
    match value {
        0..=63 => Ok(1),
        64..=16_383 => Ok(2),
        16_384..=1_073_741_823 => Ok(4),
        1_073_741_824..=QUIC_VARINT_MAX => Ok(8),
        _ => Err(MasqueCodecError::VarIntOverflow(value)),
    }
}

pub fn encode_quic_varint(value: u64, output: &mut Vec<u8>) -> Result<usize, MasqueCodecError> {
    let encoded_len = quic_varint_encoded_len(value)?;
    match encoded_len {
        1 => output.push(value as u8),
        2 => output.extend_from_slice(&(value as u16 | 0x4000).to_be_bytes()),
        4 => output.extend_from_slice(&(value as u32 | 0x8000_0000).to_be_bytes()),
        8 => output.extend_from_slice(&(value | 0xc000_0000_0000_0000).to_be_bytes()),
        _ => unreachable!("QUIC variable integer length is fixed"),
    }
    Ok(encoded_len)
}

pub fn decode_quic_varint_prefix(input: &[u8]) -> Result<Option<(u64, usize)>, MasqueCodecError> {
    let Some(first) = input.first().copied() else {
        return Ok(None);
    };
    let encoded_len = 1_usize << (first >> 6);
    if input.len() < encoded_len {
        return Ok(None);
    }
    let mut value = u64::from(first & 0x3f);
    for byte in &input[1..encoded_len] {
        value = (value << 8) | u64::from(*byte);
    }
    Ok(Some((value, encoded_len)))
}

pub fn decode_quic_varint_exact(input: &[u8]) -> Result<u64, MasqueCodecError> {
    let (value, consumed) =
        decode_quic_varint_prefix(input)?.ok_or(MasqueCodecError::TruncatedVarInt)?;
    if consumed != input.len() {
        return Err(MasqueCodecError::TrailingVarIntBytes(
            input.len() - consumed,
        ));
    }
    Ok(value)
}

#[cfg(test)]
mod tests;
