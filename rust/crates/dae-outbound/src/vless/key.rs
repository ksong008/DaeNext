use crate::error::OutboundError;
use crate::vmess::uuid::normalize_vmess_uuid;

pub fn password_to_key(password: &str) -> Result<[u8; 16], OutboundError> {
    let normalized = normalize_vmess_uuid(password);
    let compact = normalized.replace('-', "");
    if compact.len() != 32 {
        return Err(OutboundError::BadVless(format!("invalid UUID: {compact}")));
    }
    let mut out = [0_u8; 16];
    for (index, chunk) in compact.as_bytes().chunks(2).enumerate() {
        out[index] = (hex_nibble(chunk[0])? << 4) | hex_nibble(chunk[1])?;
    }
    Ok(out)
}

fn hex_nibble(byte: u8) -> Result<u8, OutboundError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(OutboundError::BadVless(format!(
            "bad uuid hex byte: {byte}"
        ))),
    }
}
