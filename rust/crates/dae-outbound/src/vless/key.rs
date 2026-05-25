use crate::error::OutboundError;
use crate::vmess::uuid::string_to_uuid5_bytes;

pub fn password_to_key(password: &str) -> Result<[u8; 16], OutboundError> {
    if !(32..=36).contains(&password.len()) {
        return Ok(string_to_uuid5_bytes(password));
    }
    let mut out = [0_u8; 16];
    let mut high = 0_u8;
    let mut nibble_count = 0_usize;
    for byte in password.bytes() {
        if byte == b'-' {
            continue;
        }
        let nibble = hex_nibble(byte)?;
        if nibble_count >= 32 {
            return Err(OutboundError::BadVless(format!("invalid UUID: {password}")));
        }
        if nibble_count % 2 == 0 {
            high = nibble << 4;
        } else {
            out[nibble_count / 2] = high | nibble;
        }
        nibble_count += 1;
    }
    if nibble_count != 32 {
        return Err(OutboundError::BadVless(format!("invalid UUID: {password}")));
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
