use crate::GeoDataError;

pub fn decode_hex(input: &str) -> Result<Vec<u8>, GeoDataError> {
    if input.len() % 2 != 0 {
        return Err(GeoDataError::InvalidHex(input.to_owned()));
    }

    input
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let hi = hex_nibble(pair[0])?;
            let lo = hex_nibble(pair[1])?;
            Ok((hi << 4) | lo)
        })
        .collect()
}

fn hex_nibble(ch: u8) -> Result<u8, GeoDataError> {
    match ch {
        b'0'..=b'9' => Ok(ch - b'0'),
        b'a'..=b'f' => Ok(ch - b'a' + 10),
        b'A'..=b'F' => Ok(ch - b'A' + 10),
        _ => Err(GeoDataError::InvalidHex((ch as char).to_string())),
    }
}
