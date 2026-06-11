use std::fmt;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Base64DecodeError {
    pub returned: String,
    pub message: String,
}

impl fmt::Display for Base64DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Base64DecodeError {}

pub fn base64_url_decode(input: &str) -> Result<Vec<u8>, Base64DecodeError> {
    decode_with(input, &URL_SAFE)
}

pub fn base64_std_decode(input: &str) -> Result<Vec<u8>, Base64DecodeError> {
    decode_with(input, &STANDARD)
}

fn decode_with(
    input: &str,
    engine: &base64::engine::GeneralPurpose,
) -> Result<Vec<u8>, Base64DecodeError> {
    let trimmed = input.trim();
    let mut padded = trimmed.to_owned();
    let remainder = padded.len() % 4;
    if remainder > 0 {
        padded.extend(std::iter::repeat_n('=', 4 - remainder));
    }

    engine
        .decode(padded.as_bytes())
        .map_err(|source| Base64DecodeError {
            returned: trimmed.to_owned(),
            message: base64_decode_error_message(source),
        })
}

fn base64_decode_error_message(source: base64::DecodeError) -> String {
    match source {
        base64::DecodeError::InvalidByte(offset, _) => {
            format!("illegal base64 data at input byte {offset}")
        }
        base64::DecodeError::InvalidLength(offset) => {
            format!("illegal base64 data at input byte {offset}")
        }
        base64::DecodeError::InvalidLastSymbol(offset, _) => {
            format!("illegal base64 data at input byte {offset}")
        }
        base64::DecodeError::InvalidPadding => "illegal base64 data at input byte 0".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_decode_matches_golden_fixture() {
        let fixture = dae_golden::load_json("config/utils/basic.json").unwrap();

        assert_cases(&fixture["base64"]["url"], base64_url_decode);
        assert_cases(&fixture["base64"]["std"], base64_std_decode);
    }

    fn assert_cases(
        cases: &serde_json::Value,
        decode: fn(&str) -> Result<Vec<u8>, Base64DecodeError>,
    ) {
        for case in cases.as_array().unwrap() {
            let input = case["input"].as_str().unwrap();
            let got = decode(input);
            assert_eq!(got.is_ok(), case["ok"].as_bool().unwrap(), "{input}");
            match got {
                Ok(decoded) => {
                    assert_eq!(hex_encode(&decoded), case["decoded_hex"].as_str().unwrap());
                    if let Some(text) = case["decoded_text"].as_str() {
                        assert_eq!(String::from_utf8(decoded).unwrap(), text);
                    }
                }
                Err(err) => {
                    assert_eq!(err.returned, case["return"].as_str().unwrap());
                    assert_eq!(err.to_string(), case["error"].as_str().unwrap());
                }
            }
        }
    }

    fn hex_encode(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 0x0f) as usize] as char);
        }
        out
    }
}
