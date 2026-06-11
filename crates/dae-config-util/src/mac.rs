use std::fmt;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParseMacError {
    InvalidMac { input: String },
    ParseMac { input: String, source: String },
}

impl fmt::Display for ParseMacError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMac { input } => write!(f, "invalid mac: {input}"),
            Self::ParseMac { input, source } => write!(f, "parse mac {input}: {source}"),
        }
    }
}

impl std::error::Error for ParseMacError {}

pub fn parse_mac(input: &str) -> Result<[u8; 6], ParseMacError> {
    let fields: Vec<_> = input.splitn(6, ':').collect();
    if fields.len() != 6 {
        return Err(ParseMacError::InvalidMac {
            input: input.to_owned(),
        });
    }

    let mut addr = [0_u8; 6];
    for (index, field) in fields.iter().enumerate() {
        if field.len() % 2 == 1 {
            return Err(ParseMacError::ParseMac {
                input: input.to_owned(),
                source: "encoding/hex: odd length hex string".to_owned(),
            });
        }
        let value = u8::from_str_radix(field, 16).map_err(|_| ParseMacError::ParseMac {
            input: input.to_owned(),
            source: format!("encoding/hex: invalid byte in {field:?}"),
        })?;
        if field.len() != 2 {
            return Err(ParseMacError::InvalidMac {
                input: input.to_owned(),
            });
        }
        addr[index] = value;
    }

    Ok(addr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_mac_matches_golden_fixture() {
        let fixture = dae_golden::load_json("config/parse/basic.json").unwrap();

        for case in fixture["macs"].as_array().unwrap() {
            let input = case["input"].as_str().unwrap();
            let got = parse_mac(input);
            assert_eq!(got.is_ok(), case["ok"].as_bool().unwrap(), "{input}");
            if let Ok(addr) = got {
                assert_eq!(hex_encode(&addr), case["want_hex"].as_str().unwrap());
            } else {
                assert_eq!(
                    got.unwrap_err().to_string(),
                    case["error"].as_str().unwrap()
                );
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
