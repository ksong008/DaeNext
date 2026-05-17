use std::fmt;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParsePortRangeError {
    BadPortRange { input: String },
    InvalidDecimal { field: String },
    ExceedsUint16 { port: i64 },
}

impl fmt::Display for ParsePortRangeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadPortRange { input } => write!(f, "bad port range: {input}"),
            Self::InvalidDecimal { field } => {
                write!(f, "strconv.Atoi: parsing \"{field}\": invalid syntax")
            }
            Self::ExceedsUint16 { port } => write!(f, "port {port} exceeds uint16 range"),
        }
    }
}

impl std::error::Error for ParsePortRangeError {}

pub fn parse_port_range(input: &str) -> Result<[u16; 2], ParsePortRangeError> {
    let fields: Vec<_> = input.splitn(2, '-').collect();
    let mut range = [0_u16; 2];

    for (index, field) in fields.iter().enumerate() {
        if field.is_empty() {
            return Err(ParsePortRangeError::BadPortRange {
                input: input.to_owned(),
            });
        }

        let port = field
            .parse::<i64>()
            .map_err(|_| ParsePortRangeError::InvalidDecimal {
                field: (*field).to_owned(),
            })?;
        if !(0..=0xffff).contains(&port) {
            return Err(ParsePortRangeError::ExceedsUint16 { port });
        }
        range[index] = port as u16;
    }

    if fields.len() == 1 {
        range[1] = range[0];
    }

    Ok(range)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_port_range_matches_golden_fixture() {
        let fixture = dae_golden::load_json("config/parse/basic.json").unwrap();

        for case in fixture["port_ranges"].as_array().unwrap() {
            let input = case["input"].as_str().unwrap();
            let got = parse_port_range(input);
            assert_eq!(got.is_ok(), case["ok"].as_bool().unwrap(), "{input}");
            if let Ok(range) = got {
                let want = case["want"].as_array().unwrap();
                assert_eq!(range[0], want[0].as_u64().unwrap() as u16);
                assert_eq!(range[1], want[1].as_u64().unwrap() as u16);
            } else {
                assert_eq!(
                    got.unwrap_err().to_string(),
                    case["error"].as_str().unwrap()
                );
            }
        }
    }
}
