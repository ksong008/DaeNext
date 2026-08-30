use std::fmt;

use base64::{Engine, engine::general_purpose::STANDARD};
use boring::ssl::{Ssl, SslContextBuilder, SslMethod};
use sha2::{Digest, Sha256};

pub const ECH_CONFIG_LIST_MAX_BYTES: usize = u16::MAX as usize + 2;
pub const ECH_CONFIG_LIST_MAX_BASE64_BYTES: usize = ECH_CONFIG_LIST_MAX_BYTES.div_ceil(3) * 4;

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct EchConfigList {
    bytes: Vec<u8>,
    canonical_base64: String,
    sha256: [u8; 32],
}

impl EchConfigList {
    pub fn parse_base64(input: &str) -> Result<Self, EchConfigListError> {
        let input = input.trim();
        if input.is_empty() {
            return Err(EchConfigListError::Empty);
        }
        if input.len() > ECH_CONFIG_LIST_MAX_BASE64_BYTES {
            return Err(EchConfigListError::EncodedTooLarge {
                actual: input.len(),
                maximum: ECH_CONFIG_LIST_MAX_BASE64_BYTES,
            });
        }
        let bytes = STANDARD
            .decode(input)
            .map_err(|err| EchConfigListError::InvalidBase64(err.to_string()))?;
        Self::from_bytes(bytes)
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, EchConfigListError> {
        if bytes.is_empty() {
            return Err(EchConfigListError::Empty);
        }
        if bytes.len() > ECH_CONFIG_LIST_MAX_BYTES {
            return Err(EchConfigListError::DecodedTooLarge {
                actual: bytes.len(),
                maximum: ECH_CONFIG_LIST_MAX_BYTES,
            });
        }
        validate_boringssl_ech_config_list(&bytes)?;
        let sha256 = Sha256::digest(&bytes).into();
        let canonical_base64 = STANDARD.encode(&bytes);
        Ok(Self {
            bytes,
            canonical_base64,
            sha256,
        })
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn canonical_base64(&self) -> &str {
        &self.canonical_base64
    }

    pub const fn sha256(&self) -> &[u8; 32] {
        &self.sha256
    }

    pub fn sha256_hex(&self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(self.sha256.len() * 2);
        for byte in self.sha256 {
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 0x0f) as usize] as char);
        }
        out
    }
}

fn validate_boringssl_ech_config_list(bytes: &[u8]) -> Result<(), EchConfigListError> {
    let context = SslContextBuilder::new(SslMethod::tls())
        .map_err(|err| EchConfigListError::InvalidConfigList(err.to_string()))?
        .build();
    let mut ssl =
        Ssl::new(&context).map_err(|err| EchConfigListError::InvalidConfigList(err.to_string()))?;
    ssl.set_ech_config_list(bytes)
        .map_err(|err| EchConfigListError::InvalidConfigList(err.to_string()))
}

impl fmt::Debug for EchConfigList {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EchConfigList")
            .field("length", &self.bytes.len())
            .field("sha256", &self.sha256_hex())
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EchConfigListError {
    Empty,
    EncodedTooLarge { actual: usize, maximum: usize },
    DecodedTooLarge { actual: usize, maximum: usize },
    InvalidBase64(String),
    InvalidConfigList(String),
}

impl fmt::Display for EchConfigListError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("ECHConfigList is empty"),
            Self::EncodedTooLarge { actual, maximum } => write!(
                formatter,
                "ECHConfigList base64 length {actual} exceeds limit {maximum}"
            ),
            Self::DecodedTooLarge { actual, maximum } => write!(
                formatter,
                "ECHConfigList decoded length {actual} exceeds limit {maximum}"
            ),
            Self::InvalidBase64(error) => {
                write!(formatter, "ECHConfigList is not standard Base64: {error}")
            }
            Self::InvalidConfigList(error) => {
                write!(
                    formatter,
                    "ECHConfigList is not a supported TLS config list: {error}"
                )
            }
        }
    }
}

impl std::error::Error for EchConfigListError {}

pub fn parse_optional_ech_config_list(
    input: &str,
) -> Result<Option<EchConfigList>, EchConfigListError> {
    let input = input.trim();
    if input.is_empty() {
        Ok(None)
    } else {
        EchConfigList::parse_base64(input).map(Some)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BORINGSSL_ECH_CONFIG_LIST_BASE64: &str =
        "AD7+DQA6AAAgACC7Lynj4wV+BBnVL8X0QRh3b422HOpP33YHm5NgbFpiSAAIAAEAAQABAAMAB2VjaC5jb20AAA==";

    #[test]
    fn parses_and_canonicalizes_official_ech_config_list_bytes() {
        let parsed = EchConfigList::parse_base64(BORINGSSL_ECH_CONFIG_LIST_BASE64).unwrap();

        assert_eq!(parsed.bytes().len(), 64);
        assert_eq!(parsed.canonical_base64(), BORINGSSL_ECH_CONFIG_LIST_BASE64);
        assert_eq!(
            parsed.sha256_hex(),
            "9af1ab5180107aaa5ea758daf3435f20e4815af6889436ad6d884ea139b0c74f"
        );
        assert!(!format!("{parsed:?}").contains(BORINGSSL_ECH_CONFIG_LIST_BASE64));
    }

    #[test]
    fn rejects_non_standard_base64_and_malformed_lists() {
        assert!(matches!(
            EchConfigList::parse_base64("AA-_"),
            Err(EchConfigListError::InvalidBase64(_))
        ));
        assert!(matches!(
            EchConfigList::parse_base64("AQIDBA=="),
            Err(EchConfigListError::InvalidConfigList(_))
        ));
    }

    #[test]
    fn enforces_encoded_and_decoded_size_limits_before_tls_use() {
        assert!(matches!(
            EchConfigList::parse_base64(&"A".repeat(ECH_CONFIG_LIST_MAX_BASE64_BYTES + 1)),
            Err(EchConfigListError::EncodedTooLarge { .. })
        ));
        assert!(matches!(
            EchConfigList::from_bytes(vec![0; ECH_CONFIG_LIST_MAX_BYTES + 1]),
            Err(EchConfigListError::DecodedTooLarge { .. })
        ));
    }

    #[test]
    fn optional_parser_treats_only_trimmed_empty_input_as_absent() {
        assert_eq!(parse_optional_ech_config_list("  \n\t ").unwrap(), None);
        assert!(parse_optional_ech_config_list("not base64").is_err());
    }
}
