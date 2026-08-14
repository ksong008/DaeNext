use std::fmt;
use std::mem::MaybeUninit;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};

pub const MLDSA65_PUBLIC_KEY_BYTES: usize = 1952;
pub const MLDSA65_SIGNATURE_BYTES: usize = 3309;
pub const MLDSA65_PUBLIC_KEY_BASE64_BYTES: usize = 2603;

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct Mldsa65VerifyKey {
    bytes: Box<[u8; MLDSA65_PUBLIC_KEY_BYTES]>,
    canonical_base64: String,
    sha256: [u8; 32],
}

impl Mldsa65VerifyKey {
    pub fn parse_base64(input: &str) -> Result<Self, Mldsa65VerifyKeyError> {
        let input = input.trim();
        if input.is_empty() {
            return Err(Mldsa65VerifyKeyError::Empty);
        }
        if input.len() != MLDSA65_PUBLIC_KEY_BASE64_BYTES {
            return Err(Mldsa65VerifyKeyError::InvalidEncodedLength {
                actual: input.len(),
                expected: MLDSA65_PUBLIC_KEY_BASE64_BYTES,
            });
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(input)
            .map_err(|err| Mldsa65VerifyKeyError::InvalidBase64(err.to_string()))?;
        Self::from_bytes(bytes)
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, Mldsa65VerifyKeyError> {
        let bytes: Box<[u8; MLDSA65_PUBLIC_KEY_BYTES]> = bytes
            .into_boxed_slice()
            .try_into()
            .map_err(
                |bytes: Box<[u8]>| Mldsa65VerifyKeyError::InvalidDecodedLength {
                    actual: bytes.len(),
                    expected: MLDSA65_PUBLIC_KEY_BYTES,
                },
            )?;
        validate_mldsa65_public_key(&bytes)?;
        let sha256 = Sha256::digest(bytes.as_slice()).into();
        let canonical_base64 = URL_SAFE_NO_PAD.encode(bytes.as_slice());
        Ok(Self {
            bytes,
            canonical_base64,
            sha256,
        })
    }

    pub fn bytes(&self) -> &[u8; MLDSA65_PUBLIC_KEY_BYTES] {
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

    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        if signature.len() != MLDSA65_SIGNATURE_BYTES {
            return false;
        }
        let Some(public_key) = parse_mldsa65_public_key(&self.bytes) else {
            return false;
        };
        unsafe {
            boring_sys::MLDSA65_verify(
                &public_key,
                signature.as_ptr(),
                signature.len(),
                message.as_ptr(),
                message.len(),
                std::ptr::null(),
                0,
            ) == 1
        }
    }
}

impl fmt::Debug for Mldsa65VerifyKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Mldsa65VerifyKey")
            .field("length", &self.bytes.len())
            .field("sha256", &self.sha256_hex())
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Mldsa65VerifyKeyError {
    Empty,
    InvalidEncodedLength { actual: usize, expected: usize },
    InvalidDecodedLength { actual: usize, expected: usize },
    InvalidBase64(String),
    InvalidPublicKey,
}

impl fmt::Display for Mldsa65VerifyKeyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("ML-DSA-65 verify key is empty"),
            Self::InvalidEncodedLength { actual, expected } => write!(
                formatter,
                "ML-DSA-65 verify key RawURL Base64 length is {actual}, expected {expected}"
            ),
            Self::InvalidDecodedLength { actual, expected } => write!(
                formatter,
                "ML-DSA-65 verify key decoded length is {actual}, expected {expected}"
            ),
            Self::InvalidBase64(error) => {
                write!(
                    formatter,
                    "ML-DSA-65 verify key is not RawURL Base64: {error}"
                )
            }
            Self::InvalidPublicKey => {
                formatter.write_str("ML-DSA-65 verify key is not a valid encoded public key")
            }
        }
    }
}

impl std::error::Error for Mldsa65VerifyKeyError {}

pub fn parse_optional_mldsa65_verify_key(
    input: &str,
) -> Result<Option<Mldsa65VerifyKey>, Mldsa65VerifyKeyError> {
    let input = input.trim();
    if input.is_empty() {
        Ok(None)
    } else {
        Mldsa65VerifyKey::parse_base64(input).map(Some)
    }
}

fn validate_mldsa65_public_key(
    bytes: &[u8; MLDSA65_PUBLIC_KEY_BYTES],
) -> Result<(), Mldsa65VerifyKeyError> {
    parse_mldsa65_public_key(bytes)
        .map(drop)
        .ok_or(Mldsa65VerifyKeyError::InvalidPublicKey)
}

fn parse_mldsa65_public_key(
    bytes: &[u8; MLDSA65_PUBLIC_KEY_BYTES],
) -> Option<boring_sys::MLDSA65_public_key> {
    let mut public_key = MaybeUninit::<boring_sys::MLDSA65_public_key>::uninit();
    let mut input = boring_sys::CBS {
        data: bytes.as_ptr(),
        len: bytes.len(),
    };
    unsafe {
        if boring_sys::MLDSA65_parse_public_key(public_key.as_mut_ptr(), &mut input) != 1
            || input.len != 0
        {
            return None;
        }
        Some(public_key.assume_init())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn generated_key() -> (Mldsa65VerifyKey, boring_sys::MLDSA65_private_key) {
        let mut encoded = vec![0_u8; MLDSA65_PUBLIC_KEY_BYTES];
        let mut seed = [0_u8; 32];
        let mut private_key = MaybeUninit::<boring_sys::MLDSA65_private_key>::uninit();
        let generated = unsafe {
            boring_sys::MLDSA65_generate_key(
                encoded.as_mut_ptr(),
                seed.as_mut_ptr(),
                private_key.as_mut_ptr(),
            )
        };
        assert_eq!(generated, 1);
        (Mldsa65VerifyKey::from_bytes(encoded).unwrap(), unsafe {
            private_key.assume_init()
        })
    }

    #[test]
    fn parses_canonical_raw_url_base64_and_redacts_debug() {
        let (key, _) = generated_key();
        let encoded = key.canonical_base64().to_owned();
        let parsed = Mldsa65VerifyKey::parse_base64(&encoded).unwrap();

        assert_eq!(parsed, key);
        assert_eq!(encoded.len(), MLDSA65_PUBLIC_KEY_BASE64_BYTES);
        assert!(!encoded.contains('='));
        assert!(!format!("{parsed:?}").contains(&encoded));
    }

    #[test]
    fn rejects_standard_base64_padding_and_wrong_lengths() {
        assert!(matches!(
            Mldsa65VerifyKey::parse_base64(&"A".repeat(MLDSA65_PUBLIC_KEY_BASE64_BYTES - 1)),
            Err(Mldsa65VerifyKeyError::InvalidEncodedLength { .. })
        ));
        assert!(matches!(
            Mldsa65VerifyKey::parse_base64(&format!(
                "{}=",
                "A".repeat(MLDSA65_PUBLIC_KEY_BASE64_BYTES - 1)
            )),
            Err(Mldsa65VerifyKeyError::InvalidBase64(_))
        ));
    }

    #[test]
    fn verifies_mldsa65_with_empty_context() {
        let (key, private_key) = generated_key();
        let message = b"Reality transcript authentication";
        let mut signature = vec![0_u8; MLDSA65_SIGNATURE_BYTES];
        let signed = unsafe {
            boring_sys::MLDSA65_sign(
                signature.as_mut_ptr(),
                &private_key,
                message.as_ptr(),
                message.len(),
                std::ptr::null(),
                0,
            )
        };
        assert_eq!(signed, 1);
        assert!(key.verify(message, &signature));

        signature[0] ^= 1;
        assert!(!key.verify(message, &signature));
    }
}
