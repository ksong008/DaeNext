use aes::cipher::{Block, BlockEncrypt, KeyInit};
use aes::{Aes128, Aes192, Aes256};
use md5::{Digest, Md5};

use dae_outbound_core::error::OutboundError;

use super::ShadowsocksMetadata;

const AES_128_CFB_KEY_LEN: usize = 16;
const AES_192_CFB_KEY_LEN: usize = 24;
const AES_256_CFB_KEY_LEN: usize = 32;
const AES_128_CFB_IV_LEN: usize = 16;

pub struct ShadowsocksRStreamEncoder {
    cipher: AesCfbEncryptor,
    iv: [u8; AES_128_CFB_IV_LEN],
    iv_written: bool,
}
pub struct ShadowsocksRStreamDecoder {
    cipher_name: String,
    key: Vec<u8>,
    cipher: Option<AesCfbDecryptor>,
    iv_prefix: Vec<u8>,
}

impl ShadowsocksRStreamEncoder {
    pub fn new(
        cipher: &str,
        password: &str,
        iv: [u8; AES_128_CFB_IV_LEN],
    ) -> Result<Self, OutboundError> {
        let spec = stream_cipher_spec(cipher)?;
        let key = evp_bytes_to_key(password.as_bytes(), spec.key_len);
        Ok(Self {
            cipher: AesCfbEncryptor::new(&spec.name, &key, iv)?,
            iv,
            iv_written: false,
        })
    }

    pub fn encode(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, OutboundError> {
        let mut out = Vec::with_capacity(plaintext.len() + AES_128_CFB_IV_LEN);
        if !self.iv_written {
            out.extend_from_slice(&self.iv);
            self.iv_written = true;
        }
        out.extend_from_slice(&self.cipher.apply(plaintext)?);
        Ok(out)
    }

    pub fn encode_payload_in_place(&mut self, payload: &mut [u8]) -> Result<(), OutboundError> {
        if !self.iv_written {
            return Err(OutboundError::BadShadowsocks(
                "SSR in-place stream payload requires the IV prefix to be written first".to_owned(),
            ));
        }
        self.cipher.apply_in_place(payload)
    }
}

impl ShadowsocksRStreamDecoder {
    pub fn new(cipher: &str, password: &str) -> Result<Self, OutboundError> {
        let spec = stream_cipher_spec(cipher)?;
        Ok(Self {
            cipher_name: spec.name,
            key: evp_bytes_to_key(password.as_bytes(), spec.key_len),
            cipher: None,
            iv_prefix: Vec::with_capacity(AES_128_CFB_IV_LEN),
        })
    }

    pub fn decode(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, OutboundError> {
        let mut plain = ciphertext.to_vec();
        let offset = self.decode_in_place_offset(&mut plain)?;
        plain.drain(..offset);
        Ok(plain)
    }

    pub fn decode_in_place<'a>(
        &mut self,
        ciphertext: &'a mut [u8],
    ) -> Result<&'a [u8], OutboundError> {
        let offset = self.decode_in_place_offset(ciphertext)?;
        Ok(&ciphertext[offset..])
    }

    fn decode_in_place_offset(&mut self, ciphertext: &mut [u8]) -> Result<usize, OutboundError> {
        if ciphertext.is_empty() {
            return Ok(0);
        }
        let mut offset = 0;
        if self.cipher.is_none() {
            let need = AES_128_CFB_IV_LEN - self.iv_prefix.len();
            let take = need.min(ciphertext.len());
            self.iv_prefix.extend_from_slice(&ciphertext[..take]);
            offset += take;
            if self.iv_prefix.len() < AES_128_CFB_IV_LEN {
                return Ok(ciphertext.len());
            }
            let mut iv = [0_u8; AES_128_CFB_IV_LEN];
            iv.copy_from_slice(&self.iv_prefix);
            self.cipher = Some(AesCfbDecryptor::new(&self.cipher_name, &self.key, iv)?);
        }
        self.cipher
            .as_mut()
            .expect("SSR stream decoder initialized")
            .apply_in_place(&mut ciphertext[offset..])?;
        Ok(offset)
    }
}

pub fn shadowsocksr_http_simple_origin_request(
    cipher: &str,
    password: &str,
    target: &str,
    payload: &[u8],
    obfs_host: &str,
    obfs_port: u16,
    client_iv: [u8; AES_128_CFB_IV_LEN],
) -> Result<(Vec<u8>, ShadowsocksRStreamEncoder), OutboundError> {
    let target_metadata = ShadowsocksMetadata::parse(target)?;
    let target_bytes = target_metadata.encode()?;
    let mut protocol_payload = target_bytes;
    protocol_payload.extend_from_slice(payload);
    let mut encoder = ShadowsocksRStreamEncoder::new(cipher, password, client_iv)?;
    let stream_payload = encoder.encode(&protocol_payload)?;
    Ok((
        http_simple_obfs_request(obfs_host, obfs_port, &stream_payload),
        encoder,
    ))
}

pub fn shadowsocksr_stream_cipher_supported(cipher: &str) -> bool {
    stream_cipher_spec(cipher).is_ok()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShadowsocksRStreamCipherSpec {
    pub cipher: &'static str,
    pub key_len: usize,
}

pub const SHADOWSOCKSR_STREAM_CIPHER_SPECS: &[ShadowsocksRStreamCipherSpec] = &[
    ShadowsocksRStreamCipherSpec {
        cipher: "aes-128-cfb",
        key_len: AES_128_CFB_KEY_LEN,
    },
    ShadowsocksRStreamCipherSpec {
        cipher: "aes-192-cfb",
        key_len: AES_192_CFB_KEY_LEN,
    },
    ShadowsocksRStreamCipherSpec {
        cipher: "aes-256-cfb",
        key_len: AES_256_CFB_KEY_LEN,
    },
];

pub fn shadowsocksr_stream_cipher_specs() -> &'static [ShadowsocksRStreamCipherSpec] {
    SHADOWSOCKSR_STREAM_CIPHER_SPECS
}

fn stream_cipher_spec(cipher: &str) -> Result<StreamCipherSpec, OutboundError> {
    shadowsocksr_stream_cipher_specs()
        .iter()
        .copied()
        .find(|spec| spec.cipher == cipher)
        .map(|spec| StreamCipherSpec {
            name: spec.cipher.to_owned(),
            key_len: spec.key_len,
        })
        .ok_or_else(|| {
            OutboundError::BadShadowsocks(format!(
                "SSR stream executor currently supports AES CFB ciphers only, got {cipher}"
            ))
        })
}

struct StreamCipherSpec {
    name: String,
    key_len: usize,
}

fn http_simple_obfs_request(obfs_host: &str, obfs_port: u16, stream_payload: &[u8]) -> Vec<u8> {
    let head_len = stream_payload.len().min(64).max(1);
    let encoded = percent_encode(&stream_payload[..head_len]);
    let body = &stream_payload[head_len..];
    let mut request = format!(
        "GET /{encoded} HTTP/1.1\r\nHost: {obfs_host}:{obfs_port}\r\nUser-Agent: Mozilla/5.0\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.8\r\nAccept-Encoding: gzip, deflate\r\nDNT: 1\r\nConnection: keep-alive\r\n\r\n"
    )
    .into_bytes();
    request.extend_from_slice(body);
    request
}

#[derive(Clone)]
struct AesCfbEncryptor {
    cipher: AesCfbBlockCipher,
    feedback: [u8; AES_128_CFB_IV_LEN],
    block: [u8; AES_128_CFB_IV_LEN],
    offset: usize,
}

#[derive(Clone)]
struct AesCfbDecryptor {
    cipher: AesCfbBlockCipher,
    feedback: [u8; AES_128_CFB_IV_LEN],
    block: [u8; AES_128_CFB_IV_LEN],
    offset: usize,
}

impl AesCfbEncryptor {
    fn new(cipher: &str, key: &[u8], iv: [u8; AES_128_CFB_IV_LEN]) -> Result<Self, OutboundError> {
        Ok(Self {
            cipher: AesCfbBlockCipher::new(cipher, key)?,
            feedback: iv,
            block: [0; AES_128_CFB_IV_LEN],
            offset: AES_128_CFB_IV_LEN,
        })
    }

    fn apply(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, OutboundError> {
        let mut out = plaintext.to_vec();
        self.apply_in_place(&mut out)?;
        Ok(out)
    }

    fn apply_in_place(&mut self, plaintext: &mut [u8]) -> Result<(), OutboundError> {
        for byte in plaintext {
            if self.offset == AES_128_CFB_IV_LEN {
                self.block = encrypted_feedback(&self.cipher, &self.feedback);
                self.offset = 0;
            }
            let encrypted = *byte ^ self.block[self.offset];
            self.feedback[self.offset] = encrypted;
            self.offset += 1;
            *byte = encrypted;
        }
        Ok(())
    }
}

impl AesCfbDecryptor {
    fn new(cipher: &str, key: &[u8], iv: [u8; AES_128_CFB_IV_LEN]) -> Result<Self, OutboundError> {
        Ok(Self {
            cipher: AesCfbBlockCipher::new(cipher, key)?,
            feedback: iv,
            block: [0; AES_128_CFB_IV_LEN],
            offset: AES_128_CFB_IV_LEN,
        })
    }

    fn apply_in_place(&mut self, ciphertext: &mut [u8]) -> Result<(), OutboundError> {
        for byte in ciphertext {
            if self.offset == AES_128_CFB_IV_LEN {
                self.block = encrypted_feedback(&self.cipher, &self.feedback);
                self.offset = 0;
            }
            let encrypted = *byte;
            let decrypted = encrypted ^ self.block[self.offset];
            self.feedback[self.offset] = encrypted;
            self.offset += 1;
            *byte = decrypted;
        }
        Ok(())
    }
}

#[derive(Clone)]
enum AesCfbBlockCipher {
    Aes128(Aes128),
    Aes192(Aes192),
    Aes256(Aes256),
}

impl AesCfbBlockCipher {
    fn new(cipher: &str, key: &[u8]) -> Result<Self, OutboundError> {
        match cipher {
            "aes-128-cfb" => Ok(Self::Aes128(
                Aes128::new_from_slice(key)
                    .map_err(|err| OutboundError::BadShadowsocks(err.to_string()))?,
            )),
            "aes-192-cfb" => Ok(Self::Aes192(
                Aes192::new_from_slice(key)
                    .map_err(|err| OutboundError::BadShadowsocks(err.to_string()))?,
            )),
            "aes-256-cfb" => Ok(Self::Aes256(
                Aes256::new_from_slice(key)
                    .map_err(|err| OutboundError::BadShadowsocks(err.to_string()))?,
            )),
            other => Err(OutboundError::BadShadowsocks(format!(
                "unsupported SSR AES CFB cipher: {other}"
            ))),
        }
    }

    fn encrypt_feedback(&self, feedback: &[u8; AES_128_CFB_IV_LEN]) -> [u8; AES_128_CFB_IV_LEN] {
        match self {
            Self::Aes128(cipher) => {
                let mut block = Block::<Aes128>::clone_from_slice(feedback);
                cipher.encrypt_block(&mut block);
                block.into()
            }
            Self::Aes192(cipher) => {
                let mut block = Block::<Aes192>::clone_from_slice(feedback);
                cipher.encrypt_block(&mut block);
                block.into()
            }
            Self::Aes256(cipher) => {
                let mut block = Block::<Aes256>::clone_from_slice(feedback);
                cipher.encrypt_block(&mut block);
                block.into()
            }
        }
    }
}

fn encrypted_feedback(
    cipher: &AesCfbBlockCipher,
    feedback: &[u8; AES_128_CFB_IV_LEN],
) -> [u8; AES_128_CFB_IV_LEN] {
    cipher.encrypt_feedback(feedback)
}

fn evp_bytes_to_key(password: &[u8], key_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(key_len);
    let mut previous = Vec::new();
    while out.len() < key_len {
        let mut hasher = Md5::new();
        if !previous.is_empty() {
            hasher.update(&previous);
        }
        hasher.update(password);
        previous = hasher.finalize().to_vec();
        out.extend_from_slice(&previous);
    }
    out.truncate(key_len);
    out
}

fn percent_encode(input: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(input.len() * 3);
    for byte in input {
        out.push('%');
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_simple_places_only_short_prefix_in_path() {
        let payload = (0_u8..=127).collect::<Vec<_>>();
        let request = http_simple_obfs_request("front.invalid", 443, &payload);
        let header_end = request
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .expect("HTTP header terminator")
            + 4;
        let header = std::str::from_utf8(&request[..header_end]).expect("HTTP header UTF-8");
        let path = header
            .lines()
            .next()
            .expect("request line")
            .split_whitespace()
            .nth(1)
            .expect("request path");
        assert_eq!(path.len(), 1 + 64 * 3);
        assert_eq!(&request[header_end..], &payload[64..]);
    }

    #[test]
    fn in_place_stream_cipher_matches_allocating_wire_for_every_cipher() {
        let iv = [0x5a; AES_128_CFB_IV_LEN];
        for spec in shadowsocksr_stream_cipher_specs() {
            let mut allocating = ShadowsocksRStreamEncoder::new(spec.cipher, "secret", iv).unwrap();
            let mut in_place = ShadowsocksRStreamEncoder::new(spec.cipher, "secret", iv).unwrap();
            assert_eq!(
                allocating.encode(b"initial").unwrap(),
                in_place.encode(b"initial").unwrap(),
                "{}",
                spec.cipher
            );

            for payload_len in [1, 4097, 16 * 1024] {
                let payload = vec![payload_len as u8; payload_len];
                let expected = allocating.encode(&payload).unwrap();
                let mut actual = payload;
                in_place.encode_payload_in_place(&mut actual).unwrap();
                assert_eq!(actual, expected, "{}", spec.cipher);
            }

            let mut sender = ShadowsocksRStreamEncoder::new(spec.cipher, "secret", iv).unwrap();
            let wire = sender.encode(b"response payload").unwrap();
            let mut allocating_decoder =
                ShadowsocksRStreamDecoder::new(spec.cipher, "secret").unwrap();
            let expected = allocating_decoder.decode(&wire).unwrap();
            let mut in_place_decoder =
                ShadowsocksRStreamDecoder::new(spec.cipher, "secret").unwrap();
            let mut actual = wire;
            let actual = in_place_decoder.decode_in_place(&mut actual).unwrap();
            assert_eq!(actual, expected, "{}", spec.cipher);
        }
    }
}
