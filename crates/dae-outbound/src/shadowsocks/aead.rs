use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use aes_gcm::aead::{Aead, AeadInPlace, KeyInit};
use aes_gcm::aes::cipher::generic_array::GenericArray;
use boring::aead::{AeadCtx, Algorithm};
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use md5::{Digest, Md5};
use sha1::Sha1;
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::error::OutboundError;
use crate::socks5::Socks5Address;

use super::cipher::{CipherFamily, classify_cipher};
use super::metadata::ShadowsocksMetadata;

pub const SUBKEY_INFO: &[u8] = b"ss-subkey";
pub const TAG_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;
pub const MAX_CHUNK_LEN: usize = 0x3fff;
pub const SHADOWSOCKS_AEAD_TCP_UPLOAD_BUFFER_SIZE: usize = 2 + TAG_LEN + MAX_CHUNK_LEN + TAG_LEN;
pub const SHADOWSOCKS_AEAD_TCP_DOWNLOAD_BUFFER_SIZE: usize = MAX_CHUNK_LEN + TAG_LEN;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AeadCipherSpec {
    pub cipher: &'static str,
    pub aliases: &'static [&'static str],
    pub key_len: usize,
    pub salt_len: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShadowsocksAeadTcpExchangeReport {
    pub server: String,
    pub target: String,
    pub cipher: String,
    pub client_salt_len: usize,
    pub server_salt_len: usize,
    pub payload_len: usize,
    pub echoed_payload: Vec<u8>,
    pub true_dataplane: bool,
}

pub const AEAD_CIPHER_SPECS: &[AeadCipherSpec] = &[
    AeadCipherSpec {
        cipher: "aes-128-gcm",
        aliases: &[],
        key_len: 16,
        salt_len: 16,
    },
    AeadCipherSpec {
        cipher: "aes-256-gcm",
        aliases: &[],
        key_len: 32,
        salt_len: 32,
    },
    AeadCipherSpec {
        cipher: "chacha20-ietf-poly1305",
        aliases: &["chacha20-poly1305"],
        key_len: 32,
        salt_len: 32,
    },
];

pub fn aead_cipher_specs() -> &'static [AeadCipherSpec] {
    AEAD_CIPHER_SPECS
}

pub fn cipher_spec(cipher: &str) -> Result<AeadCipherSpec, OutboundError> {
    let info = classify_cipher(cipher)?;
    if info.family != CipherFamily::Aead {
        return Err(OutboundError::BadShadowsocks(format!(
            "cipher family is not resident Shadowsocks AEAD stream cipher: {}",
            info.cipher
        )));
    }
    aead_cipher_specs()
        .iter()
        .copied()
        .find(|spec| spec.cipher == info.cipher || spec.aliases.contains(&info.cipher.as_str()))
        .ok_or_else(|| {
            OutboundError::BadShadowsocks(format!("unsupported AEAD cipher: {}", info.cipher))
        })
}

pub fn tcp_exchange(
    server: &str,
    cipher: &str,
    password: &str,
    target: &str,
    payload: &[u8],
    salts: AeadTcpSalts<'_>,
    timeout: Duration,
) -> Result<ShadowsocksAeadTcpExchangeReport, OutboundError> {
    let mut stream =
        TcpStream::connect(server).map_err(|err| OutboundError::BadShadowsocks(err.to_string()))?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|err| OutboundError::BadShadowsocks(err.to_string()))?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|err| OutboundError::BadShadowsocks(err.to_string()))?;

    tcp_exchange_over_stream(
        &mut stream,
        server,
        cipher,
        password,
        target,
        payload,
        salts,
    )
}

pub fn tcp_exchange_over_stream(
    stream: &mut TcpStream,
    server: &str,
    cipher: &str,
    password: &str,
    target: &str,
    payload: &[u8],
    salts: AeadTcpSalts<'_>,
) -> Result<ShadowsocksAeadTcpExchangeReport, OutboundError> {
    let spec = cipher_spec(cipher)?;
    validate_salt_len("client", salts.client, spec.salt_len)?;
    validate_salt_len("server", salts.server, spec.salt_len)?;

    let target_metadata = ShadowsocksMetadata::parse(target)?;
    let mut request_payload = target_metadata.encode()?;
    request_payload.extend_from_slice(payload);
    let request = encode_client_initial(cipher, password, salts.client, &request_payload)?;

    stream
        .write_all(&request)
        .map_err(|err| OutboundError::BadShadowsocks(err.to_string()))?;
    let mut server_salt = vec![0_u8; spec.salt_len];
    stream
        .read_exact(&mut server_salt)
        .map_err(|err| OutboundError::BadShadowsocks(err.to_string()))?;
    let mut decoder = AeadStreamCodec::new(cipher, password, &server_salt)?;
    let echoed_payload = read_encrypted_chunk(stream, &mut decoder)?;

    Ok(ShadowsocksAeadTcpExchangeReport {
        server: server.to_owned(),
        target: target_metadata.authority(),
        cipher: spec.cipher.to_owned(),
        client_salt_len: salts.client.len(),
        server_salt_len: server_salt.len(),
        payload_len: payload.len(),
        echoed_payload,
        true_dataplane: true,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AeadTcpSalts<'a> {
    pub client: &'a [u8],
    pub server: &'a [u8],
}

pub fn encode_client_initial(
    cipher: &str,
    password: &str,
    salt: &[u8],
    target_and_payload: &[u8],
) -> Result<Vec<u8>, OutboundError> {
    let spec = cipher_spec(cipher)?;
    validate_salt_len("client", salt, spec.salt_len)?;
    let mut codec = AeadStreamCodec::new(cipher, password, salt)?;
    let mut out = Vec::with_capacity(salt.len() + target_and_payload.len() + 2 + TAG_LEN * 2);
    out.extend_from_slice(salt);
    out.extend_from_slice(&codec.encrypt_chunk(target_and_payload)?);
    Ok(out)
}

pub fn decode_client_initial(
    cipher: &str,
    password: &str,
    input: &[u8],
) -> Result<(Socks5Address, Vec<u8>), OutboundError> {
    let spec = cipher_spec(cipher)?;
    if input.len() < spec.salt_len {
        return Err(OutboundError::BadShadowsocks(
            "client initial frame missing salt".to_owned(),
        ));
    }
    let (salt, encrypted) = input.split_at(spec.salt_len);
    let mut codec = AeadStreamCodec::new(cipher, password, salt)?;
    let plain = codec.decrypt_chunk(encrypted)?;
    let (target, consumed) = Socks5Address::decode(&plain)?;
    Ok((target, plain[consumed..].to_vec()))
}

pub fn read_client_initial_from_stream(
    stream: &mut TcpStream,
    cipher: &str,
    password: &str,
) -> Result<(Socks5Address, Vec<u8>), OutboundError> {
    let spec = cipher_spec(cipher)?;
    let mut salt = vec![0_u8; spec.salt_len];
    stream
        .read_exact(&mut salt)
        .map_err(|err| OutboundError::BadShadowsocks(err.to_string()))?;
    let mut decoder = AeadStreamCodec::new(cipher, password, &salt)?;
    let plain = read_encrypted_chunk(stream, &mut decoder)?;
    let (target, consumed) = Socks5Address::decode(&plain)?;
    Ok((target, plain[consumed..].to_vec()))
}

pub fn read_encrypted_chunk_from_stream<S>(
    stream: &mut S,
    decoder: &mut AeadStreamCodec,
) -> Result<Vec<u8>, OutboundError>
where
    S: Read,
{
    read_encrypted_chunk(stream, decoder)
}

pub async fn read_encrypted_chunk_from_async_stream<S>(
    stream: &mut S,
    decoder: &mut AeadStreamCodec,
) -> Result<Vec<u8>, OutboundError>
where
    S: AsyncRead + Unpin,
{
    let mut encrypted_len = [0_u8; 2 + TAG_LEN];
    stream
        .read_exact(&mut encrypted_len)
        .await
        .map_err(|err| OutboundError::BadShadowsocks(err.to_string()))?;
    let len_plain = decoder.decrypt_next(&encrypted_len)?;
    if len_plain.len() != 2 {
        return Err(OutboundError::BadShadowsocks(
            "bad decrypted chunk length".to_owned(),
        ));
    }
    let payload_len = u16::from_be_bytes([len_plain[0], len_plain[1]]) as usize;
    let mut encrypted_payload = vec![0_u8; payload_len + TAG_LEN];
    stream
        .read_exact(&mut encrypted_payload)
        .await
        .map_err(|err| OutboundError::BadShadowsocks(err.to_string()))?;
    decoder.decrypt_next(&encrypted_payload)
}

pub async fn read_encrypted_chunk_in_place_from_async_stream<S>(
    stream: &mut S,
    decoder: &mut AeadStreamCodec,
    buffer: &mut [u8; SHADOWSOCKS_AEAD_TCP_DOWNLOAD_BUFFER_SIZE],
) -> Result<usize, OutboundError>
where
    S: AsyncRead + Unpin,
{
    let mut encrypted_len = [0_u8; 2 + TAG_LEN];
    stream
        .read_exact(&mut encrypted_len)
        .await
        .map_err(|err| OutboundError::BadShadowsocks(err.to_string()))?;
    let len_plain = decoder.decrypt_next_in_place(&mut encrypted_len)?;
    if len_plain != 2 {
        return Err(OutboundError::BadShadowsocks(
            "bad decrypted chunk length".to_owned(),
        ));
    }
    let payload_len = u16::from_be_bytes([encrypted_len[0], encrypted_len[1]]) as usize;
    stream
        .read_exact(&mut buffer[..payload_len + TAG_LEN])
        .await
        .map_err(|err| OutboundError::BadShadowsocks(err.to_string()))?;
    let plain_len = decoder.decrypt_next_in_place(&mut buffer[..payload_len + TAG_LEN])?;
    if plain_len != payload_len {
        return Err(OutboundError::BadShadowsocks(
            "bad decrypted chunk payload length".to_owned(),
        ));
    }
    Ok(plain_len)
}

pub fn encode_server_payload(
    cipher: &str,
    password: &str,
    salt: &[u8],
    payload: &[u8],
) -> Result<Vec<u8>, OutboundError> {
    let spec = cipher_spec(cipher)?;
    validate_salt_len("server", salt, spec.salt_len)?;
    let mut codec = AeadStreamCodec::new(cipher, password, salt)?;
    let mut out = Vec::with_capacity(salt.len() + payload.len() + 2 + TAG_LEN * 2);
    out.extend_from_slice(salt);
    out.extend_from_slice(&codec.encrypt_chunk(payload)?);
    Ok(out)
}

pub struct AeadStreamCodec {
    cipher: AeadCipher,
    nonce_counter: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShadowsocksAeadUdpPacket {
    pub target: String,
    pub payload: Vec<u8>,
    pub salt_len: usize,
    pub packet_len: usize,
}

pub fn encode_udp_packet(
    cipher: &str,
    password: &str,
    salt: &[u8],
    target: &str,
    payload: &[u8],
) -> Result<Vec<u8>, OutboundError> {
    let spec = cipher_spec(cipher)?;
    validate_salt_len("udp", salt, spec.salt_len)?;
    let target_metadata = ShadowsocksMetadata::parse(target)?;
    let mut plain = target_metadata.encode()?;
    plain.extend_from_slice(payload);
    let packet_cipher = udp_packet_cipher(cipher, password, salt)?;
    let nonce = nonce_from_counter(0);
    let encrypted = packet_cipher.encrypt(&nonce, &plain)?;
    let mut out = Vec::with_capacity(salt.len() + encrypted.len());
    out.extend_from_slice(salt);
    out.extend_from_slice(&encrypted);
    Ok(out)
}

pub fn decode_udp_packet(
    cipher: &str,
    password: &str,
    packet: &[u8],
) -> Result<ShadowsocksAeadUdpPacket, OutboundError> {
    let spec = cipher_spec(cipher)?;
    if packet.len() < spec.salt_len + TAG_LEN {
        return Err(OutboundError::BadShadowsocks(
            "udp packet missing salt or tag".to_owned(),
        ));
    }
    let (salt, encrypted) = packet.split_at(spec.salt_len);
    let packet_cipher = udp_packet_cipher(cipher, password, salt)?;
    let nonce = nonce_from_counter(0);
    let plain = packet_cipher.decrypt(&nonce, encrypted)?;
    let (target, consumed) = Socks5Address::decode(&plain)?;
    Ok(ShadowsocksAeadUdpPacket {
        target: target.authority(),
        payload: plain[consumed..].to_vec(),
        salt_len: salt.len(),
        packet_len: packet.len(),
    })
}

fn udp_packet_cipher(
    cipher: &str,
    password: &str,
    salt: &[u8],
) -> Result<AeadCipher, OutboundError> {
    let spec = cipher_spec(cipher)?;
    validate_salt_len("udp", salt, spec.salt_len)?;
    let master_key = evp_bytes_to_key(password.as_bytes(), spec.key_len);
    let subkey = hkdf_sha1_subkey(&master_key, salt, spec.key_len)?;
    AeadCipher::new(spec.cipher, &subkey)
}

impl AeadStreamCodec {
    pub fn new(cipher: &str, password: &str, salt: &[u8]) -> Result<Self, OutboundError> {
        let spec = cipher_spec(cipher)?;
        validate_salt_len("stream", salt, spec.salt_len)?;
        let master_key = evp_bytes_to_key(password.as_bytes(), spec.key_len);
        let subkey = hkdf_sha1_subkey(&master_key, salt, spec.key_len)?;
        Ok(Self {
            cipher: AeadCipher::new(spec.cipher, &subkey)?,
            nonce_counter: 0,
        })
    }

    pub fn encrypt_chunk(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, OutboundError> {
        if plaintext.len() > MAX_CHUNK_LEN {
            return Err(OutboundError::BadShadowsocks(format!(
                "chunk too large: {}",
                plaintext.len()
            )));
        }
        let mut out = Vec::with_capacity(2 + TAG_LEN + plaintext.len() + TAG_LEN);
        let len = (plaintext.len() as u16).to_be_bytes();
        let encrypted_len = self.encrypt_next(&len)?;
        out.extend_from_slice(&encrypted_len);
        let encrypted_payload = self.encrypt_next(plaintext)?;
        out.extend_from_slice(&encrypted_payload);
        Ok(out)
    }

    pub fn chunk_payload_buffer<'a>(&self, buffer: &'a mut [u8]) -> &'a mut [u8] {
        let payload_offset = 2 + TAG_LEN;
        let payload_capacity = buffer
            .len()
            .saturating_sub(payload_offset + TAG_LEN)
            .min(MAX_CHUNK_LEN);
        &mut buffer[payload_offset..payload_offset + payload_capacity]
    }

    pub fn encrypt_chunk_in_place(
        &mut self,
        buffer: &mut [u8],
        payload_len: usize,
    ) -> Result<usize, OutboundError> {
        if payload_len > MAX_CHUNK_LEN {
            return Err(OutboundError::BadShadowsocks(format!(
                "chunk too large: {payload_len}"
            )));
        }
        let payload_start = 2 + TAG_LEN;
        let payload_end = payload_start + payload_len;
        if payload_end + TAG_LEN > buffer.len() {
            return Err(OutboundError::BadShadowsocks(format!(
                "chunk length {payload_len} exceeds in-place buffer capacity"
            )));
        }
        buffer[..2].copy_from_slice(&(payload_len as u16).to_be_bytes());
        let len_tag = self.encrypt_next_in_place(&mut buffer[..2])?;
        buffer[2..2 + TAG_LEN].copy_from_slice(&len_tag);

        let payload_tag = self.encrypt_next_in_place(&mut buffer[payload_start..payload_end])?;
        buffer[payload_end..payload_end + TAG_LEN].copy_from_slice(&payload_tag);
        Ok(payload_end + TAG_LEN)
    }

    pub fn decrypt_chunk(&mut self, input: &[u8]) -> Result<Vec<u8>, OutboundError> {
        if input.len() < 2 + TAG_LEN {
            return Err(OutboundError::BadShadowsocks(
                "encrypted chunk missing length".to_owned(),
            ));
        }
        let encrypted_len_len = 2 + TAG_LEN;
        let len_plain = self.decrypt_next(&input[..encrypted_len_len])?;
        if len_plain.len() != 2 {
            return Err(OutboundError::BadShadowsocks(
                "bad decrypted chunk length".to_owned(),
            ));
        }
        let payload_len = u16::from_be_bytes([len_plain[0], len_plain[1]]) as usize;
        let payload_end = encrypted_len_len + payload_len + TAG_LEN;
        if input.len() < payload_end {
            return Err(OutboundError::BadShadowsocks(
                "encrypted chunk missing payload".to_owned(),
            ));
        }
        self.decrypt_next(&input[encrypted_len_len..payload_end])
    }

    fn encrypt_next(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, OutboundError> {
        let nonce = nonce_from_counter(self.nonce_counter);
        self.nonce_counter += 1;
        self.cipher.encrypt(&nonce, plaintext)
    }

    fn decrypt_next(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, OutboundError> {
        let nonce = nonce_from_counter(self.nonce_counter);
        self.nonce_counter += 1;
        self.cipher.decrypt(&nonce, ciphertext)
    }

    fn encrypt_next_in_place(
        &mut self,
        plaintext: &mut [u8],
    ) -> Result<[u8; TAG_LEN], OutboundError> {
        let nonce = nonce_from_counter(self.nonce_counter);
        self.nonce_counter += 1;
        self.cipher.encrypt_in_place(&nonce, plaintext)
    }

    fn decrypt_next_in_place(&mut self, ciphertext: &mut [u8]) -> Result<usize, OutboundError> {
        let nonce = nonce_from_counter(self.nonce_counter);
        self.nonce_counter += 1;
        self.cipher.decrypt_in_place(&nonce, ciphertext)
    }
}

fn read_encrypted_chunk<S>(
    stream: &mut S,
    decoder: &mut AeadStreamCodec,
) -> Result<Vec<u8>, OutboundError>
where
    S: Read,
{
    let mut encrypted_len = [0_u8; 2 + TAG_LEN];
    stream
        .read_exact(&mut encrypted_len)
        .map_err(|err| OutboundError::BadShadowsocks(err.to_string()))?;
    let len_plain = decoder.decrypt_next(&encrypted_len)?;
    if len_plain.len() != 2 {
        return Err(OutboundError::BadShadowsocks(
            "bad decrypted chunk length".to_owned(),
        ));
    }
    let payload_len = u16::from_be_bytes([len_plain[0], len_plain[1]]) as usize;
    let mut encrypted_payload = vec![0_u8; payload_len + TAG_LEN];
    stream
        .read_exact(&mut encrypted_payload)
        .map_err(|err| OutboundError::BadShadowsocks(err.to_string()))?;
    decoder.decrypt_next(&encrypted_payload)
}

fn validate_salt_len(name: &str, salt: &[u8], want: usize) -> Result<(), OutboundError> {
    if salt.len() != want {
        return Err(OutboundError::BadShadowsocks(format!(
            "{name} salt length must be {want}, got {}",
            salt.len()
        )));
    }
    Ok(())
}

fn hkdf_sha1_subkey(master_key: &[u8], salt: &[u8], len: usize) -> Result<Vec<u8>, OutboundError> {
    let hk = Hkdf::<Sha1>::new(Some(salt), master_key);
    let mut subkey = vec![0_u8; len];
    hk.expand(SUBKEY_INFO, &mut subkey)
        .map_err(|_| OutboundError::BadShadowsocks("hkdf expand failed".to_owned()))?;
    Ok(subkey)
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

fn nonce_from_counter(counter: u64) -> [u8; NONCE_LEN] {
    let mut nonce = [0_u8; NONCE_LEN];
    nonce[..8].copy_from_slice(&counter.to_le_bytes());
    nonce
}

enum AeadCipher {
    Aes128(Box<AeadCtx>),
    Aes256(Box<AeadCtx>),
    ChaCha(Box<ChaCha20Poly1305>),
}

impl AeadCipher {
    fn new(cipher: &str, key: &[u8]) -> Result<Self, OutboundError> {
        let spec = cipher_spec(cipher)?;
        match spec.cipher {
            "aes-128-gcm" => Ok(Self::Aes128(Box::new(
                AeadCtx::new_default_tag(&Algorithm::aes_128_gcm(), key).map_err(|err| {
                    OutboundError::BadShadowsocks(format!("bad aes-128 key: {err}"))
                })?,
            ))),
            "aes-256-gcm" => Ok(Self::Aes256(Box::new(
                AeadCtx::new_default_tag(&Algorithm::aes_256_gcm(), key).map_err(|err| {
                    OutboundError::BadShadowsocks(format!("bad aes-256 key: {err}"))
                })?,
            ))),
            "chacha20-ietf-poly1305" => Ok(Self::ChaCha(Box::new(
                ChaCha20Poly1305::new_from_slice(key)
                    .map_err(|_| OutboundError::BadShadowsocks("bad chacha key".to_owned()))?,
            ))),
            other => Err(OutboundError::BadShadowsocks(format!(
                "unsupported AEAD cipher: {other}"
            ))),
        }
    }

    fn encrypt(&self, nonce: &[u8; NONCE_LEN], plaintext: &[u8]) -> Result<Vec<u8>, OutboundError> {
        match self {
            Self::Aes128(cipher) | Self::Aes256(cipher) => {
                let mut output = plaintext.to_vec();
                let mut tag = [0_u8; TAG_LEN];
                cipher
                    .seal_in_place(nonce, &mut output, &mut tag, &[])
                    .map_err(|_| OutboundError::BadShadowsocks("aead encrypt failed".to_owned()))?;
                output.extend_from_slice(&tag);
                Ok(output)
            }
            Self::ChaCha(cipher) => cipher
                .encrypt(chacha20poly1305::Nonce::from_slice(nonce), plaintext)
                .map_err(|_| OutboundError::BadShadowsocks("aead encrypt failed".to_owned())),
        }
    }

    fn decrypt(
        &self,
        nonce: &[u8; NONCE_LEN],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, OutboundError> {
        match self {
            Self::Aes128(cipher) | Self::Aes256(cipher) => {
                let payload_len = ciphertext.len().checked_sub(TAG_LEN).ok_or_else(|| {
                    OutboundError::BadShadowsocks(
                        "aead ciphertext is shorter than its tag".to_owned(),
                    )
                })?;
                let mut output = ciphertext[..payload_len].to_vec();
                cipher
                    .open_in_place(nonce, &mut output, &ciphertext[payload_len..], &[])
                    .map_err(|_| OutboundError::BadShadowsocks("aead decrypt failed".to_owned()))?;
                Ok(output)
            }
            Self::ChaCha(cipher) => cipher
                .decrypt(chacha20poly1305::Nonce::from_slice(nonce), ciphertext)
                .map_err(|_| OutboundError::BadShadowsocks("aead decrypt failed".to_owned())),
        }
    }

    fn encrypt_in_place(
        &self,
        nonce: &[u8; NONCE_LEN],
        plaintext: &mut [u8],
    ) -> Result<[u8; TAG_LEN], OutboundError> {
        let tag = match self {
            Self::Aes128(cipher) | Self::Aes256(cipher) => {
                let mut tag = [0_u8; TAG_LEN];
                cipher
                    .seal_in_place(nonce, plaintext, &mut tag, &[])
                    .map_err(|_| OutboundError::BadShadowsocks("aead encrypt failed".to_owned()))?;
                return Ok(tag);
            }
            Self::ChaCha(cipher) => cipher.encrypt_in_place_detached(
                chacha20poly1305::Nonce::from_slice(nonce),
                &[],
                plaintext,
            ),
        }
        .map_err(|_| OutboundError::BadShadowsocks("aead encrypt failed".to_owned()))?;
        Ok(tag.into())
    }

    fn decrypt_in_place(
        &self,
        nonce: &[u8; NONCE_LEN],
        ciphertext: &mut [u8],
    ) -> Result<usize, OutboundError> {
        let plain_len = ciphertext.len().checked_sub(TAG_LEN).ok_or_else(|| {
            OutboundError::BadShadowsocks("aead ciphertext is shorter than its tag".to_owned())
        })?;
        let (plaintext, tag) = ciphertext.split_at_mut(plain_len);
        if let Self::Aes128(cipher) | Self::Aes256(cipher) = self {
            cipher
                .open_in_place(nonce, plaintext, tag, &[])
                .map_err(|_| OutboundError::BadShadowsocks("aead decrypt failed".to_owned()))?;
            return Ok(plain_len);
        }
        let tag = GenericArray::from_slice(tag);
        match self {
            Self::ChaCha(cipher) => cipher.decrypt_in_place_detached(
                chacha20poly1305::Nonce::from_slice(nonce),
                &[],
                plaintext,
                tag,
            ),
            Self::Aes128(_) | Self::Aes256(_) => unreachable!(),
        }
        .map_err(|_| OutboundError::BadShadowsocks("aead decrypt failed".to_owned()))?;
        Ok(plain_len)
    }
}

#[cfg(test)]
mod in_place_tests {
    use super::*;

    #[test]
    fn in_place_stream_chunks_match_allocating_wire_for_every_cipher() {
        for cipher in ["aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305"] {
            let spec = cipher_spec(cipher).unwrap();
            let salt = vec![0x35; spec.salt_len];
            let mut allocating = AeadStreamCodec::new(cipher, "password", &salt).unwrap();
            let mut in_place = AeadStreamCodec::new(cipher, "password", &salt).unwrap();
            let mut buffer = [0_u8; SHADOWSOCKS_AEAD_TCP_UPLOAD_BUFFER_SIZE];

            for payload_len in [1, 4097, MAX_CHUNK_LEN] {
                let payload = vec![payload_len as u8; payload_len];
                let expected = allocating.encrypt_chunk(&payload).unwrap();
                in_place.chunk_payload_buffer(&mut buffer)[..payload_len].copy_from_slice(&payload);
                let wire_len = in_place
                    .encrypt_chunk_in_place(&mut buffer, payload_len)
                    .unwrap();
                assert_eq!(&buffer[..wire_len], expected);
            }
        }
    }
}
