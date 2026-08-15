use super::kdf::derive_key_bytes;
use super::{
    VlessEncryptionClient, VlessEncryptionMode, VlessEncryptionRtt, VlessEncryptionSpec,
    VlessEncryptionTicket,
};
use aes::Aes256;
use aes::cipher::{BlockEncrypt, KeyInit as BlockKeyInit};
use aes_gcm::aead::{Aead, AeadInPlace};
use aes_gcm::{Aes256Gcm, Nonce as AesNonce};
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChaChaNonce};
use getrandom::fill as random_fill;
use std::io::{self, Error, ErrorKind, Result};
use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use super::boring_mlkem::{DecapsulationKey, EncapsulationKey};
use x25519_dalek::{PublicKey, StaticSecret};

const MAX_RECORD_PAYLOAD: usize = 8192;
const RECORD_HEADER_LEN: usize = 5;
const AEAD_TAG_LEN: usize = 16;
const MAX_RECORD_LEN: usize = 16_640;
const MAX_NONCE: [u8; 12] = [0xff; 12];
const SERVER_PFS_RESPONSE_LEN: usize = 1088 + 32 + 16;

#[cfg(test)]
static SECRET_WIPE_CALLS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

fn cleanse_secret(bytes: &mut [u8]) {
    unsafe {
        boring_sys::OPENSSL_cleanse(bytes.as_mut_ptr().cast(), bytes.len());
    }
    #[cfg(test)]
    SECRET_WIPE_CALLS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}

struct SecretVec(Vec<u8>);

impl SecretVec {
    fn new() -> Self {
        Self(Vec::new())
    }

    fn extend_from_slice(&mut self, bytes: &[u8]) {
        self.0.extend_from_slice(bytes);
    }
}

impl From<Vec<u8>> for SecretVec {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl Deref for SecretVec {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for SecretVec {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Drop for SecretVec {
    fn drop(&mut self) {
        cleanse_secret(&mut self.0);
    }
}

struct SecretArray<const N: usize>([u8; N]);

impl<const N: usize> SecretArray<N> {
    fn zeroed() -> Self {
        Self([0; N])
    }

    fn copied(&self) -> [u8; N] {
        self.0
    }
}

impl<const N: usize> From<[u8; N]> for SecretArray<N> {
    fn from(bytes: [u8; N]) -> Self {
        Self(bytes)
    }
}

impl<const N: usize> Deref for SecretArray<N> {
    type Target = [u8; N];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const N: usize> DerefMut for SecretArray<N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<const N: usize> Drop for SecretArray<N> {
    fn drop(&mut self) {
        cleanse_secret(&mut self.0);
    }
}

#[derive(Clone)]
#[allow(dead_code)]
enum AeadState {
    Aes(Aes256Gcm, [u8; 12]),
    ChaCha(ChaCha20Poly1305, [u8; 12]),
}

impl AeadState {
    fn new(context: &[u8], key_material: &[u8]) -> Self {
        let mut key = derive_key_bytes(context, key_material);
        // Xray-core's VLESS Encryption server currently constructs its record
        // AEAD with AES enabled. Keep the client on the same wire choice; the
        // AES implementation itself uses the platform's accelerated backend
        // when available.
        let cipher = Aes256Gcm::new_from_slice(&key).expect("VLESS AES-256 key length");
        cleanse_secret(&mut key);
        Self::Aes(cipher, [0; 12])
    }

    fn nonce_next(nonce: &mut [u8; 12]) -> [u8; 12] {
        for index in (0..12).rev() {
            nonce[index] = nonce[index].wrapping_add(1);
            if nonce[index] != 0 {
                break;
            }
        }
        *nonce
    }

    fn seal_next(&mut self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::Aes(cipher, nonce) => cipher
                .encrypt(
                    AesNonce::from_slice(&Self::nonce_next(nonce)),
                    aes_gcm::aead::Payload {
                        msg: plaintext,
                        aad,
                    },
                )
                .map_err(|_| {
                    Error::new(ErrorKind::InvalidData, "VLESS Encryption AES seal failed")
                }),
            Self::ChaCha(cipher, nonce) => cipher
                .encrypt(
                    ChaChaNonce::from_slice(&Self::nonce_next(nonce)),
                    chacha20poly1305::aead::Payload {
                        msg: plaintext,
                        aad,
                    },
                )
                .map_err(|_| {
                    Error::new(
                        ErrorKind::InvalidData,
                        "VLESS Encryption ChaCha seal failed",
                    )
                }),
        }
    }

    fn open_next(&mut self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::Aes(cipher, nonce) => cipher
                .decrypt(
                    AesNonce::from_slice(&Self::nonce_next(nonce)),
                    aes_gcm::aead::Payload {
                        msg: ciphertext,
                        aad,
                    },
                )
                .map_err(|_| {
                    Error::new(ErrorKind::InvalidData, "VLESS Encryption AES open failed")
                }),
            Self::ChaCha(cipher, nonce) => cipher
                .decrypt(
                    ChaChaNonce::from_slice(&Self::nonce_next(nonce)),
                    chacha20poly1305::aead::Payload {
                        msg: ciphertext,
                        aad,
                    },
                )
                .map_err(|_| {
                    Error::new(
                        ErrorKind::InvalidData,
                        "VLESS Encryption ChaCha open failed",
                    )
                }),
        }
    }

    fn seal_next_in_place(
        &mut self,
        buffer: &mut Vec<u8>,
        payload_offset: usize,
        aad: &[u8],
    ) -> Result<()> {
        let tag = match self {
            Self::Aes(cipher, nonce) => cipher
                .encrypt_in_place_detached(
                    AesNonce::from_slice(&Self::nonce_next(nonce)),
                    aad,
                    &mut buffer[payload_offset..],
                )
                .map_err(|_| {
                    Error::new(ErrorKind::InvalidData, "VLESS Encryption AES seal failed")
                })?,
            Self::ChaCha(cipher, nonce) => cipher
                .encrypt_in_place_detached(
                    ChaChaNonce::from_slice(&Self::nonce_next(nonce)),
                    aad,
                    &mut buffer[payload_offset..],
                )
                .map_err(|_| {
                    Error::new(
                        ErrorKind::InvalidData,
                        "VLESS Encryption ChaCha seal failed",
                    )
                })?,
        };
        buffer.extend_from_slice(&tag);
        Ok(())
    }

    fn open_next_in_place(&mut self, ciphertext: &mut Vec<u8>, aad: &[u8]) -> Result<()> {
        let payload_len = ciphertext
            .len()
            .checked_sub(AEAD_TAG_LEN)
            .ok_or_else(|| io_other("VLESS Encryption record is shorter than its AEAD tag"))?;
        let tag = aes_gcm::Tag::clone_from_slice(&ciphertext[payload_len..]);
        let plaintext = &mut ciphertext[..payload_len];
        match self {
            Self::Aes(cipher, nonce) => cipher
                .decrypt_in_place_detached(
                    AesNonce::from_slice(&Self::nonce_next(nonce)),
                    aad,
                    plaintext,
                    &tag,
                )
                .map_err(|_| {
                    Error::new(ErrorKind::InvalidData, "VLESS Encryption AES open failed")
                })?,
            Self::ChaCha(cipher, nonce) => cipher
                .decrypt_in_place_detached(
                    ChaChaNonce::from_slice(&Self::nonce_next(nonce)),
                    aad,
                    plaintext,
                    &tag,
                )
                .map_err(|_| {
                    Error::new(
                        ErrorKind::InvalidData,
                        "VLESS Encryption ChaCha open failed",
                    )
                })?,
        }
        ciphertext.truncate(payload_len);
        Ok(())
    }

    fn open_with_nonce(&self, nonce: &[u8; 12], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::Aes(cipher, _) => cipher
                .decrypt(
                    AesNonce::from_slice(nonce),
                    aes_gcm::aead::Payload {
                        msg: ciphertext,
                        aad,
                    },
                )
                .map_err(|_| {
                    Error::new(ErrorKind::InvalidData, "VLESS Encryption AES open failed")
                }),
            Self::ChaCha(cipher, _) => cipher
                .decrypt(
                    ChaChaNonce::from_slice(nonce),
                    chacha20poly1305::aead::Payload {
                        msg: ciphertext,
                        aad,
                    },
                )
                .map_err(|_| {
                    Error::new(
                        ErrorKind::InvalidData,
                        "VLESS Encryption ChaCha open failed",
                    )
                }),
        }
    }
}

struct AesCtr {
    cipher: Aes256,
    counter: [u8; 16],
    block: [u8; 16],
    offset: usize,
}

impl AesCtr {
    /// Xray's camouflage CTR uses the fixed BLAKE3 derive-key context
    /// `VLESS`, with the caller-provided material as the derive input.
    /// Keeping this separate from the AEAD context is important: the relay
    /// public-key XOR and the `random` record-header camouflage are not
    /// derived from their wire context bytes.
    fn new(key_material: &[u8], iv: &[u8; 16]) -> Self {
        let mut key = derive_key_bytes(b"VLESS", key_material);
        let state = Self {
            cipher: Aes256::new_from_slice(&key).expect("VLESS CTR key length"),
            counter: *iv,
            block: [0; 16],
            offset: 16,
        };
        cleanse_secret(&mut key);
        state
    }

    fn apply(&mut self, data: &mut [u8]) {
        for byte in data {
            if self.offset == 16 {
                self.block = self.counter;
                self.cipher.encrypt_block((&mut self.block).into());
                self.offset = 0;
                for index in (0..16).rev() {
                    self.counter[index] = self.counter[index].wrapping_add(1);
                    if self.counter[index] != 0 {
                        break;
                    }
                }
            }
            *byte ^= self.block[self.offset];
            self.offset += 1;
        }
    }
}

impl Drop for AesCtr {
    fn drop(&mut self) {
        cleanse_secret(&mut self.counter);
        cleanse_secret(&mut self.block);
        self.offset = 0;
    }
}

#[derive(Debug)]
enum ReadState {
    ServerRandom {
        buffer: [u8; 16],
        filled: usize,
    },
    PeerPadding {
        buffer: Vec<u8>,
        filled: usize,
    },
    Header {
        buffer: [u8; RECORD_HEADER_LEN],
        filled: usize,
    },
    Body {
        header: [u8; RECORD_HEADER_LEN],
        buffer: Vec<u8>,
        filled: usize,
    },
    Eof,
}

pub struct VlessEncryptedStream<S> {
    inner: S,
    write_aead: AeadState,
    read_aead: Option<AeadState>,
    united_key: SecretVec,
    write_ctr: Option<AesCtr>,
    read_ctr: Option<AesCtr>,
    prewrite: Vec<u8>,
    pending_write: Vec<u8>,
    pending_offset: usize,
    read_state: ReadState,
    read_plain: Vec<u8>,
    read_plain_offset: usize,
    vision_raw_read_handoff_requested: bool,
    vision_raw_read_handoff_active: bool,
    vision_raw_write_handoff_requested: bool,
    vision_raw_write_handoff_active: bool,
    client: VlessEncryptionClient,
}

impl<S> Unpin for VlessEncryptedStream<S> where S: Unpin {}

impl<S> VlessEncryptedStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    pub async fn handshake(mut inner: S, client: VlessEncryptionClient) -> Result<Self> {
        let spec = &client.spec;
        let mut iv = [0_u8; 16];
        random_fill(&mut iv).map_err(|error| io_other(error.to_string()))?;
        let (relays, nfs_key) = build_relays(spec, &iv)?;
        let iv_and_relays_len = 16 + relays.len();
        let mut nfs_aead = AeadState::new(&iv, &nfs_key);
        let mut prewrite = Vec::new();
        let read_state;
        let mut read_aead: Option<AeadState> = None;
        let mut write_ctr: Option<AesCtr> = None;
        let mut read_ctr: Option<AesCtr> = None;
        let mut united_key = SecretVec::new();
        if spec.rtt == VlessEncryptionRtt::ZeroRtt {
            let ticket = client
                .ticket
                .lock()
                .map_err(|_| io_other("VLESS Encryption ticket mutex poisoned"))?
                .clone()
                .filter(|ticket| ticket.expires_at > Instant::now());
            if let Some(ticket) = ticket {
                united_key.extend_from_slice(&ticket.pfs_key);
                united_key.extend_from_slice(&nfs_key);
                let mut prefix = Vec::with_capacity(iv_and_relays_len + 50);
                prefix.extend_from_slice(&iv);
                prefix.extend_from_slice(&relays);
                prefix.extend_from_slice(&nfs_aead.seal_next(&[0, 32], &[])?);
                let encrypted_ticket = nfs_aead.seal_next(&ticket.ticket, &[])?;
                prefix.extend_from_slice(&encrypted_ticket);
                prewrite = prefix;
                let write_aead = AeadState::new(&encrypted_ticket, &united_key);
                if spec.mode.random_records() {
                    write_ctr = Some(AesCtr::new(&united_key, &iv));
                }
                read_state = ReadState::ServerRandom {
                    buffer: [0; 16],
                    filled: 0,
                };
                return Ok(Self {
                    inner,
                    write_aead,
                    read_aead,
                    united_key,
                    write_ctr,
                    read_ctr,
                    prewrite,
                    pending_write: Vec::new(),
                    pending_offset: 0,
                    read_state,
                    read_plain: Vec::new(),
                    read_plain_offset: 0,
                    vision_raw_read_handoff_requested: false,
                    vision_raw_read_handoff_active: false,
                    vision_raw_write_handoff_requested: false,
                    vision_raw_write_handoff_active: false,
                    client,
                });
            }
        }

        let (pfs_mlkem_public, pfs_decapsulation) = DecapsulationKey::generate();
        let mut x25519_private_bytes = SecretArray::<32>::zeroed();
        random_fill(&mut *x25519_private_bytes).map_err(|error| io_other(error.to_string()))?;
        let x25519_private = StaticSecret::from(x25519_private_bytes.copied());
        let x25519_public = PublicKey::from(&x25519_private);
        let mut pfs_public = Vec::with_capacity(1216);
        pfs_public.extend_from_slice(&pfs_mlkem_public);
        pfs_public.extend_from_slice(x25519_public.as_bytes());

        let padding = spec.padding.encoded_fragment_lengths();
        let padding_plain_len = padding.0.iter().sum::<usize>();
        let padding_total_len = padding_plain_len;
        if padding_total_len < 35 {
            return Err(io_other(
                "VLESS Encryption sampled padding is below 35 bytes",
            ));
        }
        let pfs_cipher_len = 18 + pfs_public.len() + 16;
        let mut pfs_exchange = Vec::with_capacity(pfs_cipher_len);
        // The length field is the ciphertext size that follows it (the
        // 1216-byte PFS public key plus its 16-byte AEAD tag), matching
        // Xray's `pfsKeyExchangeLength - 18` calculation.
        pfs_exchange.extend_from_slice(&nfs_aead.seal_next(
            &encode_len(pfs_public.len().saturating_add(AEAD_TAG_LEN)),
            &[],
        )?);
        pfs_exchange.extend_from_slice(&nfs_aead.seal_next(&pfs_public, &[])?);
        debug_assert_eq!(pfs_exchange.len(), pfs_cipher_len);
        let mut padding_exchange = vec![0_u8; padding_total_len];
        let padding_length_cipher =
            nfs_aead.seal_next(&encode_len(padding_total_len.saturating_sub(18)), &[])?;
        if padding_length_cipher.len() != 18 {
            return Err(io_other("VLESS Encryption padding length framing failed"));
        }
        padding_exchange[..18].copy_from_slice(&padding_length_cipher);
        let padding_data_len = padding_total_len.saturating_sub(34);
        let padding_data_cipher = nfs_aead.seal_next(&vec![0_u8; padding_data_len], &[])?;
        if padding_data_cipher.len() != padding_data_len + 16 {
            return Err(io_other("VLESS Encryption padding framing failed"));
        }
        if 18 + padding_data_cipher.len() != padding_exchange.len() {
            return Err(io_other("VLESS Encryption padding length mismatch"));
        }
        padding_exchange[18..].copy_from_slice(&padding_data_cipher);

        let mut client_hello =
            Vec::with_capacity(iv_and_relays_len + pfs_exchange.len() + padding_exchange.len());
        client_hello.extend_from_slice(&iv);
        client_hello.extend_from_slice(&relays);
        client_hello.extend_from_slice(&pfs_exchange);
        client_hello.extend_from_slice(&padding_exchange);
        let mut fragment_lengths = padding.0;
        fragment_lengths[0] =
            fragment_lengths[0].saturating_add(iv_and_relays_len + pfs_exchange.len());
        let mut cursor = 0usize;
        for (index, length) in fragment_lengths.into_iter().enumerate() {
            let end = cursor.saturating_add(length);
            if end > client_hello.len() {
                return Err(io_other(
                    "VLESS Encryption handshake fragmentation overflow",
                ));
            }
            inner.write_all(&client_hello[cursor..end]).await?;
            inner.flush().await?;
            cursor = end;
            if let Some(gap) = padding.1.get(index) {
                if !gap.is_zero() {
                    tokio::time::sleep(*gap).await;
                }
            }
        }
        if cursor != client_hello.len() {
            return Err(io_other(
                "VLESS Encryption handshake fragmentation underflow",
            ));
        }

        let mut encrypted_peer_pfs = vec![0_u8; SERVER_PFS_RESPONSE_LEN];
        inner.read_exact(&mut encrypted_peer_pfs).await?;
        let max_nonce = MAX_NONCE;
        let peer_pfs_plain =
            SecretVec::from(nfs_aead.open_with_nonce(&max_nonce, &encrypted_peer_pfs, &[])?);
        if peer_pfs_plain.len() != 1120 {
            return Err(io_other(
                "VLESS Encryption server PFS response length mismatch",
            ));
        }
        let mlkem_secret = pfs_decapsulation
            .decapsulate(&peer_pfs_plain[..1088])
            .map_err(|_| io_other("VLESS ML-KEM-768 decapsulation failed"))?;
        let server_x25519_public = PublicKey::from(
            <[u8; 32]>::try_from(&peer_pfs_plain[1088..1120])
                .map_err(|_| io_other("VLESS X25519 server public key length mismatch"))?,
        );
        let x25519_secret = x25519_private.diffie_hellman(&server_x25519_public);
        let mut pfs_key = SecretArray::<64>::zeroed();
        pfs_key[..32].copy_from_slice(mlkem_secret.as_bytes());
        pfs_key[32..].copy_from_slice(x25519_secret.as_bytes());
        united_key.extend_from_slice(&*pfs_key);
        united_key.extend_from_slice(&nfs_key);
        let write_aead = AeadState::new(&pfs_public, &united_key);
        let mut peer_aead = AeadState::new(&peer_pfs_plain, &united_key);

        let mut encrypted_ticket = [0_u8; 32];
        inner.read_exact(&mut encrypted_ticket).await?;
        let ticket = SecretVec::from(peer_aead.open_next(&encrypted_ticket, &[])?);
        if ticket.len() != 16 {
            return Err(io_other("VLESS Encryption ticket length mismatch"));
        }
        let mut ticket_bytes = SecretArray::<16>::zeroed();
        ticket_bytes.copy_from_slice(&ticket);
        let server_seconds = u16::from_be_bytes([ticket[0], ticket[1]]) as u64;
        // The actual ticket duration is encoded in the first two bytes by
        // Xray. A zero value means no 0-RTT cache is admitted.
        if spec.rtt == VlessEncryptionRtt::ZeroRtt && server_seconds != 0 {
            let mut guard = client
                .ticket
                .lock()
                .map_err(|_| io_other("VLESS Encryption ticket mutex poisoned"))?;
            *guard = Some(VlessEncryptionTicket {
                expires_at: Instant::now() + Duration::from_secs(server_seconds),
                pfs_key: pfs_key.copied(),
                ticket: ticket_bytes.copied(),
            });
        }

        let mut encrypted_padding_len = [0_u8; 18];
        inner.read_exact(&mut encrypted_padding_len).await?;
        let padding_len_plain = peer_aead.open_next(&encrypted_padding_len, &[])?;
        if padding_len_plain.len() != 2 {
            return Err(io_other("VLESS Encryption server padding length mismatch"));
        }
        let peer_padding_len =
            u16::from_be_bytes([padding_len_plain[0], padding_len_plain[1]]) as usize;
        read_state = ReadState::PeerPadding {
            buffer: vec![0_u8; peer_padding_len],
            filled: 0,
        };
        if spec.mode.random_records() {
            write_ctr = Some(AesCtr::new(&united_key, &iv));
            read_ctr = Some(AesCtr::new(&united_key, &*ticket_bytes));
        }
        read_aead = Some(peer_aead);
        Ok(Self {
            inner,
            write_aead,
            read_aead,
            united_key,
            write_ctr,
            read_ctr,
            prewrite,
            pending_write: Vec::new(),
            pending_offset: 0,
            read_state,
            read_plain: Vec::new(),
            read_plain_offset: 0,
            vision_raw_read_handoff_requested: false,
            vision_raw_read_handoff_active: false,
            vision_raw_write_handoff_requested: false,
            vision_raw_write_handoff_active: false,
            client,
        })
    }

    pub fn into_inner(self) -> S {
        self.inner
    }

    pub fn mode(&self) -> VlessEncryptionMode {
        self.client.spec.mode
    }

    /// Switch the Vision transport from VLESS Encryption records to the
    /// underlying TLS stream after the server's direct command. Xray keeps the
    /// outer TLS security layer but deliberately bypasses the VLESS record
    /// wrapper at this point; retaining the wrapper would interpret raw TLS
    /// records as VLESS ciphertext and produce BAD_RECORD_MAC.
    pub fn request_vision_raw_read_handoff(&mut self) {
        self.vision_raw_read_handoff_requested = true;
    }

    pub fn vision_raw_handoff_active(&self) -> bool {
        self.vision_raw_read_handoff_active
    }

    pub fn request_vision_raw_write_handoff(&mut self) {
        self.vision_raw_write_handoff_requested = true;
    }

    fn activate_vision_raw_read_handoff(&mut self) {
        if self.vision_raw_read_handoff_requested && self.read_plain_offset >= self.read_plain.len()
        {
            self.vision_raw_read_handoff_requested = false;
            self.vision_raw_read_handoff_active = true;
        }
    }

    fn activate_vision_raw_write_handoff(&mut self) {
        if self.vision_raw_write_handoff_requested
            && self.pending_offset >= self.pending_write.len()
        {
            self.vision_raw_write_handoff_requested = false;
            self.vision_raw_write_handoff_active = true;
        }
    }

    fn build_record(&mut self, payload: &[u8]) -> Result<()> {
        let length = payload.len().saturating_add(AEAD_TAG_LEN);
        if length > u16::MAX as usize || length + RECORD_HEADER_LEN > MAX_RECORD_LEN {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "VLESS Encryption record is too large",
            ));
        }
        let mut header = [0_u8; RECORD_HEADER_LEN];
        header[..3].copy_from_slice(&[23, 3, 3]);
        header[3..].copy_from_slice(&(length as u16).to_be_bytes());
        self.pending_write.clear();
        self.pending_offset = 0;
        if !self.prewrite.is_empty() {
            if self.pending_write.capacity() < self.prewrite.len() {
                self.pending_write = std::mem::take(&mut self.prewrite);
            } else {
                self.pending_write.append(&mut self.prewrite);
            }
        }
        let record_start = self.pending_write.len();
        self.pending_write
            .reserve(RECORD_HEADER_LEN + payload.len() + AEAD_TAG_LEN);
        self.pending_write.extend_from_slice(&header);
        let payload_offset = self.pending_write.len();
        self.pending_write.extend_from_slice(payload);
        self.write_aead
            .seal_next_in_place(&mut self.pending_write, payload_offset, &header)?;
        if let Some(ctr) = &mut self.write_ctr {
            ctr.apply(&mut self.pending_write[record_start..payload_offset]);
        }
        Ok(())
    }

    fn evict_ticket(&self) {
        if let Ok(mut guard) = self.client.ticket.lock() {
            // Xray treats an invalid 0-RTT response as a stale or replayed
            // ticket and forces the next connection through a full handshake.
            // Keeping a still-in-TTL ticket after an invalid record would
            // make every subsequent request reuse the same bad state.
            *guard = None;
        }
    }
}

impl<S> AsyncRead for VlessEncryptedStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        target: &mut ReadBuf<'_>,
    ) -> Poll<Result<()>> {
        self.as_mut().get_mut().activate_vision_raw_read_handoff();
        if self.vision_raw_read_handoff_active && self.read_plain_offset >= self.read_plain.len() {
            return Pin::new(&mut self.inner).poll_read(cx, target);
        }
        if self.read_plain_offset < self.read_plain.len() {
            let remaining = &self.read_plain[self.read_plain_offset..];
            let copied = remaining.len().min(target.remaining());
            target.put_slice(&remaining[..copied]);
            self.read_plain_offset += copied;
            if self.read_plain_offset == self.read_plain.len() {
                self.read_plain.clear();
                self.read_plain_offset = 0;
            }
            return Poll::Ready(Ok(()));
        }
        loop {
            let state = std::mem::replace(&mut self.read_state, ReadState::Eof);
            match state {
                ReadState::Eof => return Poll::Ready(Ok(())),
                ReadState::ServerRandom {
                    mut buffer,
                    mut filled,
                } => {
                    let mut read_buf = ReadBuf::new(&mut buffer[filled..]);
                    match Pin::new(&mut self.inner).poll_read(cx, &mut read_buf) {
                        Poll::Pending => {
                            self.read_state = ReadState::ServerRandom { buffer, filled };
                            return Poll::Pending;
                        }
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Ready(Ok(())) => {
                            let read = read_buf.filled().len();
                            filled += read;
                            if filled != buffer.len() {
                                if read == 0 {
                                    self.read_state = ReadState::Eof;
                                    return Poll::Ready(Err(Error::new(
                                        ErrorKind::UnexpectedEof,
                                        "VLESS Encryption server random truncated",
                                    )));
                                }
                                self.read_state = ReadState::ServerRandom { buffer, filled };
                                continue;
                            }
                            let aead = AeadState::new(&buffer, &self.united_key);
                            self.read_aead = Some(aead);
                            if self.client.spec.mode.random_records() {
                                self.read_ctr = Some(AesCtr::new(&self.united_key, &buffer));
                            }
                            self.read_state = ReadState::Header {
                                buffer: [0; RECORD_HEADER_LEN],
                                filled: 0,
                            };
                            continue;
                        }
                    }
                }
                ReadState::PeerPadding {
                    mut buffer,
                    mut filled,
                } => {
                    if buffer.is_empty() {
                        self.read_state = ReadState::Header {
                            buffer: [0; RECORD_HEADER_LEN],
                            filled: 0,
                        };
                        continue;
                    }
                    let mut read_buf = ReadBuf::new(&mut buffer[filled..]);
                    match Pin::new(&mut self.inner).poll_read(cx, &mut read_buf) {
                        Poll::Pending => {
                            self.read_state = ReadState::PeerPadding { buffer, filled };
                            return Poll::Pending;
                        }
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Ready(Ok(())) => {
                            let read = read_buf.filled().len();
                            filled += read;
                            if filled != buffer.len() {
                                if read == 0 {
                                    self.read_state = ReadState::Eof;
                                    return Poll::Ready(Err(Error::new(
                                        ErrorKind::UnexpectedEof,
                                        "VLESS Encryption peer padding truncated",
                                    )));
                                }
                                self.read_state = ReadState::PeerPadding { buffer, filled };
                                continue;
                            }
                            let aead = self
                                .read_aead
                                .as_mut()
                                .ok_or_else(|| io_other("VLESS Encryption peer AEAD missing"));
                            if let Err(error) =
                                aead.and_then(|aead| aead.open_next(&buffer, &[]).map(|_| ()))
                            {
                                return Poll::Ready(Err(error));
                            }
                            self.read_state = ReadState::Header {
                                buffer: [0; RECORD_HEADER_LEN],
                                filled: 0,
                            };
                            continue;
                        }
                    }
                }
                ReadState::Header {
                    mut buffer,
                    mut filled,
                } => {
                    let mut read_buf = ReadBuf::new(&mut buffer[filled..]);
                    match Pin::new(&mut self.inner).poll_read(cx, &mut read_buf) {
                        Poll::Pending => {
                            self.read_state = ReadState::Header { buffer, filled };
                            return Poll::Pending;
                        }
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Ready(Ok(())) => {
                            let read = read_buf.filled().len();
                            filled += read;
                            if filled != buffer.len() {
                                if read == 0 {
                                    self.read_state = ReadState::Eof;
                                    if filled == 0 {
                                        return Poll::Ready(Ok(()));
                                    }
                                    return Poll::Ready(Err(Error::new(
                                        ErrorKind::UnexpectedEof,
                                        "VLESS Encryption record header truncated",
                                    )));
                                }
                                self.read_state = ReadState::Header { buffer, filled };
                                continue;
                            }
                            if let Some(ctr) = &mut self.read_ctr {
                                ctr.apply(&mut buffer);
                            }
                            let length = u16::from_be_bytes([buffer[3], buffer[4]]) as usize;
                            if buffer[..3] != [23, 3, 3] || !(17..=MAX_RECORD_LEN).contains(&length)
                            {
                                self.evict_ticket();
                                return Poll::Ready(Err(io_other(
                                    "VLESS Encryption record header invalid; ticket evicted",
                                )));
                            }
                            let mut body = std::mem::take(&mut self.read_plain);
                            body.clear();
                            body.resize(length, 0);
                            self.read_state = ReadState::Body {
                                header: buffer,
                                buffer: body,
                                filled: 0,
                            };
                            continue;
                        }
                    }
                }
                ReadState::Body {
                    header,
                    mut buffer,
                    mut filled,
                } => {
                    let mut read_buf = ReadBuf::new(&mut buffer[filled..]);
                    match Pin::new(&mut self.inner).poll_read(cx, &mut read_buf) {
                        Poll::Pending => {
                            self.read_state = ReadState::Body {
                                header,
                                buffer,
                                filled,
                            };
                            return Poll::Pending;
                        }
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Ready(Ok(())) => {
                            let read = read_buf.filled().len();
                            filled += read;
                            if filled != buffer.len() {
                                if read == 0 {
                                    self.read_state = ReadState::Eof;
                                    return Poll::Ready(Err(Error::new(
                                        ErrorKind::UnexpectedEof,
                                        "VLESS Encryption record body truncated",
                                    )));
                                }
                                self.read_state = ReadState::Body {
                                    header,
                                    buffer,
                                    filled,
                                };
                                continue;
                            }
                            let plaintext = self
                                .read_aead
                                .as_mut()
                                .ok_or_else(|| io_other("VLESS Encryption peer AEAD missing"))
                                .and_then(|aead| aead.open_next_in_place(&mut buffer, &header));
                            match plaintext {
                                Ok(()) => {
                                    self.read_plain = buffer;
                                    self.read_plain_offset = 0;
                                    self.read_state = ReadState::Header {
                                        buffer: [0; RECORD_HEADER_LEN],
                                        filled: 0,
                                    };
                                    if !self.read_plain.is_empty() {
                                        // Return the plaintext produced by this record in the
                                        // same poll.  Continuing here can consume the next
                                        // record and then return Pending with `read_plain`
                                        // buffered but no new socket wakeup, leaving callers
                                        // (notably the Vision relay) asleep forever after the
                                        // peer's final response record.
                                        let copied = self.read_plain.len().min(target.remaining());
                                        target.put_slice(&self.read_plain[..copied]);
                                        self.read_plain_offset = copied;
                                        if self.read_plain_offset == self.read_plain.len() {
                                            self.read_plain.clear();
                                            self.read_plain_offset = 0;
                                        }
                                        return Poll::Ready(Ok(()));
                                    }
                                }
                                Err(error) => return Poll::Ready(Err(error)),
                            }
                        }
                    }
                }
            }
        }
    }
}

impl<S> AsyncWrite for VlessEncryptedStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<Result<usize>> {
        self.as_mut().get_mut().activate_vision_raw_write_handoff();
        if self.vision_raw_write_handoff_active {
            return Pin::new(&mut self.inner).poll_write(cx, input);
        }
        while self.pending_offset < self.pending_write.len() {
            let this = self.as_mut().get_mut();
            let pending = &this.pending_write[this.pending_offset..];
            match Pin::new(&mut this.inner).poll_write(cx, pending) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(Error::new(
                        ErrorKind::WriteZero,
                        "VLESS Encryption inner write returned zero",
                    )));
                }
                Poll::Ready(Ok(written)) => {
                    this.pending_offset += written;
                }
            }
        }
        self.pending_write.clear();
        self.pending_offset = 0;
        self.as_mut().get_mut().activate_vision_raw_write_handoff();
        if self.vision_raw_write_handoff_active {
            return Pin::new(&mut self.inner).poll_write(cx, input);
        }
        if input.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let take = input.len().min(MAX_RECORD_PAYLOAD);
        match self.build_record(&input[..take]) {
            Ok(()) => Poll::Ready(Ok(take)),
            Err(error) => Poll::Ready(Err(error)),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        self.as_mut().get_mut().activate_vision_raw_write_handoff();
        if self.vision_raw_write_handoff_active {
            return Pin::new(&mut self.inner).poll_flush(cx);
        }
        while self.pending_offset < self.pending_write.len() {
            let this = self.as_mut().get_mut();
            let pending = &this.pending_write[this.pending_offset..];
            match Pin::new(&mut this.inner).poll_write(cx, pending) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(Error::new(
                        ErrorKind::WriteZero,
                        "VLESS Encryption inner flush write returned zero",
                    )));
                }
                Poll::Ready(Ok(written)) => this.pending_offset += written,
            }
        }
        self.pending_write.clear();
        self.pending_offset = 0;
        self.as_mut().get_mut().activate_vision_raw_write_handoff();
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        self.as_mut().get_mut().activate_vision_raw_write_handoff();
        if self.vision_raw_write_handoff_active {
            return Pin::new(&mut self.inner).poll_shutdown(cx);
        }
        match self.as_mut().poll_flush(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut self.inner).poll_shutdown(cx),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }
}

fn build_relays(spec: &VlessEncryptionSpec, iv: &[u8; 16]) -> Result<(Vec<u8>, SecretVec)> {
    let mut relays = Vec::new();
    let mut nfs_key = SecretVec::new();
    let mut last_ctr: Option<AesCtr> = None;
    for (index, public_key) in spec.public_keys.iter().enumerate() {
        let relay_offset = relays.len();
        if public_key.len() == 32 {
            let key = PublicKey::from(
                <[u8; 32]>::try_from(public_key.as_slice())
                    .map_err(|_| io_other("VLESS X25519 key length mismatch"))?,
            );
            let mut private_bytes = SecretArray::<32>::zeroed();
            random_fill(&mut *private_bytes).map_err(|error| io_other(error.to_string()))?;
            let private = StaticSecret::from(private_bytes.copied());
            let public = PublicKey::from(&private);
            relays.extend_from_slice(public.as_bytes());
            nfs_key = SecretVec::from(private.diffie_hellman(&key).as_bytes().to_vec());
            if spec.mode.xor_public_key() {
                let mut ctr = AesCtr::new(public_key, iv);
                ctr.apply(&mut relays[relay_offset..relay_offset + 32]);
            }
        } else {
            let key = EncapsulationKey::from_encoded(public_key)
                .map_err(|_| io_other("invalid VLESS ML-KEM-768 client public key"))?;
            let (ciphertext, secret) = key.encapsulate();
            relays.extend_from_slice(&ciphertext);
            nfs_key = SecretVec::from(secret.as_bytes().to_vec());
            if spec.mode.xor_public_key() {
                let mut ctr = AesCtr::new(public_key, iv);
                ctr.apply(&mut relays[relay_offset..relay_offset + 1088]);
            }
        }
        if let Some(ctr) = &mut last_ctr {
            ctr.apply(&mut relays[relay_offset..relay_offset + 32]);
        }
        if index + 1 != spec.public_keys.len() {
            let next_hash = blake3::hash(&spec.public_keys[index + 1]);
            let link_start = relays.len();
            relays.extend_from_slice(&[0_u8; 32]);
            let mut ctr = AesCtr::new(&nfs_key, iv);
            let mut linked = next_hash.as_bytes().to_owned();
            ctr.apply(&mut linked);
            relays[link_start..link_start + 32].copy_from_slice(&linked);
            last_ctr = Some(ctr);
        }
    }
    if nfs_key.len() != 32 {
        return Err(io_other(
            "VLESS Encryption static key exchange produced invalid secret",
        ));
    }
    Ok((relays, nfs_key))
}

fn encode_len(value: usize) -> [u8; 2] {
    (value as u16).to_be_bytes()
}

fn io_other(message: impl Into<String>) -> io::Error {
    Error::new(ErrorKind::Other, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use std::task::Poll;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    struct ChunkedIo {
        read_data: Vec<u8>,
        read_offset: usize,
        writes: Vec<u8>,
        max_write: usize,
    }

    impl ChunkedIo {
        fn new(read_data: Vec<u8>, max_write: usize) -> Self {
            Self {
                read_data,
                read_offset: 0,
                writes: Vec::new(),
                max_write: max_write.max(1),
            }
        }
    }

    impl AsyncRead for ChunkedIo {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            target: &mut ReadBuf<'_>,
        ) -> Poll<Result<()>> {
            if self.read_offset >= self.read_data.len() {
                return Poll::Ready(Ok(()));
            }
            let available = self.read_data.len() - self.read_offset;
            let copied = available.min(target.remaining());
            target.put_slice(&self.read_data[self.read_offset..self.read_offset + copied]);
            self.read_offset += copied;
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for ChunkedIo {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            input: &[u8],
        ) -> Poll<Result<usize>> {
            let copied = input.len().min(self.max_write);
            self.writes.extend_from_slice(&input[..copied]);
            Poll::Ready(Ok(copied))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    fn test_client() -> VlessEncryptionClient {
        let public_key = URL_SAFE_NO_PAD.encode([0x42_u8; 32]);
        VlessEncryptionClient::parse(&format!("mlkem768x25519plus.native.1rtt.{public_key}"))
            .expect("fixture encryption must parse")
            .expect("fixture encryption must be admitted")
    }

    fn test_stream(inner: ChunkedIo, read_state: ReadState) -> VlessEncryptedStream<ChunkedIo> {
        let client = test_client();
        VlessEncryptedStream {
            inner,
            write_aead: AeadState::new(b"fixture-write", &[0x11; 32]),
            read_aead: Some(AeadState::new(b"fixture-read", &[0x22; 32])),
            united_key: SecretVec::from(vec![0x33; 64]),
            write_ctr: None,
            read_ctr: None,
            prewrite: Vec::new(),
            pending_write: Vec::new(),
            pending_offset: 0,
            read_state,
            read_plain: Vec::new(),
            read_plain_offset: 0,
            vision_raw_read_handoff_requested: false,
            vision_raw_read_handoff_active: false,
            vision_raw_write_handoff_requested: false,
            vision_raw_write_handoff_active: false,
            client,
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn partial_inner_writes_are_drained_without_lost_wakeup() {
        let mut stream = test_stream(ChunkedIo::new(Vec::new(), 1), ReadState::Eof);
        tokio::time::timeout(
            Duration::from_secs(1),
            stream.write_all(b"partial-write-fixture"),
        )
        .await
        .expect("write_all must not wait for a wakeup after a partial write")
        .expect("write_all must succeed");
        stream.flush().await.expect("flush must drain the record");
        assert!(!stream.into_inner().writes.is_empty());
    }

    #[test]
    fn record_aead_in_place_matches_allocating_wire_and_open() {
        let payload = b"in-place-record-payload";
        let aad = [23, 3, 3, 0, (payload.len() + AEAD_TAG_LEN) as u8];
        let mut allocating = AeadState::new(b"fixture", &[0x11; 32]);
        let expected = allocating.seal_next(payload, &aad).unwrap();

        let mut in_place = AeadState::new(b"fixture", &[0x11; 32]);
        let mut encoded = vec![0xaa, 0xbb];
        encoded.extend_from_slice(payload);
        in_place.seal_next_in_place(&mut encoded, 2, &aad).unwrap();
        assert_eq!(&encoded[2..], expected);

        let mut opener = AeadState::new(b"fixture", &[0x11; 32]);
        let mut ciphertext = expected;
        opener.open_next_in_place(&mut ciphertext, &aad).unwrap();
        assert_eq!(ciphertext, payload);
    }

    #[test]
    fn record_writer_reuses_pending_allocation() {
        let mut stream = test_stream(ChunkedIo::new(Vec::new(), usize::MAX), ReadState::Eof);
        stream.build_record(&[0x31; 256]).unwrap();
        let allocation = stream.pending_write.as_ptr();
        let capacity = stream.pending_write.capacity();

        stream.build_record(&[0x72; 256]).unwrap();
        assert_eq!(stream.pending_write.as_ptr(), allocation);
        assert_eq!(stream.pending_write.capacity(), capacity);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn clean_record_boundary_eof_returns_without_spinning() {
        let mut stream = test_stream(
            ChunkedIo::new(Vec::new(), 8),
            ReadState::Header {
                buffer: [0; RECORD_HEADER_LEN],
                filled: 0,
            },
        );
        let mut output = [0_u8; 32];
        let read = tokio::time::timeout(Duration::from_secs(1), stream.read(&mut output))
            .await
            .expect("clean EOF must not spin")
            .expect("clean EOF read must succeed");
        assert_eq!(read, 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn partial_record_eof_is_reported_as_unexpected_eof() {
        let mut stream = test_stream(
            ChunkedIo::new(vec![23], 8),
            ReadState::Header {
                buffer: [0; RECORD_HEADER_LEN],
                filled: 0,
            },
        );
        let mut output = [0_u8; 32];
        let error = tokio::time::timeout(Duration::from_secs(1), stream.read(&mut output))
            .await
            .expect("partial EOF must not spin")
            .expect_err("partial record must fail");
        assert_eq!(error.kind(), ErrorKind::UnexpectedEof);
    }

    #[test]
    fn invalid_record_evicts_a_still_live_zero_rtt_ticket() {
        let stream = test_stream(ChunkedIo::new(Vec::new(), 8), ReadState::Eof);
        *stream
            .client
            .ticket
            .lock()
            .expect("ticket mutex must be available") = Some(VlessEncryptionTicket {
            expires_at: Instant::now() + Duration::from_secs(600),
            pfs_key: [0x44; 64],
            ticket: [0x55; 16],
        });
        stream.evict_ticket();
        assert!(
            stream
                .client
                .ticket
                .lock()
                .expect("ticket mutex must be available")
                .is_none()
        );
    }

    #[test]
    fn secret_owners_cleanse_on_drop() {
        let before = SECRET_WIPE_CALLS.load(std::sync::atomic::Ordering::Relaxed);
        drop(SecretVec::from(vec![0x5a; 64]));
        drop(SecretArray::<32>::from([0xa5; 32]));
        let after = SECRET_WIPE_CALLS.load(std::sync::atomic::Ordering::Relaxed);
        assert!(after >= before + 2);
    }
}
