use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit as BlockKeyInit};
use aes::{Aes128, Aes256};
use aes_gcm::aead::Aead;
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use chacha20poly1305::XChaCha20Poly1305;

use crate::error::OutboundError;
use crate::socks5::Socks5Address;

use super::ss2022::{
    CipherConf2022, HEADER_TYPE_CLIENT_PACKET, HEADER_TYPE_SERVER_PACKET, MAX_PADDING_LENGTH,
    SERVER_SESSION_RETENTION_SECS, SlidingWindowFilter, UDP_REPLAY_WINDOW_SIZE, cipher_conf,
    validate_base64_psk,
};

const SESSION_SUBKEY_CONTEXT: &str = "shadowsocks 2022 session subkey";
const TIMESTAMP_TOLERANCE_SECS: u64 = 30;
const AES_BLOCK_LEN: usize = 16;

mod types;
pub use self::types::*;
mod replay;
use self::replay::Ss2022UdpReplayTable;
pub use self::replay::{Ss2022UdpReplayMetricsSnapshot, Ss2022UdpReplayPolicy};
mod codec;
mod public_api;
pub use self::public_api::*;
mod separate_header;
use self::separate_header::*;
mod merged_header;
use self::merged_header::*;
mod messages;
use self::messages::*;
mod payload_cipher;
use self::payload_cipher::*;
mod identity_headers;
use self::identity_headers::*;
mod helpers;
use self::helpers::*;
