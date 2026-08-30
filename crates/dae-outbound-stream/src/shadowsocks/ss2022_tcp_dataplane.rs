use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aes::cipher::{BlockEncrypt, KeyInit as BlockKeyInit};
use aes::{Aes128, Aes256};
use aes_gcm::aead::{Aead, AeadInPlace};
use aes_gcm::aes::cipher::generic_array::GenericArray;
use boring::aead::{AeadCtx, Algorithm};
use chacha20poly1305::ChaCha20Poly1305;

use crate::error::OutboundError;
use crate::socks5::Socks5Address;
use tokio::io::{AsyncRead, AsyncReadExt};

use super::ss2022::{
    CipherConf2022, HEADER_TYPE_CLIENT_STREAM, HEADER_TYPE_SERVER_STREAM, MAX_PADDING_LENGTH,
    TCP_CHUNK_MAX_LEN, cipher_conf, validate_base64_psk,
};

mod types;
pub use self::types::*;
mod exchanges;
pub use self::exchanges::*;
mod client_api;
pub use self::client_api::*;
mod server_api;
pub use self::server_api::*;
mod client_codec;
use self::client_codec::*;
mod server_codec;
use self::server_codec::*;
mod identity;
use self::identity::*;
mod stream_codec;
use self::stream_codec::*;
mod keys;
pub use self::keys::*;
