use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aes::cipher::{BlockEncrypt, KeyInit as BlockKeyInit};
use aes::{Aes128, Aes256};
use aes_gcm::aead::Aead;
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use chacha20poly1305::ChaCha20Poly1305;

use crate::error::OutboundError;
use crate::socks5::Socks5Address;

use super::ss2022::{
    CipherConf2022, HEADER_TYPE_CLIENT_STREAM, HEADER_TYPE_SERVER_STREAM, MAX_PADDING_LENGTH,
    TCP_CHUNK_MAX_LEN, cipher_conf, validate_base64_psk,
};

include!("ss2022_tcp_dataplane/types.rs");
include!("ss2022_tcp_dataplane/exchanges.rs");
include!("ss2022_tcp_dataplane/client_api.rs");
include!("ss2022_tcp_dataplane/server_api.rs");
include!("ss2022_tcp_dataplane/client_codec.rs");
include!("ss2022_tcp_dataplane/server_codec.rs");
include!("ss2022_tcp_dataplane/identity.rs");
include!("ss2022_tcp_dataplane/stream_codec.rs");
include!("ss2022_tcp_dataplane/keys.rs");
