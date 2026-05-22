use std::io::{Cursor, Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::{SystemTime, UNIX_EPOCH};

use aes_gcm::aead::{Aead, KeyInit as AeadKeyInit, Payload};
use aes_gcm::aes::Aes128;
use aes_gcm::aes::cipher::{
    BlockDecrypt, BlockEncrypt, KeyInit as BlockKeyInit, generic_array::GenericArray,
};
use aes_gcm::{Aes128Gcm, Nonce};
use md5::{Digest, Md5};
use sha2::Sha256;
use sha3::Shake128;
use sha3::digest::{ExtendableOutput, Update, XofReader};

use crate::error::OutboundError;
use crate::http_proxy::{HttpConnectOptions, request as http_proxy_request};
use crate::shared_transport::{
    DEFAULT_WS_KEY, GrpcLifecycleOptions, HttpUpgradeOptions, MeekRoundTripOptions,
    MuxFrameOptions, WS_MASK_KEY, grpc_hunk_frame, grpc_stream_preface, http_upgrade_request,
    meek_http_request, mux, mux_data_frame, mux_end_frame, mux_new_frame, read_grpc_hunk_frame,
    read_http_head, read_websocket_binary_frame, validate_http_status,
    websocket_client_binary_frame, websocket_handshake_request,
};
use crate::vmess::uuid::normalize_vmess_uuid;

use super::{
    VMessMetadata, VMessMetadataType, VMessNetwork, packet_addr_magic_target,
    parse_packet_addr_payload, put_packet_addr_payload,
};

const KDF_SALT_AUTH_ID_ENCRYPTION_KEY: &[u8] = b"AES Auth ID Encryption";
const KDF_SALT_AEAD_RESP_HEADER_LEN_KEY: &[u8] = b"AEAD Resp Header Len Key";
const KDF_SALT_AEAD_RESP_HEADER_LEN_IV: &[u8] = b"AEAD Resp Header Len IV";
const KDF_SALT_AEAD_RESP_HEADER_PAYLOAD_KEY: &[u8] = b"AEAD Resp Header Key";
const KDF_SALT_AEAD_RESP_HEADER_PAYLOAD_IV: &[u8] = b"AEAD Resp Header IV";
const KDF_SALT_VMESS_AEAD_KDF: &[u8] = b"VMess AEAD KDF";
const KDF_SALT_HEADER_PAYLOAD_AEAD_KEY: &[u8] = b"VMess Header AEAD Key";
const KDF_SALT_HEADER_PAYLOAD_AEAD_IV: &[u8] = b"VMess Header AEAD Nonce";
const KDF_SALT_HEADER_PAYLOAD_LENGTH_AEAD_KEY: &[u8] = b"VMess Header AEAD Key_Length";
const KDF_SALT_HEADER_PAYLOAD_LENGTH_AEAD_IV: &[u8] = b"VMess Header AEAD Nonce_Length";
const VMESS_CMD_KEY_SALT: &[u8] = b"c48619fe-8f02-49e0-b9e9-edf763e17e21";
const VMESS_VERSION: u8 = 1;
const OPTION_CHUNK_STREAM: u8 = 1;
const OPTION_CHUNK_LENGTH_MASKING: u8 = 4;
const OPTION_GLOBAL_PADDING: u8 = 8;
const REQUEST_OPTIONS: u8 =
    OPTION_CHUNK_STREAM | OPTION_CHUNK_LENGTH_MASKING | OPTION_GLOBAL_PADDING;
const MAX_CHUNK_SIZE: usize = 1 << 14;

pub const VMESS_AEAD_SECURITY_AES_128_GCM: u8 = 3;

mod body_codec;
mod build_request;
mod command_key;
mod crypto;
mod exchange;
mod grpc_http2;
mod read_request;
mod response_http;
mod response_read;
mod tls_transports;
mod types;
mod xhttp_http2;

pub use command_key::*;
pub use exchange::*;
pub use grpc_http2::*;
pub use read_request::*;
pub use response_http::*;
pub use tls_transports::*;
pub use types::*;
pub use xhttp_http2::*;

use body_codec::*;
use build_request::*;
use crypto::*;
use response_read::*;
