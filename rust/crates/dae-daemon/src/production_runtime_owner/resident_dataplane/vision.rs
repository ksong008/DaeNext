use std::sync::atomic::{AtomicBool, Ordering};

use super::client::{AsyncVlessTlsClient, VlessTlsClient, flush_tls_writes};
use super::{
    TLS_RECORD_HEADER_LEN, TLS_RECORD_MAX_PAYLOAD_LEN, VISION_COMMAND_CONTINUE,
    VISION_COMMAND_DIRECT, VISION_COMMAND_END,
};
use tls_parser::{
    TlsExtension, TlsMessage, TlsMessageHandshake, TlsPlaintext, TlsRecordType, TlsVersion,
    parse_tls_client_hello_extension, parse_tls_plaintext, parse_tls_server_hello_extension,
};

const TLS_CONTENT_TYPE_APPLICATION_DATA: u8 = 23;
const TLS_CONTENT_TYPE_HANDSHAKE: u8 = 22;
#[cfg(test)]
const TLS_HANDSHAKE_TYPE_SERVER_HELLO: u8 = 0x02;
#[cfg(test)]
const TLS_EXTENSION_SUPPORTED_VERSIONS: u16 = 0x002b;
#[cfg(test)]
const TLS_VERSION_1_3: u16 = 0x0304;
const TLS13_AES_128_CCM_8_SHA256: u16 = 0x1305;
const VISION_TLS_OBSERVE_LIMIT: usize = 64 * 1024;

mod unpadder;
pub(super) use self::unpadder::*;
mod tls_state;
pub(super) use self::tls_state::*;
mod uplink;
pub(super) use self::uplink::*;
mod helpers;
pub(super) use self::helpers::*;
#[cfg(test)]
mod tests;
#[cfg(test)]
use self::tests::*;
