use super::*;

pub(super) const VLESS_RELAY_BUFFER_SIZE: usize = 32 * 1024;

mod support;
pub(super) use self::support::*;
mod async_tls;
pub(crate) use self::async_tls::*;
mod websocket;
pub(crate) use self::websocket::*;
mod plain_duplex;
pub(super) use self::plain_duplex::*;
mod mux_duplex;
pub(super) use self::mux_duplex::*;
mod tls_plain_duplex;
use self::tls_plain_duplex::*;
mod vision_duplex;
pub(crate) use self::vision_duplex::*;
