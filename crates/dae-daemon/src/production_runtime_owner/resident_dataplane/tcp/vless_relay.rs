use super::*;

pub(super) const VLESS_RELAY_BUFFER_SIZE: usize = 32 * 1024;

mod support;
pub(super) use self::support::*;
mod async_tls;
pub(in crate::production_runtime_owner::resident_dataplane) use self::async_tls::*;
mod websocket;
pub(in crate::production_runtime_owner::resident_dataplane) use self::websocket::*;
mod plain_duplex;
pub(super) use self::plain_duplex::*;
mod mux_duplex;
pub(super) use self::mux_duplex::*;
mod tls_plain_duplex;
use self::tls_plain_duplex::*;
mod vision_duplex;
use self::vision_duplex::*;
