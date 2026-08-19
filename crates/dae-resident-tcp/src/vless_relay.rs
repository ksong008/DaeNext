use super::*;

pub const VLESS_RELAY_BUFFER_SIZE: usize = 32 * 1024;

mod support;
pub use self::support::*;
mod async_tls;
pub use self::async_tls::*;
mod websocket;
pub use self::websocket::*;
mod plain_duplex;
pub use self::plain_duplex::*;
mod mux_duplex;
pub use self::mux_duplex::*;
mod tls_plain_duplex;
use self::tls_plain_duplex::*;
mod vision_duplex;
pub use self::vision_duplex::*;
