pub mod boring_quic;
pub mod congestion;
pub mod hysteria2;
pub mod juicity;
#[cfg(any(test, feature = "test-support"))]
pub mod quic_h3;
pub mod system_ca;
pub mod tuic;

pub const XHTTP_H3_ALPN: &str = "h3";
pub const XHTTP_H3_KEEPALIVE_SECS: u64 = 5;
pub const XHTTP_H3_HANDSHAKE_IDLE_TIMEOUT_SECS: u64 = 8;

#[cfg(any(test, feature = "test-support"))]
pub mod test_support;

pub use congestion::{QuicCongestionController, QuicCongestionControllerError};
