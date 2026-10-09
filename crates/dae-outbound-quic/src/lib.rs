pub mod boring_quic;
pub mod congestion;
pub mod hysteria2;
pub mod juicity;
#[cfg(any(test, feature = "test-support"))]
pub mod quic_h3;
pub mod system_ca;
pub mod tuic;

// Shared by multiplexed HY2/TUIC connections. 64 KiB evicts received packets
// during ordinary 100-session MTU-sized bursts before the owner can drain them.
// Keep a bounded 256 KiB allowance per connection, allocated only as data arrives;
// the separate 64 KiB send queue uses backpressure at the resident sender.
pub const PROXY_DATAGRAM_RECEIVE_BUFFER_BYTES: usize = 256 * 1024;

pub const XHTTP_H3_ALPN: &str = "h3";
pub const XHTTP_H3_KEEPALIVE_SECS: u64 = 10;
// QUIC's max_idle_timeout also applies after the handshake. Keep it above the
// default 10-second keepalive; an 8-second handshake budget here killed idle
// application streams before their first PING. Match Xray's ConnIdleTimeout.
pub const XHTTP_H3_MAX_IDLE_TIMEOUT_SECS: u64 = 300;

#[cfg(any(test, feature = "test-support"))]
pub mod test_support;

pub use congestion::{QuicCongestionController, QuicCongestionControllerError};

#[cfg(test)]
mod datagram_tests;
