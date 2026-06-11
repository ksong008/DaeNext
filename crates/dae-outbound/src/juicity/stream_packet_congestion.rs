use std::cmp;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::error::OutboundError;
use crate::socks5::Socks5Address;
use crate::trojan::{TrojanMetadata, TrojanNetwork};

use super::auth_stream_live::{build_live_client_config, build_live_server_config, selected_alpn};
use super::h3_loopback::{
    DEFAULT_H3_ALPN, DEFAULT_H3_HANDSHAKE_IDLE_TIMEOUT_SECS, DEFAULT_H3_KEEPALIVE_SECS,
    DEFAULT_H3_SERVER_NAME,
};
use super::packet::{
    JuicityStreamPacketFrame, decode_stream_packet_frame, seal_stream_packet_frame,
};

mod model;
pub use self::model::*;
mod runner;
pub use self::runner::*;
mod server;
use self::server::*;
mod stream_request;
use self::stream_request::*;
mod transport;
use self::transport::*;
