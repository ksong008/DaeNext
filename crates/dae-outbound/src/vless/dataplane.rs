use std::io::{Cursor, Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::error::OutboundError;
use crate::http_proxy::{HttpConnectOptions, request as http_proxy_request};
use crate::shared_transport::{
    DEFAULT_WS_KEY, GrpcLifecycleOptions, HttpUpgradeOptions, MeekRoundTripOptions,
    MuxFrameOptions, WS_MASK_KEY, XHttpLifecycleOptions, grpc_hunk_frame, grpc_hunk_frame_len,
    grpc_stream_preface, http_upgrade_request, meek_http_request, mux, mux_data_frame,
    mux_end_frame, mux_new_frame, read_grpc_hunk_frame, read_http_head,
    read_websocket_binary_frame, validate_http_status, websocket_client_binary_frame,
    websocket_handshake_request, xhttp_packet_request, xhttp_request_path,
};
use crate::vmess::{VMessMetadata, VMessNetwork};

use super::packet;

pub const VLESS_VERSION: u8 = 0;

mod grpc_http2;
mod helpers;
mod tls_transports;
mod types;
#[cfg(any(test, feature = "test-support"))]
mod xhttp_h3;
mod xhttp_http2;

pub use grpc_http2::*;
use helpers::*;
pub use tls_transports::*;
pub use types::*;
#[cfg(any(test, feature = "test-support"))]
pub use xhttp_h3::*;
pub use xhttp_http2::*;

mod stream_exchange;
pub use self::stream_exchange::*;
mod transport_exchange;
pub use self::transport_exchange::*;
mod request_readers;
pub use self::request_readers::*;
mod transport_readers;
pub use self::transport_readers::*;
mod responses;
pub use self::responses::*;
