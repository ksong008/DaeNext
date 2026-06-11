use super::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VMessAeadTcpExchangeReport {
    pub proxy: String,
    pub target: String,
    pub uuid: String,
    pub cmd_key_hex: String,
    pub command: u8,
    pub security: u8,
    pub request_header_len: usize,
    pub request_chunk_len: usize,
    pub response_header_len: usize,
    pub response_chunk_len: usize,
    pub payload_len: usize,
    pub echoed_payload: Vec<u8>,
    pub true_dataplane: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VMessAeadUdpOverTcpExchangeReport {
    pub proxy: String,
    pub target: String,
    pub uuid: String,
    pub cmd_key_hex: String,
    pub command: u8,
    pub security: u8,
    pub request_header_len: usize,
    pub request_chunk_len: usize,
    pub response_header_len: usize,
    pub response_chunk_len: usize,
    pub payload_len: usize,
    pub packet_len: usize,
    pub echoed_payload: Vec<u8>,
    pub true_dataplane: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VMessAeadPacketAddrUdpExchangeReport {
    pub proxy: String,
    pub request_target: String,
    pub packet_target: String,
    pub uuid: String,
    pub cmd_key_hex: String,
    pub command: u8,
    pub security: u8,
    pub request_header_len: usize,
    pub request_chunk_len: usize,
    pub response_header_len: usize,
    pub response_chunk_len: usize,
    pub payload_len: usize,
    pub packet_addr_len: usize,
    pub packet_len: usize,
    pub echoed_payload: Vec<u8>,
    pub true_dataplane: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VMessAeadMuxExchangeReport {
    pub proxy: String,
    pub request_target: String,
    pub mux_target: String,
    pub uuid: String,
    pub cmd_key_hex: String,
    pub command: u8,
    pub security: u8,
    pub mux_id_hex: String,
    pub request_header_len: usize,
    pub request_chunk_len: usize,
    pub response_header_len: usize,
    pub response_chunk_len: usize,
    pub payload_len: usize,
    pub echoed_payload: Vec<u8>,
    pub new_frame_validated: bool,
    pub data_frame_validated: bool,
    pub end_frame_sent: bool,
    pub true_dataplane: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VMessAeadWebSocketExchangeReport {
    pub proxy: String,
    pub target: String,
    pub ws_host: String,
    pub ws_path: String,
    pub uuid: String,
    pub cmd_key_hex: String,
    pub command: u8,
    pub security: u8,
    pub request_header_len: usize,
    pub request_chunk_len: usize,
    pub response_header_len: usize,
    pub response_chunk_len: usize,
    pub websocket_request_frame_len: usize,
    pub websocket_response_frame_len: usize,
    pub payload_len: usize,
    pub echoed_payload: Vec<u8>,
    pub websocket_handshake_validated: bool,
    pub websocket_binary_frame_validated: bool,
    pub true_dataplane: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VMessAeadHttpUpgradeExchangeReport {
    pub proxy: String,
    pub target: String,
    pub httpupgrade_host: String,
    pub httpupgrade_path: String,
    pub uuid: String,
    pub cmd_key_hex: String,
    pub command: u8,
    pub security: u8,
    pub request_header_len: usize,
    pub request_chunk_len: usize,
    pub response_header_len: usize,
    pub response_chunk_len: usize,
    pub httpupgrade_request_len: usize,
    pub httpupgrade_response_head_len: usize,
    pub payload_len: usize,
    pub echoed_payload: Vec<u8>,
    pub httpupgrade_handshake_validated: bool,
    pub httpupgrade_tunnel_validated: bool,
    pub true_dataplane: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VMessAeadGrpcHunkExchangeReport {
    pub proxy: String,
    pub target: String,
    pub grpc_service_name: String,
    pub grpc_cache_key: String,
    pub uuid: String,
    pub cmd_key_hex: String,
    pub command: u8,
    pub security: u8,
    pub request_header_len: usize,
    pub request_chunk_len: usize,
    pub response_header_len: usize,
    pub response_chunk_len: usize,
    pub grpc_preface_len: usize,
    pub grpc_request_hunk_len: usize,
    pub grpc_response_hunk_len: usize,
    pub payload_len: usize,
    pub echoed_payload: Vec<u8>,
    pub grpc_stream_preface_validated: bool,
    pub grpc_hunk_frame_validated: bool,
    pub cache_key_route_context_validated: bool,
    pub full_grpc_http2_stack: bool,
    pub true_dataplane: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VMessAeadMeekPollingExchangeReport {
    pub proxy: String,
    pub target: String,
    pub meek_url: String,
    pub meek_host: String,
    pub meek_path: String,
    pub meek_session_id: String,
    pub uuid: String,
    pub cmd_key_hex: String,
    pub command: u8,
    pub security: u8,
    pub request_header_len: usize,
    pub request_chunk_len: usize,
    pub response_header_len: usize,
    pub response_chunk_len: usize,
    pub meek_request_len: usize,
    pub meek_request_body_len: usize,
    pub meek_response_head_len: usize,
    pub meek_response_body_len: usize,
    pub payload_len: usize,
    pub echoed_payload: Vec<u8>,
    pub meek_polling_validated: bool,
    pub full_https_round_tripper: bool,
    pub true_dataplane: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VMessAeadHttpTransportExchangeReport {
    pub proxy: String,
    pub target: String,
    pub http_transport_host: String,
    pub http_transport_path: String,
    pub uuid: String,
    pub cmd_key_hex: String,
    pub command: u8,
    pub security: u8,
    pub request_header_len: usize,
    pub request_chunk_len: usize,
    pub response_header_len: usize,
    pub response_chunk_len: usize,
    pub http_transport_request_len: usize,
    pub http_transport_response_head_len: usize,
    pub payload_len: usize,
    pub echoed_payload: Vec<u8>,
    pub http_transport_put_validated: bool,
    pub full_http2_stack: bool,
    pub true_dataplane: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VMessAeadTcpRequest {
    pub version: u8,
    pub uuid: String,
    pub cmd_key_hex: String,
    pub eauth_crc_validated: bool,
    pub eauth_timestamp: u64,
    pub request_options: u8,
    pub security: u8,
    pub command: u8,
    pub target: String,
    pub payload: Vec<u8>,
    pub request_header_len: usize,
    pub request_chunk_len: usize,
    pub response_auth: u8,
    pub request_body_iv: [u8; 16],
    pub request_body_key: [u8; 16],
    pub response_body_iv: [u8; 16],
    pub response_body_key: [u8; 16],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VMessAeadUdpOverTcpRequest {
    pub request: VMessAeadTcpRequest,
    pub packet_len: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VMessAeadPacketAddrUdpRequest {
    pub request: VMessAeadTcpRequest,
    pub packet_target: String,
    pub packet_addr_len: usize,
    pub packet_payload: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VMessAeadMuxRequest {
    pub request: VMessAeadTcpRequest,
    pub new_frame: mux::MuxFrame,
    pub data_frame: mux::MuxFrame,
    pub end_frame: mux::MuxFrame,
    pub mux_id_hex: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VMessAeadWebSocketRequest {
    pub request: VMessAeadTcpRequest,
    pub websocket_request_frame_len: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VMessAeadHttpUpgradeRequest {
    pub request: VMessAeadTcpRequest,
    pub httpupgrade_tunnel_validated: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VMessAeadGrpcHunkRequest {
    pub request: VMessAeadTcpRequest,
    pub grpc_request_hunk_len: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VMessAeadMeekPollingRequest {
    pub request: VMessAeadTcpRequest,
    pub meek_request_body_len: usize,
    pub meek_session_id_validated: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VMessHttpTransportRequestHead {
    pub method: String,
    pub request_uri: String,
    pub host: String,
    pub path: String,
    pub request_head_len: usize,
    pub transport_enabled: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct VMessAeadRequestPacket {
    pub(super) header: Vec<u8>,
    pub(super) chunk: Vec<u8>,
    pub(super) request: VMessAeadTcpRequest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct VMessAeadChunkedRequestPacket {
    pub(super) header: Vec<u8>,
    pub(super) chunks: Vec<Vec<u8>>,
    pub(super) request: VMessAeadTcpRequest,
}

pub struct VMessAeadTcpClientSessionStart {
    pub first_write: Vec<u8>,
    pub request: VMessAeadTcpRequest,
    pub upload: VMessAeadTcpUploadCodec,
}

pub struct VMessAeadTcpUploadCodec {
    pub(super) codec: BodyCodec,
}

pub struct VMessAeadTcpResponseReader {
    pub response_header_len: usize,
    pub(super) codec: BodyCodec,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct VMessAeadMaterial {
    pub(super) request_body_iv: [u8; 16],
    pub(super) request_body_key: [u8; 16],
    pub(super) response_auth: u8,
    pub(super) eauth_random: [u8; 4],
    pub(super) connection_nonce: [u8; 8],
}

impl Default for VMessAeadMaterial {
    fn default() -> Self {
        Self {
            request_body_iv: *b"dae-vmess-aead!!",
            request_body_key: *b"dae-vmess-key!!!",
            response_auth: 0x65,
            eauth_random: [0xda, 0xee, 0x65, 0x01],
            connection_nonce: *b"dae65cn!",
        }
    }
}

impl VMessAeadMaterial {
    pub(super) fn random() -> Self {
        let mut request_body_iv = [0_u8; 16];
        let mut request_body_key = [0_u8; 16];
        let mut eauth_random = [0_u8; 4];
        let mut connection_nonce = [0_u8; 8];
        let mut response_auth = [0_u8; 1];
        fastrand::fill(&mut request_body_iv);
        fastrand::fill(&mut request_body_key);
        fastrand::fill(&mut eauth_random);
        fastrand::fill(&mut connection_nonce);
        fastrand::fill(&mut response_auth);
        Self {
            request_body_iv,
            request_body_key,
            response_auth: response_auth[0],
            eauth_random,
            connection_nonce,
        }
    }
}
