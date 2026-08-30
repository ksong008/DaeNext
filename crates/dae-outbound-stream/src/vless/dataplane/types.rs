#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VlessTcpExchangeReport {
    pub proxy: String,
    pub target: String,
    pub key_hex: String,
    pub command: u8,
    pub payload_len: usize,
    pub echoed_payload: Vec<u8>,
    pub true_dataplane: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VlessUdpOverTcpExchangeReport {
    pub proxy: String,
    pub target: String,
    pub key_hex: String,
    pub command: u8,
    pub payload_len: usize,
    pub packet_len: usize,
    pub echoed_payload: Vec<u8>,
    pub response_header_len: usize,
    pub true_dataplane: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VlessMuxExchangeReport {
    pub proxy: String,
    pub target: String,
    pub key_hex: String,
    pub command: u8,
    pub mux_id_hex: String,
    pub payload_len: usize,
    pub echoed_payload: Vec<u8>,
    pub new_frame_validated: bool,
    pub data_frame_validated: bool,
    pub end_frame_sent: bool,
    pub true_dataplane: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VlessWebSocketExchangeReport {
    pub proxy: String,
    pub target: String,
    pub ws_host: String,
    pub ws_path: String,
    pub key_hex: String,
    pub command: u8,
    pub request_header_len: usize,
    pub response_header_len: usize,
    pub websocket_request_frame_len: usize,
    pub websocket_response_frame_len: usize,
    pub payload_len: usize,
    pub echoed_payload: Vec<u8>,
    pub websocket_handshake_validated: bool,
    pub websocket_binary_frame_validated: bool,
    pub true_dataplane: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VlessHttpUpgradeExchangeReport {
    pub proxy: String,
    pub target: String,
    pub httpupgrade_host: String,
    pub httpupgrade_path: String,
    pub key_hex: String,
    pub command: u8,
    pub request_header_len: usize,
    pub response_header_len: usize,
    pub httpupgrade_request_len: usize,
    pub httpupgrade_response_head_len: usize,
    pub payload_len: usize,
    pub echoed_payload: Vec<u8>,
    pub httpupgrade_handshake_validated: bool,
    pub true_dataplane: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VlessGrpcHunkExchangeReport {
    pub proxy: String,
    pub target: String,
    pub grpc_service_name: String,
    pub grpc_cache_key: String,
    pub key_hex: String,
    pub command: u8,
    pub request_header_len: usize,
    pub response_header_len: usize,
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
pub struct VlessMeekPollingExchangeReport {
    pub proxy: String,
    pub target: String,
    pub meek_url: String,
    pub meek_host: String,
    pub meek_path: String,
    pub meek_session_id: String,
    pub key_hex: String,
    pub command: u8,
    pub request_header_len: usize,
    pub response_header_len: usize,
    pub meek_request_len: usize,
    pub meek_request_body_len: usize,
    pub meek_response_head_len: usize,
    pub meek_response_body_len: usize,
    pub payload_len: usize,
    pub echoed_payload: Vec<u8>,
    pub meek_polling_validated: bool,
    pub meek_session_id_validated: bool,
    pub full_https_round_tripper: bool,
    pub true_dataplane: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VlessHttpTransportExchangeReport {
    pub proxy: String,
    pub target: String,
    pub http_transport_host: String,
    pub http_transport_path: String,
    pub key_hex: String,
    pub command: u8,
    pub request_header_len: usize,
    pub response_header_len: usize,
    pub http_transport_request_len: usize,
    pub http_transport_response_head_len: usize,
    pub payload_len: usize,
    pub echoed_payload: Vec<u8>,
    pub http_transport_put_validated: bool,
    pub full_http2_stack: bool,
    pub true_dataplane: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VlessXHttpPacketExchangeReport {
    pub proxy: String,
    pub target: String,
    pub xhttp_host: String,
    pub xhttp_path: String,
    pub xhttp_request_path: String,
    pub xhttp_mode: String,
    pub xhttp_alpn: String,
    pub key_hex: String,
    pub command: u8,
    pub request_header_len: usize,
    pub response_header_len: usize,
    pub xhttp_request_len: usize,
    pub xhttp_request_body_len: usize,
    pub xhttp_response_head_len: usize,
    pub xhttp_response_body_len: usize,
    pub payload_len: usize,
    pub echoed_payload: Vec<u8>,
    pub xhttp_packet_up_validated: bool,
    pub xhttp_xmux_enabled: bool,
    pub full_h2_h3_stack: bool,
    pub true_dataplane: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VlessTcpRequest {
    pub version: u8,
    pub key: [u8; 16],
    pub key_hex: String,
    pub addons_len: usize,
    pub command: u8,
    pub target: String,
    pub payload: Vec<u8>,
    pub header_len: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VlessUdpRequest {
    pub version: u8,
    pub key: [u8; 16],
    pub key_hex: String,
    pub addons_len: usize,
    pub command: u8,
    pub target: String,
    pub payload_len: usize,
    pub payload: Vec<u8>,
    pub header_len: usize,
    pub packet_len: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VlessMuxRequest {
    pub version: u8,
    pub key: [u8; 16],
    pub key_hex: String,
    pub addons_len: usize,
    pub command: u8,
    pub header_len: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VlessWebSocketRequest {
    pub request: VlessTcpRequest,
    pub websocket_request_frame_len: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VlessGrpcHunkRequest {
    pub request: VlessTcpRequest,
    pub grpc_request_hunk_len: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VlessMeekPollingRequest {
    pub request: VlessTcpRequest,
    pub meek_request_body_len: usize,
    pub meek_session_id_validated: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VlessHttpTransportRequestHead {
    pub method: String,
    pub request_uri: String,
    pub host: String,
    pub path: String,
    pub request_head_len: usize,
    pub transport_enabled: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VlessXHttpPacketRequest {
    pub request: VlessTcpRequest,
    pub xhttp_request_body_len: usize,
    pub xhttp_request_path: String,
    pub xhttp_packet_up_validated: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct VlessRequestHeader {
    pub(super) version: u8,
    pub(super) key: [u8; 16],
    pub(super) key_hex: String,
    pub(super) addons_len: usize,
    pub(super) command: u8,
    pub(super) target: String,
    pub(super) header_len: usize,
}
