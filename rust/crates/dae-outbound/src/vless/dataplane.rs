use std::io::{Cursor, Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::error::OutboundError;
use crate::http_proxy::{HttpConnectOptions, request as http_proxy_request};
use crate::shared_transport::{
    DEFAULT_WS_KEY, GrpcLifecycleOptions, HttpUpgradeOptions, MeekRoundTripOptions,
    MuxFrameOptions, WS_MASK_KEY, XHttpLifecycleOptions, grpc_hunk_frame, grpc_stream_preface,
    http_upgrade_request, meek_http_request, mux, mux_data_frame, mux_end_frame, mux_new_frame,
    read_grpc_hunk_frame, read_http_head, read_websocket_binary_frame, validate_http_status,
    websocket_client_binary_frame, websocket_handshake_request, xhttp_packet_request,
    xhttp_request_path,
};
use crate::vmess::{VMessMetadata, VMessNetwork};

use super::packet;

pub const VLESS_VERSION: u8 = 0;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VlessTcpExchangeReport {
    pub proxy: String,
    pub target: String,
    pub key_hex: String,
    pub command: u8,
    pub payload_len: usize,
    pub echoed_payload: Vec<u8>,
    pub true_dataplane: bool,
    pub default_go_path: bool,
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
    pub default_go_path: bool,
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
    pub default_go_path: bool,
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
    pub default_go_path: bool,
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
    pub default_go_path: bool,
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
    pub default_go_path: bool,
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
    pub default_go_path: bool,
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
    pub default_go_path: bool,
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
    pub default_go_path: bool,
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
struct VlessRequestHeader {
    version: u8,
    key: [u8; 16],
    key_hex: String,
    addons_len: usize,
    command: u8,
    target: String,
    header_len: usize,
}

pub fn tcp_exchange_over_stream<S>(
    stream: &mut S,
    proxy: &str,
    key: &[u8; 16],
    target: &str,
    payload: &[u8],
) -> Result<VlessTcpExchangeReport, OutboundError>
where
    S: Read + Write,
{
    let request = packet::first_write_bytes(key, "", "tcp", target, false, payload)?;
    stream
        .write_all(&request)
        .map_err(|err| OutboundError::BadVless(err.to_string()))?;

    let mut echoed_payload = vec![0_u8; payload.len()];
    stream
        .read_exact(&mut echoed_payload)
        .map_err(|err| OutboundError::BadVless(err.to_string()))?;

    Ok(VlessTcpExchangeReport {
        proxy: proxy.to_owned(),
        target: target.to_owned(),
        key_hex: hex_encode(key),
        command: VMessNetwork::Tcp.byte(),
        payload_len: payload.len(),
        echoed_payload,
        true_dataplane: true,
        default_go_path: true,
    })
}

pub fn udp_over_tcp_exchange_over_stream<S>(
    stream: &mut S,
    proxy: &str,
    key: &[u8; 16],
    target: &str,
    payload: &[u8],
) -> Result<VlessUdpOverTcpExchangeReport, OutboundError>
where
    S: Read + Write,
{
    let request = packet::first_write_bytes(key, "", "udp", target, false, payload)?;
    stream
        .write_all(&request)
        .map_err(|err| OutboundError::BadVless(err.to_string()))?;

    let (response_header_len, echoed_payload) = read_udp_response_payload(stream)?;
    if echoed_payload.len() != payload.len() {
        return Err(OutboundError::BadVless(format!(
            "unexpected VLESS UDP response payload length: got {}, want {}",
            echoed_payload.len(),
            payload.len()
        )));
    }

    Ok(VlessUdpOverTcpExchangeReport {
        proxy: proxy.to_owned(),
        target: target.to_owned(),
        key_hex: hex_encode(key),
        command: VMessNetwork::Udp.byte(),
        payload_len: payload.len(),
        packet_len: 2 + payload.len(),
        echoed_payload,
        response_header_len,
        true_dataplane: true,
        default_go_path: true,
    })
}

pub fn mux_exchange_over_stream<S>(
    stream: &mut S,
    proxy: &str,
    key: &[u8; 16],
    mux_id: [u8; 2],
    target: &str,
    network: &str,
    payload: &[u8],
) -> Result<VlessMuxExchangeReport, OutboundError>
where
    S: Read + Write,
{
    let header = packet::request_header(key, "", "tcp", "0.0.0.0:0", true, &[])?;
    let metadata = VMessMetadata::parse(network, target)?;
    let options = MuxFrameOptions::new(mux_id, metadata.hostname(), metadata.port(), network);
    stream
        .write_all(&header)
        .map_err(|err| OutboundError::BadVless(err.to_string()))?;
    stream
        .write_all(&mux_new_frame(&options))
        .map_err(|err| OutboundError::BadVless(err.to_string()))?;
    stream
        .write_all(&mux_data_frame(mux_id, payload)?)
        .map_err(|err| OutboundError::BadVless(err.to_string()))?;

    let echoed = mux::read_mux_frame(stream)?;
    stream
        .write_all(&mux_end_frame(mux_id))
        .map_err(|err| OutboundError::BadVless(err.to_string()))?;
    if echoed.payload != payload {
        return Err(OutboundError::BadVless(
            "VLESS mux payload response mismatch".to_owned(),
        ));
    }

    Ok(VlessMuxExchangeReport {
        proxy: proxy.to_owned(),
        target: target.to_owned(),
        key_hex: hex_encode(key),
        command: VMessNetwork::Mux.byte(),
        mux_id_hex: hex_encode(&mux_id),
        payload_len: payload.len(),
        echoed_payload: echoed.payload,
        new_frame_validated: true,
        data_frame_validated: true,
        end_frame_sent: true,
        true_dataplane: true,
        default_go_path: true,
    })
}

pub fn tcp_exchange_over_websocket_stream<S>(
    stream: &mut S,
    proxy: &str,
    key: &[u8; 16],
    target: &str,
    ws_host: &str,
    ws_path: &str,
    payload: &[u8],
) -> Result<VlessWebSocketExchangeReport, OutboundError>
where
    S: Read + Write,
{
    let ws_options = HttpUpgradeOptions::new(ws_host, ws_path);
    let handshake = websocket_handshake_request(&ws_options, DEFAULT_WS_KEY);
    stream
        .write_all(&handshake)
        .map_err(|err| OutboundError::BadVless(err.to_string()))?;
    let response = read_http_head(stream)?;
    validate_http_status(&response, 101)?;

    let request = packet::first_write_bytes(key, "", "tcp", target, false, payload)?;
    let request_header_len = request.len().saturating_sub(payload.len());
    let request_frame = websocket_client_binary_frame(&request, WS_MASK_KEY)?;
    stream
        .write_all(&request_frame)
        .map_err(|err| OutboundError::BadVless(err.to_string()))?;

    let response_payload = read_websocket_binary_frame(stream)?;
    let websocket_response_frame_len = response_payload.len();
    let (response_header_len, echoed_payload) = decode_response_payload(&response_payload)?;
    if echoed_payload != payload {
        return Err(OutboundError::BadVless(
            "VLESS WebSocket payload response mismatch".to_owned(),
        ));
    }

    Ok(VlessWebSocketExchangeReport {
        proxy: proxy.to_owned(),
        target: target.to_owned(),
        ws_host: ws_options.host,
        ws_path: ws_options.path,
        key_hex: hex_encode(key),
        command: VMessNetwork::Tcp.byte(),
        request_header_len,
        response_header_len,
        websocket_request_frame_len: request_frame.len(),
        websocket_response_frame_len,
        payload_len: payload.len(),
        echoed_payload,
        websocket_handshake_validated: true,
        websocket_binary_frame_validated: true,
        true_dataplane: true,
        default_go_path: true,
    })
}

pub fn tcp_exchange_over_httpupgrade_stream<S>(
    stream: &mut S,
    proxy: &str,
    key: &[u8; 16],
    target: &str,
    httpupgrade_host: &str,
    httpupgrade_path: &str,
    payload: &[u8],
) -> Result<VlessHttpUpgradeExchangeReport, OutboundError>
where
    S: Read + Write,
{
    let httpupgrade_options = HttpUpgradeOptions::new(httpupgrade_host, httpupgrade_path);
    let upgrade_request = http_upgrade_request(&httpupgrade_options);
    stream
        .write_all(&upgrade_request)
        .map_err(|err| OutboundError::BadVless(err.to_string()))?;
    let response = read_http_head(stream)?;
    validate_http_status(&response, 101)?;

    let request = packet::first_write_bytes(key, "", "tcp", target, false, payload)?;
    let request_header_len = request.len().saturating_sub(payload.len());
    stream
        .write_all(&request)
        .map_err(|err| OutboundError::BadVless(err.to_string()))?;

    let (response_header_len, echoed_payload) =
        read_tcp_response_payload_from_stream(stream, payload.len())?;
    if echoed_payload != payload {
        return Err(OutboundError::BadVless(
            "VLESS HTTPUpgrade payload response mismatch".to_owned(),
        ));
    }

    Ok(VlessHttpUpgradeExchangeReport {
        proxy: proxy.to_owned(),
        target: target.to_owned(),
        httpupgrade_host: httpupgrade_options.host,
        httpupgrade_path: httpupgrade_options.path,
        key_hex: hex_encode(key),
        command: VMessNetwork::Tcp.byte(),
        request_header_len,
        response_header_len,
        httpupgrade_request_len: upgrade_request.len(),
        httpupgrade_response_head_len: response.len(),
        payload_len: payload.len(),
        echoed_payload,
        httpupgrade_handshake_validated: true,
        true_dataplane: true,
        default_go_path: true,
    })
}

pub fn tcp_exchange_over_grpc_hunk_stream<S>(
    stream: &mut S,
    proxy: &str,
    key: &[u8; 16],
    target: &str,
    grpc_options: &GrpcLifecycleOptions,
    payload: &[u8],
) -> Result<VlessGrpcHunkExchangeReport, OutboundError>
where
    S: Read + Write,
{
    let preface = grpc_stream_preface(&grpc_options.service_name);
    stream
        .write_all(&preface)
        .map_err(|err| OutboundError::BadVless(err.to_string()))?;

    let request = packet::first_write_bytes(key, "", "tcp", target, false, payload)?;
    let request_header_len = request.len().saturating_sub(payload.len());
    let request_hunk = grpc_hunk_frame(&request)?;
    stream
        .write_all(&request_hunk)
        .map_err(|err| OutboundError::BadVless(err.to_string()))?;

    let response_payload = read_grpc_hunk_frame(stream)?;
    let grpc_response_hunk_len = response_payload.len() + 5;
    let (response_header_len, echoed_payload) = decode_response_payload(&response_payload)?;
    if echoed_payload != payload {
        return Err(OutboundError::BadVless(
            "VLESS gRPC hunk payload response mismatch".to_owned(),
        ));
    }

    Ok(VlessGrpcHunkExchangeReport {
        proxy: proxy.to_owned(),
        target: target.to_owned(),
        grpc_service_name: if grpc_options.service_name.is_empty() {
            "GunService".to_owned()
        } else {
            grpc_options.service_name.clone()
        },
        grpc_cache_key: grpc_options.cache_key(),
        key_hex: hex_encode(key),
        command: VMessNetwork::Tcp.byte(),
        request_header_len,
        response_header_len,
        grpc_preface_len: preface.len(),
        grpc_request_hunk_len: request_hunk.len(),
        grpc_response_hunk_len,
        payload_len: payload.len(),
        echoed_payload,
        grpc_stream_preface_validated: true,
        grpc_hunk_frame_validated: true,
        cache_key_route_context_validated: true,
        full_grpc_http2_stack: false,
        true_dataplane: true,
        default_go_path: true,
    })
}

pub fn tcp_exchange_over_meek_polling_stream<S>(
    stream: &mut S,
    proxy: &str,
    key: &[u8; 16],
    target: &str,
    meek_options: &MeekRoundTripOptions,
    payload: &[u8],
) -> Result<VlessMeekPollingExchangeReport, OutboundError>
where
    S: Read + Write,
{
    let request = packet::first_write_bytes(key, "", "tcp", target, false, payload)?;
    let request_header_len = request.len().saturating_sub(payload.len());
    let meek_request = meek_http_request(meek_options, &request);
    stream
        .write_all(&meek_request)
        .map_err(|err| OutboundError::BadVless(err.to_string()))?;

    let (response_head, response_payload) = read_http_message(stream, "meek response")?;
    validate_http_status(&response_head, 200)?;
    let (response_header_len, echoed_payload) = decode_response_payload(&response_payload)?;
    if echoed_payload != payload {
        return Err(OutboundError::BadVless(
            "VLESS Meek polling payload response mismatch".to_owned(),
        ));
    }

    Ok(VlessMeekPollingExchangeReport {
        proxy: proxy.to_owned(),
        target: target.to_owned(),
        meek_url: meek_options.url.clone(),
        meek_host: meek_options.host.clone(),
        meek_path: meek_options.path.clone(),
        meek_session_id: meek_options.session_id(),
        key_hex: hex_encode(key),
        command: VMessNetwork::Tcp.byte(),
        request_header_len,
        response_header_len,
        meek_request_len: meek_request.len(),
        meek_request_body_len: request.len(),
        meek_response_head_len: response_head.len(),
        meek_response_body_len: response_payload.len(),
        payload_len: payload.len(),
        echoed_payload,
        meek_polling_validated: true,
        meek_session_id_validated: true,
        full_https_round_tripper: false,
        true_dataplane: true,
        default_go_path: true,
    })
}

pub fn tcp_exchange_over_http_transport_stream<S>(
    stream: &mut S,
    proxy: &str,
    key: &[u8; 16],
    target: &str,
    http_options: &HttpConnectOptions,
    payload: &[u8],
) -> Result<VlessHttpTransportExchangeReport, OutboundError>
where
    S: Read + Write,
{
    if !http_options.transport.enabled {
        return Err(OutboundError::BadVless(
            "VLESS HTTP transport requires HttpConnectOptions.transport.enabled=true".to_owned(),
        ));
    }
    let transport_request = http_proxy_request::connect_request(http_options);
    stream
        .write_all(&transport_request)
        .map_err(|err| OutboundError::BadVless(err.to_string()))?;
    let response = read_http_head(stream)?;
    let http_transport_response_head_len = response.len();
    let status = http_proxy_request::parse_connect_response(&response)?;
    if status != 200 {
        return Err(OutboundError::BadVless(format!(
            "VLESS HTTP transport status: {status}"
        )));
    }

    let request = packet::first_write_bytes(key, "", "tcp", target, false, payload)?;
    let request_header_len = request.len().saturating_sub(payload.len());
    stream
        .write_all(&request)
        .map_err(|err| OutboundError::BadVless(err.to_string()))?;

    let (response_header_len, echoed_payload) =
        read_tcp_response_payload_from_stream(stream, payload.len())?;
    if echoed_payload != payload {
        return Err(OutboundError::BadVless(
            "VLESS HTTP transport payload response mismatch".to_owned(),
        ));
    }

    Ok(VlessHttpTransportExchangeReport {
        proxy: proxy.to_owned(),
        target: target.to_owned(),
        http_transport_host: http_transport_host(http_options),
        http_transport_path: http_transport_path(http_options),
        key_hex: hex_encode(key),
        command: VMessNetwork::Tcp.byte(),
        request_header_len,
        response_header_len,
        http_transport_request_len: transport_request.len(),
        http_transport_response_head_len,
        payload_len: payload.len(),
        echoed_payload,
        http_transport_put_validated: true,
        full_http2_stack: false,
        true_dataplane: true,
        default_go_path: true,
    })
}

pub fn tcp_exchange_over_xhttp_packet_stream<S>(
    stream: &mut S,
    proxy: &str,
    key: &[u8; 16],
    target: &str,
    xhttp_options: &XHttpLifecycleOptions,
    payload: &[u8],
) -> Result<VlessXHttpPacketExchangeReport, OutboundError>
where
    S: Read + Write,
{
    if xhttp_options.mode != "packet-up" {
        return Err(OutboundError::BadVless(format!(
            "VLESS xHTTP packet exchange requires packet-up mode, got {}",
            xhttp_options.mode
        )));
    }
    let request = packet::first_write_bytes(key, "", "tcp", target, false, payload)?;
    let request_header_len = request.len().saturating_sub(payload.len());
    let xhttp_request = xhttp_packet_request(xhttp_options, &request);
    stream
        .write_all(&xhttp_request)
        .map_err(|err| OutboundError::BadVless(err.to_string()))?;

    let (response_head, response_payload) = read_http_message(stream, "xhttp response")?;
    validate_http_status(&response_head, 200)?;
    let (response_header_len, echoed_payload) = decode_response_payload(&response_payload)?;
    if echoed_payload != payload {
        return Err(OutboundError::BadVless(
            "VLESS xHTTP packet payload response mismatch".to_owned(),
        ));
    }

    Ok(VlessXHttpPacketExchangeReport {
        proxy: proxy.to_owned(),
        target: target.to_owned(),
        xhttp_host: xhttp_options.host.clone(),
        xhttp_path: crate::shared_transport::ir::normalize_xhttp_path_and_query(
            &xhttp_options.path,
        )
        .path,
        xhttp_request_path: xhttp_request_path(xhttp_options),
        xhttp_mode: xhttp_options.mode.clone(),
        xhttp_alpn: xhttp_options.alpn.clone(),
        key_hex: hex_encode(key),
        command: VMessNetwork::Tcp.byte(),
        request_header_len,
        response_header_len,
        xhttp_request_len: xhttp_request.len(),
        xhttp_request_body_len: request.len(),
        xhttp_response_head_len: response_head.len(),
        xhttp_response_body_len: response_payload.len(),
        payload_len: payload.len(),
        echoed_payload,
        xhttp_packet_up_validated: true,
        xhttp_xmux_enabled: false,
        full_h2_h3_stack: false,
        true_dataplane: true,
        default_go_path: true,
    })
}

pub fn read_tcp_request_from_stream<S>(
    stream: &mut S,
    payload_len: usize,
) -> Result<VlessTcpRequest, OutboundError>
where
    S: Read,
{
    let header = read_request_header(stream)?;
    if header.command != VMessNetwork::Tcp.byte() {
        return Err(OutboundError::BadVless(format!(
            "unexpected VLESS TCP command: {}",
            header.command
        )));
    }

    let mut payload = vec![0_u8; payload_len];
    read_exact(stream, &mut payload, "vless payload")?;
    Ok(VlessTcpRequest {
        version: header.version,
        key: header.key,
        key_hex: header.key_hex,
        addons_len: header.addons_len,
        command: header.command,
        target: header.target,
        payload,
        header_len: header.header_len,
    })
}

pub fn read_udp_request_from_stream<S>(stream: &mut S) -> Result<VlessUdpRequest, OutboundError>
where
    S: Read,
{
    let header = read_request_header(stream)?;
    if header.command != VMessNetwork::Udp.byte() {
        return Err(OutboundError::BadVless(format!(
            "unexpected VLESS UDP command: {}",
            header.command
        )));
    }

    let mut length = [0_u8; 2];
    read_exact(stream, &mut length, "vless udp payload length")?;
    let payload_len = u16::from_be_bytes(length) as usize;
    let mut payload = vec![0_u8; payload_len];
    read_exact(stream, &mut payload, "vless udp payload")?;
    Ok(VlessUdpRequest {
        version: header.version,
        key: header.key,
        key_hex: header.key_hex,
        addons_len: header.addons_len,
        command: header.command,
        target: header.target,
        payload_len,
        payload,
        header_len: header.header_len,
        packet_len: 2 + payload_len,
    })
}

pub fn read_mux_request_from_stream<S>(stream: &mut S) -> Result<VlessMuxRequest, OutboundError>
where
    S: Read,
{
    let mut version = [0_u8; 1];
    read_exact(stream, &mut version, "vless mux version")?;
    if version[0] != VLESS_VERSION {
        return Err(OutboundError::BadVless(format!(
            "unexpected VLESS mux version: {}",
            version[0]
        )));
    }

    let mut key = [0_u8; 16];
    read_exact(stream, &mut key, "vless mux key")?;

    let mut addons_len = [0_u8; 1];
    read_exact(stream, &mut addons_len, "vless mux addons length")?;
    let addons_len = addons_len[0] as usize;
    let mut addons = vec![0_u8; addons_len];
    read_exact(stream, &mut addons, "vless mux addons")?;

    let mut command = [0_u8; 1];
    read_exact(stream, &mut command, "vless mux command")?;
    if command[0] != VMessNetwork::Mux.byte() {
        return Err(OutboundError::BadVless(format!(
            "unexpected VLESS mux command: {}",
            command[0]
        )));
    }

    Ok(VlessMuxRequest {
        version: version[0],
        key,
        key_hex: hex_encode(&key),
        addons_len,
        command: command[0],
        header_len: 1 + 16 + 1 + addons_len + 1,
    })
}

pub fn read_tcp_request_from_websocket_stream<S>(
    stream: &mut S,
    payload_len: usize,
) -> Result<VlessWebSocketRequest, OutboundError>
where
    S: Read,
{
    let payload = read_websocket_binary_frame(stream)?;
    let websocket_request_frame_len = payload.len();
    let mut cursor = Cursor::new(payload);
    let request = read_tcp_request_from_stream(&mut cursor, payload_len)?;
    if cursor.position() as usize != websocket_request_frame_len {
        return Err(OutboundError::BadVless(format!(
            "VLESS WebSocket request has trailing bytes: {}",
            websocket_request_frame_len - cursor.position() as usize
        )));
    }
    Ok(VlessWebSocketRequest {
        request,
        websocket_request_frame_len,
    })
}

pub fn read_tcp_request_from_grpc_hunk_stream<S>(
    stream: &mut S,
    payload_len: usize,
) -> Result<VlessGrpcHunkRequest, OutboundError>
where
    S: Read,
{
    let payload = read_grpc_hunk_frame(stream)?;
    let grpc_request_hunk_len = payload.len() + 5;
    let mut cursor = Cursor::new(&payload);
    let request = read_tcp_request_from_stream(&mut cursor, payload_len)?;
    if cursor.position() as usize != payload.len() {
        return Err(OutboundError::BadVless(format!(
            "VLESS gRPC hunk request has trailing bytes: {}",
            payload.len() - cursor.position() as usize
        )));
    }
    Ok(VlessGrpcHunkRequest {
        request,
        grpc_request_hunk_len,
    })
}

pub fn read_tcp_request_from_meek_polling_stream<S>(
    stream: &mut S,
    payload_len: usize,
    meek_options: &MeekRoundTripOptions,
) -> Result<VlessMeekPollingRequest, OutboundError>
where
    S: Read,
{
    let (request_head, payload) = read_http_message(stream, "meek request")?;
    validate_meek_request_head(&request_head, meek_options)?;
    let mut cursor = Cursor::new(&payload);
    let request = read_tcp_request_from_stream(&mut cursor, payload_len)?;
    if cursor.position() as usize != payload.len() {
        return Err(OutboundError::BadVless(format!(
            "VLESS Meek polling request has trailing bytes: {}",
            payload.len() - cursor.position() as usize
        )));
    }
    Ok(VlessMeekPollingRequest {
        request,
        meek_request_body_len: payload.len(),
        meek_session_id_validated: true,
    })
}

pub fn read_http_transport_request_head_from_stream<S>(
    stream: &mut S,
    http_options: &HttpConnectOptions,
) -> Result<VlessHttpTransportRequestHead, OutboundError>
where
    S: Read,
{
    if !http_options.transport.enabled {
        return Err(OutboundError::BadVless(
            "VLESS HTTP transport request requires transport.enabled=true".to_owned(),
        ));
    }
    let request_head = read_http_head(stream)?;
    validate_http_transport_request_head(&request_head, http_options)
}

pub fn read_tcp_request_from_xhttp_packet_stream<S>(
    stream: &mut S,
    payload_len: usize,
    xhttp_options: &XHttpLifecycleOptions,
) -> Result<VlessXHttpPacketRequest, OutboundError>
where
    S: Read,
{
    let (request_head, payload) = read_http_message(stream, "xhttp request")?;
    let request_path =
        validate_xhttp_packet_request_head(&request_head, payload.len(), xhttp_options)?;
    let mut cursor = Cursor::new(&payload);
    let request = read_tcp_request_from_stream(&mut cursor, payload_len)?;
    if cursor.position() as usize != payload.len() {
        return Err(OutboundError::BadVless(format!(
            "VLESS xHTTP packet request has trailing bytes: {}",
            payload.len() - cursor.position() as usize
        )));
    }
    Ok(VlessXHttpPacketRequest {
        request,
        xhttp_request_body_len: payload.len(),
        xhttp_request_path: request_path,
        xhttp_packet_up_validated: true,
    })
}

pub fn response_header_bytes() -> [u8; 2] {
    [VLESS_VERSION, 0]
}

pub fn udp_response_packet(payload: &[u8]) -> Result<Vec<u8>, OutboundError> {
    if payload.len() > u16::MAX as usize {
        return Err(OutboundError::BadVless(format!(
            "vless udp payload too long: {} bytes",
            payload.len()
        )));
    }
    let mut out = Vec::with_capacity(2 + 2 + payload.len());
    out.extend_from_slice(&response_header_bytes());
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

pub fn response_payload_bytes(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + payload.len());
    out.extend_from_slice(&response_header_bytes());
    out.extend_from_slice(payload);
    out
}

fn read_http_message<S: Read>(
    stream: &mut S,
    context: &str,
) -> Result<(Vec<u8>, Vec<u8>), OutboundError> {
    let head_with_leftover = read_http_head(stream)?;
    let Some(index) = head_with_leftover
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
    else {
        return Err(OutboundError::BadSharedTransport(format!(
            "incomplete {context} header"
        )));
    };
    let body_start = index + 4;
    let head = head_with_leftover[..body_start].to_vec();
    let mut body = head_with_leftover[body_start..].to_vec();
    let content_length = http_content_length(&head)?;
    while body.len() < content_length {
        let mut buf = vec![0_u8; content_length - body.len()];
        let n = stream
            .read(&mut buf)
            .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&buf[..n]);
    }
    if body.len() < content_length {
        return Err(OutboundError::BadSharedTransport(format!(
            "incomplete {context} body"
        )));
    }
    body.truncate(content_length);
    Ok((head, body))
}

fn validate_meek_request_head(
    request_head: &[u8],
    meek_options: &MeekRoundTripOptions,
) -> Result<(), OutboundError> {
    let text = std::str::from_utf8(request_head)
        .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
    let mut lines = text.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| OutboundError::BadSharedTransport("empty meek request".to_owned()))?;
    let want = format!("POST {} HTTP/1.1", meek_options.path);
    if request_line != want {
        return Err(OutboundError::BadSharedTransport(format!(
            "unexpected meek request line: {request_line}"
        )));
    }
    let host = http_header_value(text, "host")
        .ok_or_else(|| OutboundError::BadSharedTransport("missing meek Host header".to_owned()))?;
    if host != meek_options.host {
        return Err(OutboundError::BadSharedTransport(format!(
            "unexpected meek Host header: {host}"
        )));
    }
    let session = http_header_value(text, "x-session-id").ok_or_else(|| {
        OutboundError::BadSharedTransport("missing meek X-Session-ID header".to_owned())
    })?;
    if session != meek_options.session_id() {
        return Err(OutboundError::BadSharedTransport(format!(
            "unexpected meek X-Session-ID header: {session}"
        )));
    }
    Ok(())
}

fn validate_http_transport_request_head(
    request_head: &[u8],
    http_options: &HttpConnectOptions,
) -> Result<VlessHttpTransportRequestHead, OutboundError> {
    let text = std::str::from_utf8(request_head)
        .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
    let mut lines = text.split("\r\n");
    let request_line = lines.next().ok_or_else(|| {
        OutboundError::BadSharedTransport("empty http transport request".to_owned())
    })?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let request_uri = parts.next().unwrap_or_default();
    let version = parts.next().unwrap_or_default();
    if method != "PUT" || version != "HTTP/1.1" {
        return Err(OutboundError::BadSharedTransport(format!(
            "unexpected http transport request line: {request_line}"
        )));
    }
    let host = http_transport_host(http_options);
    let path = http_transport_path(http_options);
    let want_uri = format!("http://{host}{path}");
    if request_uri != want_uri {
        return Err(OutboundError::BadSharedTransport(format!(
            "unexpected http transport uri: {request_uri}"
        )));
    }
    let got_host = http_header_value(text, "host").ok_or_else(|| {
        OutboundError::BadSharedTransport("missing http transport Host header".to_owned())
    })?;
    if got_host != host {
        return Err(OutboundError::BadSharedTransport(format!(
            "unexpected http transport Host header: {got_host}"
        )));
    }
    let content_length = http_header_value(text, "content-length").ok_or_else(|| {
        OutboundError::BadSharedTransport("missing http transport Content-Length header".to_owned())
    })?;
    if content_length != "0" {
        return Err(OutboundError::BadSharedTransport(format!(
            "unexpected http transport Content-Length: {content_length}"
        )));
    }
    Ok(VlessHttpTransportRequestHead {
        method: method.to_owned(),
        request_uri: request_uri.to_owned(),
        host,
        path,
        request_head_len: request_head.len(),
        transport_enabled: true,
    })
}

fn validate_xhttp_packet_request_head(
    request_head: &[u8],
    body_len: usize,
    xhttp_options: &XHttpLifecycleOptions,
) -> Result<String, OutboundError> {
    let text = std::str::from_utf8(request_head)
        .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
    let mut lines = text.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| OutboundError::BadSharedTransport("empty xhttp request".to_owned()))?;
    let request_path = xhttp_request_path(xhttp_options);
    let want = format!("POST {request_path} HTTP/1.1");
    if request_line != want {
        return Err(OutboundError::BadSharedTransport(format!(
            "unexpected xhttp request line: {request_line}"
        )));
    }
    let host = http_header_value(text, "host")
        .ok_or_else(|| OutboundError::BadSharedTransport("missing xhttp Host header".to_owned()))?;
    if host != xhttp_options.host {
        return Err(OutboundError::BadSharedTransport(format!(
            "unexpected xhttp Host header: {host}"
        )));
    }
    let mode = http_header_value(text, "x-dae-xhttp-mode")
        .ok_or_else(|| OutboundError::BadSharedTransport("missing xhttp mode header".to_owned()))?;
    if mode != xhttp_options.mode {
        return Err(OutboundError::BadSharedTransport(format!(
            "unexpected xhttp mode header: {mode}"
        )));
    }
    let alpn = http_header_value(text, "x-dae-xhttp-alpn")
        .ok_or_else(|| OutboundError::BadSharedTransport("missing xhttp alpn header".to_owned()))?;
    if alpn != xhttp_options.alpn {
        return Err(OutboundError::BadSharedTransport(format!(
            "unexpected xhttp alpn header: {alpn}"
        )));
    }
    let content_length = http_header_value(text, "content-length").ok_or_else(|| {
        OutboundError::BadSharedTransport("missing xhttp Content-Length header".to_owned())
    })?;
    if content_length != body_len.to_string() {
        return Err(OutboundError::BadSharedTransport(format!(
            "unexpected xhttp Content-Length: {content_length}"
        )));
    }
    Ok(request_path)
}

fn read_request_header(stream: &mut impl Read) -> Result<VlessRequestHeader, OutboundError> {
    let mut version = [0_u8; 1];
    read_exact(stream, &mut version, "vless version")?;
    if version[0] != VLESS_VERSION {
        return Err(OutboundError::BadVless(format!(
            "unexpected VLESS version: {}",
            version[0]
        )));
    }

    let mut key = [0_u8; 16];
    read_exact(stream, &mut key, "vless key")?;

    let mut addons_len = [0_u8; 1];
    read_exact(stream, &mut addons_len, "vless addons length")?;
    let addons_len = addons_len[0] as usize;
    let mut addons = vec![0_u8; addons_len];
    read_exact(stream, &mut addons, "vless addons")?;

    let mut command = [0_u8; 1];
    read_exact(stream, &mut command, "vless command")?;

    let mut port = [0_u8; 2];
    read_exact(stream, &mut port, "vless target port")?;
    let port = u16::from_be_bytes(port);

    let mut atyp = [0_u8; 1];
    read_exact(stream, &mut atyp, "vless target address type")?;
    let (host, addr_len) = read_vless_host(stream, atyp[0])?;
    let target = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };

    Ok(VlessRequestHeader {
        version: version[0],
        key,
        key_hex: hex_encode(&key),
        addons_len,
        command: command[0],
        target,
        header_len: 1 + 16 + 1 + addons_len + 1 + 2 + 1 + addr_len,
    })
}

fn decode_response_payload(input: &[u8]) -> Result<(usize, Vec<u8>), OutboundError> {
    if input.len() < 2 {
        return Err(OutboundError::BadVless(
            "VLESS response header missing".to_owned(),
        ));
    }
    if input[0] != VLESS_VERSION {
        return Err(OutboundError::BadVless(format!(
            "unexpected VLESS response version: {}",
            input[0]
        )));
    }
    let addons_len = input[1] as usize;
    let response_header_len = 2 + addons_len;
    if input.len() < response_header_len {
        return Err(OutboundError::BadVless(
            "VLESS response addons truncated".to_owned(),
        ));
    }
    Ok((response_header_len, input[response_header_len..].to_vec()))
}

fn http_content_length(head: &[u8]) -> Result<usize, OutboundError> {
    let text = std::str::from_utf8(head)
        .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
    http_header_value(text, "content-length")
        .unwrap_or("0")
        .parse::<usize>()
        .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))
}

fn http_header_value<'a>(head: &'a str, key: &str) -> Option<&'a str> {
    for line in head.split("\r\n") {
        let Some((got_key, value)) = line.split_once(':') else {
            continue;
        };
        if got_key.eq_ignore_ascii_case(key) {
            return Some(value.trim());
        }
    }
    None
}

fn http_transport_host(options: &HttpConnectOptions) -> String {
    if options.host_override.is_empty() {
        "www.example.com".to_owned()
    } else {
        options.host_override.clone()
    }
}

fn http_transport_path(options: &HttpConnectOptions) -> String {
    if options.transport.path.is_empty() {
        "/".to_owned()
    } else {
        options.transport.path.clone()
    }
}

fn read_udp_response_payload(stream: &mut impl Read) -> Result<(usize, Vec<u8>), OutboundError> {
    let mut version = [0_u8; 1];
    read_exact(stream, &mut version, "vless response version")?;
    if version[0] != VLESS_VERSION {
        return Err(OutboundError::BadVless(format!(
            "unexpected VLESS response version: {}",
            version[0]
        )));
    }
    let mut addons_len = [0_u8; 1];
    read_exact(stream, &mut addons_len, "vless response addons length")?;
    let addons_len = addons_len[0] as usize;
    let mut addons = vec![0_u8; addons_len];
    read_exact(stream, &mut addons, "vless response addons")?;

    let mut length = [0_u8; 2];
    read_exact(stream, &mut length, "vless udp response payload length")?;
    let payload_len = u16::from_be_bytes(length) as usize;
    let mut payload = vec![0_u8; payload_len];
    read_exact(stream, &mut payload, "vless udp response payload")?;
    Ok((2 + addons_len, payload))
}

fn read_tcp_response_payload_from_stream(
    stream: &mut impl Read,
    payload_len: usize,
) -> Result<(usize, Vec<u8>), OutboundError> {
    let mut version = [0_u8; 1];
    read_exact(stream, &mut version, "vless response version")?;
    if version[0] != VLESS_VERSION {
        return Err(OutboundError::BadVless(format!(
            "unexpected VLESS response version: {}",
            version[0]
        )));
    }
    let mut addons_len = [0_u8; 1];
    read_exact(stream, &mut addons_len, "vless response addons length")?;
    let addons_len = addons_len[0] as usize;
    let mut addons = vec![0_u8; addons_len];
    read_exact(stream, &mut addons, "vless response addons")?;

    let mut payload = vec![0_u8; payload_len];
    read_exact(stream, &mut payload, "vless response payload")?;
    Ok((2 + addons_len, payload))
}

fn read_vless_host(stream: &mut impl Read, atyp: u8) -> Result<(String, usize), OutboundError> {
    match atyp {
        1 => {
            let mut octets = [0_u8; 4];
            read_exact(stream, &mut octets, "vless ipv4 target")?;
            Ok((Ipv4Addr::from(octets).to_string(), 4))
        }
        2 => {
            let mut len = [0_u8; 1];
            read_exact(stream, &mut len, "vless domain length")?;
            let mut host = vec![0_u8; len[0] as usize];
            read_exact(stream, &mut host, "vless domain target")?;
            let host =
                String::from_utf8(host).map_err(|err| OutboundError::BadVless(err.to_string()))?;
            Ok((host, 1 + len[0] as usize))
        }
        3 => {
            let mut octets = [0_u8; 16];
            read_exact(stream, &mut octets, "vless ipv6 target")?;
            Ok((Ipv6Addr::from(octets).to_string(), 16))
        }
        value => Err(OutboundError::BadVless(format!(
            "bad VLESS address type: {value}"
        ))),
    }
}

fn read_exact(stream: &mut impl Read, buf: &mut [u8], context: &str) -> Result<(), OutboundError> {
    stream
        .read_exact(buf)
        .map_err(|err| OutboundError::BadVless(format!("read {context} failed: {err}")))
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}
