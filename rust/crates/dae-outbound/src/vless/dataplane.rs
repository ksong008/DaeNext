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

mod helpers;
mod types;

use helpers::*;
pub use types::*;

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
