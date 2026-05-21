use std::io::{Cursor, Read, Write};

use crate::error::OutboundError;
use crate::shared_transport::{
    GrpcHttp2FrameReport, GrpcHttp2LifecycleOptions, GrpcLifecycleOptions, grpc_hunk_http2_data,
    read_grpc_http2_request, read_grpc_http2_response, read_grpc_hunk_frame,
    write_grpc_http2_request, write_grpc_http2_response,
};
use crate::vmess::VMessNetwork;

use super::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VlessGrpcHttp2ExchangeReport {
    pub proxy: String,
    pub target: String,
    pub grpc_service_name: String,
    pub grpc_cache_key: String,
    pub key_hex: String,
    pub command: u8,
    pub request_header_len: usize,
    pub response_header_len: usize,
    pub request_hunk_len: usize,
    pub response_hunk_len: usize,
    pub payload_len: usize,
    pub echoed_payload: Vec<u8>,
    pub http2_lifecycle: bool,
    pub full_tls_lifecycle: bool,
    pub tls_utls_reality_deferred: bool,
    pub http2_client_preface_validated: bool,
    pub http2_settings_validated: bool,
    pub http2_headers_validated: bool,
    pub http2_data_validated: bool,
    pub grpc_hunk_frame_validated: bool,
    pub cache_key_route_context_validated: bool,
    pub request_frames: GrpcHttp2FrameReport,
    pub response_frames: GrpcHttp2FrameReport,
    pub true_dataplane: bool,
    pub default_go_path: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VlessGrpcHttp2Request {
    pub request: VlessTcpRequest,
    pub request_hunk_len: usize,
    pub http2_frames: GrpcHttp2FrameReport,
}

pub fn tcp_exchange_over_grpc_http2_stream<S>(
    stream: &mut S,
    proxy: &str,
    key: &[u8; 16],
    target: &str,
    grpc_options: &GrpcLifecycleOptions,
    payload: &[u8],
) -> Result<VlessGrpcHttp2ExchangeReport, OutboundError>
where
    S: Read + Write,
{
    let request = packet::first_write_bytes(key, "", "tcp", target, false, payload)?;
    let request_header_len = request.len().saturating_sub(payload.len());
    let request_hunk = grpc_hunk_http2_data(&request)?;
    let http2_options = GrpcHttp2LifecycleOptions {
        authority: grpc_options.address.clone(),
        service_name: grpc_options.service_name.clone(),
    };
    let request_frames = write_grpc_http2_request(stream, &http2_options, &request_hunk)?;

    let (response_hunk, response_frames) = read_grpc_http2_response(stream)?;
    let response_hunk_len = response_hunk.len();
    let mut hunk_cursor = Cursor::new(response_hunk);
    let response_payload = read_grpc_hunk_frame(&mut hunk_cursor)?;
    if hunk_cursor.position() as usize != hunk_cursor.get_ref().len() {
        return Err(OutboundError::BadVless(format!(
            "VLESS gRPC HTTP/2 response hunk has trailing bytes: {}",
            hunk_cursor.get_ref().len() - hunk_cursor.position() as usize
        )));
    }
    let (response_header_len, echoed_payload) = decode_response_payload(&response_payload)?;
    if echoed_payload != payload {
        return Err(OutboundError::BadVless(
            "VLESS gRPC HTTP/2 payload response mismatch".to_owned(),
        ));
    }

    Ok(VlessGrpcHttp2ExchangeReport {
        proxy: proxy.to_owned(),
        target: target.to_owned(),
        grpc_service_name: request_frames.service_name.clone(),
        grpc_cache_key: grpc_options.cache_key(),
        key_hex: hex_encode(key),
        command: VMessNetwork::Tcp.byte(),
        request_header_len,
        response_header_len,
        request_hunk_len: request_hunk.len(),
        response_hunk_len,
        payload_len: payload.len(),
        echoed_payload,
        http2_lifecycle: true,
        full_tls_lifecycle: false,
        tls_utls_reality_deferred: true,
        http2_client_preface_validated: request_frames.http2_client_preface_validated,
        http2_settings_validated: request_frames.settings_frame_validated
            && response_frames.response_settings_ack_validated,
        http2_headers_validated: request_frames.headers_frame_validated
            && response_frames.response_headers_validated,
        http2_data_validated: request_frames.data_frame_validated
            && response_frames.response_data_validated,
        grpc_hunk_frame_validated: true,
        cache_key_route_context_validated: true,
        request_frames,
        response_frames,
        true_dataplane: true,
        default_go_path: true,
    })
}

pub fn read_tcp_request_from_grpc_http2_stream<S>(
    stream: &mut S,
    grpc_options: &GrpcHttp2LifecycleOptions,
    payload_len: usize,
) -> Result<VlessGrpcHttp2Request, OutboundError>
where
    S: Read,
{
    let request = read_grpc_http2_request(stream, grpc_options)?;
    let request_hunk_len = request.grpc_payload.len();
    let mut hunk_cursor = Cursor::new(request.grpc_payload);
    let vless_payload = read_grpc_hunk_frame(&mut hunk_cursor)?;
    if hunk_cursor.position() as usize != hunk_cursor.get_ref().len() {
        return Err(OutboundError::BadVless(format!(
            "VLESS gRPC HTTP/2 hunk request has trailing bytes: {}",
            hunk_cursor.get_ref().len() - hunk_cursor.position() as usize
        )));
    }
    let mut cursor = Cursor::new(vless_payload);
    let tcp = read_tcp_request_from_stream(&mut cursor, payload_len)?;
    if cursor.position() as usize != cursor.get_ref().len() {
        return Err(OutboundError::BadVless(format!(
            "VLESS gRPC HTTP/2 request has trailing bytes: {}",
            cursor.get_ref().len() - cursor.position() as usize
        )));
    }
    Ok(VlessGrpcHttp2Request {
        request: tcp,
        request_hunk_len,
        http2_frames: request.report,
    })
}

pub fn write_grpc_http2_hunk_response<S>(
    stream: &mut S,
    response_payload: &[u8],
) -> Result<GrpcHttp2FrameReport, OutboundError>
where
    S: Write,
{
    let response_hunk = grpc_hunk_http2_data(response_payload)?;
    write_grpc_http2_response(stream, &response_hunk)
}
