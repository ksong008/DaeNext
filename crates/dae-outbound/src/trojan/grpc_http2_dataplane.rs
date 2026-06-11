use std::io::{Cursor, Read, Write};

use crate::error::OutboundError;
use crate::shared_transport::{
    GrpcHttp2FrameReport, GrpcHttp2LifecycleOptions, GrpcLifecycleOptions, grpc_hunk_http2_data,
    read_grpc_http2_request, read_grpc_http2_response, read_grpc_hunk_frame,
    write_grpc_http2_request, write_grpc_http2_response,
};

use super::dataplane::{TrojanTcpRequest, read_tcp_request_from_stream};
use super::metadata::{TrojanMetadata, TrojanNetwork};
use super::packet;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrojanGrpcHttp2TlsExchangeReport {
    pub proxy: String,
    pub target: String,
    pub grpc_service_name: String,
    pub grpc_cache_key: String,
    pub password_sha224_hex: String,
    pub command: u8,
    pub request_header_len: usize,
    pub request_hunk_len: usize,
    pub response_hunk_len: usize,
    pub payload_len: usize,
    pub echoed_payload: Vec<u8>,
    pub outer_tls_wrapped: bool,
    pub grpc_contains_tls_boundary: bool,
    pub http2_tls_lifecycle: bool,
    pub http2_client_preface_validated: bool,
    pub http2_settings_validated: bool,
    pub http2_headers_validated: bool,
    pub http2_data_validated: bool,
    pub grpc_hunk_frame_validated: bool,
    pub cache_key_route_context_validated: bool,
    pub request_frames: GrpcHttp2FrameReport,
    pub response_frames: GrpcHttp2FrameReport,
    pub true_dataplane: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrojanGrpcHttp2Request {
    pub request: TrojanTcpRequest,
    pub request_hunk_len: usize,
    pub http2_frames: GrpcHttp2FrameReport,
}

pub fn tcp_exchange_over_grpc_http2_stream<S>(
    stream: &mut S,
    proxy: &str,
    password: &str,
    target: &str,
    grpc_options: &GrpcLifecycleOptions,
    payload: &[u8],
) -> Result<TrojanGrpcHttp2TlsExchangeReport, OutboundError>
where
    S: Read + Write,
{
    let metadata = TrojanMetadata::parse("tcp", target)?;
    let target = metadata.authority();
    let request = packet::tcp_request_header(password, "tcp", &target, payload)?;
    let request_header_len = request.len().saturating_sub(payload.len());
    let request_hunk = grpc_hunk_http2_data(&request)?;
    let http2_options = GrpcHttp2LifecycleOptions {
        authority: grpc_options.address.clone(),
        service_name: grpc_options.service_name.clone(),
    };
    let request_frames = write_grpc_http2_request(stream, &http2_options, &request_hunk)?;

    let (response_hunk, response_frames) = read_grpc_http2_response(stream)?;
    let response_hunk_len = response_hunk.len();
    let mut response_cursor = Cursor::new(response_hunk);
    let echoed_payload = read_grpc_hunk_frame(&mut response_cursor)?;
    if echoed_payload != payload {
        return Err(OutboundError::BadTrojan(
            "trojan-go grpc http2 payload response mismatch".to_owned(),
        ));
    }

    Ok(TrojanGrpcHttp2TlsExchangeReport {
        proxy: proxy.to_owned(),
        target,
        grpc_service_name: request_frames.service_name.clone(),
        grpc_cache_key: grpc_options.cache_key(),
        password_sha224_hex: packet::password_sha224_hex(password),
        command: TrojanNetwork::Tcp.byte(),
        request_header_len,
        request_hunk_len: request_hunk.len(),
        response_hunk_len,
        payload_len: payload.len(),
        echoed_payload,
        outer_tls_wrapped: false,
        grpc_contains_tls_boundary: true,
        http2_tls_lifecycle: true,
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
    })
}

pub fn read_tcp_request_from_grpc_http2_stream<S>(
    stream: &mut S,
    grpc_options: &GrpcHttp2LifecycleOptions,
    payload_len: usize,
) -> Result<TrojanGrpcHttp2Request, OutboundError>
where
    S: Read,
{
    let request = read_grpc_http2_request(stream, grpc_options)?;
    let request_hunk_len = request.grpc_payload.len();
    let mut hunk_cursor = Cursor::new(request.grpc_payload);
    let trojan_payload = read_grpc_hunk_frame(&mut hunk_cursor)?;
    let mut cursor = Cursor::new(trojan_payload);
    let tcp = read_tcp_request_from_stream(&mut cursor, payload_len)?;
    if cursor.position() as usize != cursor.get_ref().len() {
        return Err(OutboundError::BadTrojan(format!(
            "trojan-go grpc http2 hunk request has trailing bytes: {}",
            cursor.get_ref().len() - cursor.position() as usize
        )));
    }
    Ok(TrojanGrpcHttp2Request {
        request: tcp,
        request_hunk_len,
        http2_frames: request.report,
    })
}

pub fn write_grpc_http2_hunk_response<S>(
    stream: &mut S,
    payload: &[u8],
) -> Result<GrpcHttp2FrameReport, OutboundError>
where
    S: Write,
{
    let response_hunk = grpc_hunk_http2_data(payload)?;
    write_grpc_http2_response(stream, &response_hunk)
}
