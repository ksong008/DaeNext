use std::io::{Cursor, Read, Write};

use crate::error::OutboundError;
use crate::shared_transport::{
    GrpcLifecycleOptions, grpc_hunk_frame, grpc_hunk_frame_len, grpc_stream_preface,
    read_grpc_hunk_frame,
};

use super::dataplane::{TrojanTcpRequest, read_tcp_request_from_stream};
use super::metadata::{TrojanMetadata, TrojanNetwork};
use super::packet;

pub const TROJAN_GRPC_DEFAULT_SERVICE_NAME: &str = "GunService";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrojanGrpcTcpExchangeReport {
    pub proxy: String,
    pub target: String,
    pub grpc_service_name: String,
    pub grpc_cache_key: String,
    pub password_sha224_hex: String,
    pub command: u8,
    pub request_header_len: usize,
    pub grpc_preface_len: usize,
    pub grpc_request_hunk_len: usize,
    pub grpc_response_hunk_len: usize,
    pub payload_len: usize,
    pub echoed_payload: Vec<u8>,
    pub outer_tls_wrapped: bool,
    pub grpc_contains_tls_boundary: bool,
    pub trojan_grpc: bool,
    pub grpc_stream_preface_validated: bool,
    pub grpc_hunk_frame_validated: bool,
    pub cache_key_route_context_validated: bool,
    pub full_grpc_http2_stack: bool,
    pub true_dataplane: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrojanGrpcRequest {
    pub request: TrojanTcpRequest,
    pub grpc_request_hunk_len: usize,
}

pub fn trojan_grpc_service_name(service_name: &str, path: &str) -> String {
    if !service_name.is_empty() {
        service_name.to_owned()
    } else if !path.is_empty() {
        path.to_owned()
    } else {
        TROJAN_GRPC_DEFAULT_SERVICE_NAME.to_owned()
    }
}

pub fn tcp_exchange_over_grpc_hunk_stream<S>(
    stream: &mut S,
    proxy: &str,
    password: &str,
    target: &str,
    grpc_options: &GrpcLifecycleOptions,
    payload: &[u8],
) -> Result<TrojanGrpcTcpExchangeReport, OutboundError>
where
    S: Read + Write,
{
    let service_name = if grpc_options.service_name.is_empty() {
        TROJAN_GRPC_DEFAULT_SERVICE_NAME.to_owned()
    } else {
        grpc_options.service_name.clone()
    };
    let preface = grpc_stream_preface(&grpc_options.service_name)?;
    stream
        .write_all(&preface)
        .map_err(|err| OutboundError::BadTrojan(err.to_string()))?;

    let metadata = TrojanMetadata::parse("tcp", target)?;
    let target = metadata.authority();
    let request = packet::tcp_request_header(password, "tcp", &target, payload)?;
    let request_header_len = request.len().saturating_sub(payload.len());
    let request_hunk = grpc_hunk_frame(&request)?;
    stream
        .write_all(&request_hunk)
        .map_err(|err| OutboundError::BadTrojan(err.to_string()))?;

    let response_payload = read_grpc_hunk_frame(stream)?;
    let grpc_response_hunk_len = grpc_hunk_frame_len(&response_payload)?;
    if response_payload != payload {
        return Err(OutboundError::BadTrojan(
            "trojan-go grpc hunk payload response mismatch".to_owned(),
        ));
    }

    Ok(TrojanGrpcTcpExchangeReport {
        proxy: proxy.to_owned(),
        target,
        grpc_service_name: service_name,
        grpc_cache_key: grpc_options.cache_key(),
        password_sha224_hex: packet::password_sha224_hex(password),
        command: TrojanNetwork::Tcp.byte(),
        request_header_len,
        grpc_preface_len: preface.len(),
        grpc_request_hunk_len: request_hunk.len(),
        grpc_response_hunk_len,
        payload_len: payload.len(),
        echoed_payload: response_payload,
        outer_tls_wrapped: false,
        grpc_contains_tls_boundary: true,
        trojan_grpc: true,
        grpc_stream_preface_validated: true,
        grpc_hunk_frame_validated: true,
        cache_key_route_context_validated: true,
        full_grpc_http2_stack: false,
        true_dataplane: true,
    })
}

pub fn read_tcp_request_from_grpc_hunk_stream<S>(
    stream: &mut S,
    payload_len: usize,
) -> Result<TrojanGrpcRequest, OutboundError>
where
    S: Read,
{
    let payload = read_grpc_hunk_frame(stream)?;
    let grpc_request_hunk_len = grpc_hunk_frame_len(&payload)?;
    let mut cursor = Cursor::new(&payload);
    let request = read_tcp_request_from_stream(&mut cursor, payload_len)?;
    if cursor.position() as usize != payload.len() {
        return Err(OutboundError::BadTrojan(format!(
            "trojan-go grpc hunk request has trailing bytes: {}",
            payload.len() - cursor.position() as usize
        )));
    }
    Ok(TrojanGrpcRequest {
        request,
        grpc_request_hunk_len,
    })
}
