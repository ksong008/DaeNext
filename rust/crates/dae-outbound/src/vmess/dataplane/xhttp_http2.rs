use std::io::{Cursor, Read, Write};

use crate::error::OutboundError;
use crate::shared_transport::{
    XHttpHttp2FrameReport, XHttpLifecycleOptions, read_xhttp_http2_request,
    read_xhttp_http2_response, write_xhttp_http2_request, write_xhttp_http2_response,
};

use super::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VMessAeadXHttpHttp2ExchangeReport {
    pub proxy: String,
    pub target: String,
    pub xhttp_host: String,
    pub xhttp_path: String,
    pub xhttp_request_path: String,
    pub xhttp_mode: String,
    pub xhttp_alpn: String,
    pub use_h3: bool,
    pub uuid: String,
    pub cmd_key_hex: String,
    pub command: u8,
    pub security: u8,
    pub request_header_len: usize,
    pub request_chunk_len: usize,
    pub response_header_len: usize,
    pub response_chunk_len: usize,
    pub xhttp_request_body_len: usize,
    pub xhttp_response_body_len: usize,
    pub payload_len: usize,
    pub echoed_payload: Vec<u8>,
    pub http2_lifecycle: bool,
    pub h2_packet_up_validated: bool,
    pub h3_deferred: bool,
    pub tls_utls_deferred: bool,
    pub reality_rejected_for_vmess: bool,
    pub download_settings_deferred: bool,
    pub stream_modes_deferred: bool,
    pub http2_client_preface_validated: bool,
    pub http2_settings_validated: bool,
    pub http2_headers_validated: bool,
    pub http2_data_validated: bool,
    pub request_frames: XHttpHttp2FrameReport,
    pub response_frames: XHttpHttp2FrameReport,
    pub true_dataplane: bool,
    pub default_go_path: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VMessAeadXHttpHttp2Request {
    pub request: VMessAeadTcpRequest,
    pub xhttp_request_body_len: usize,
    pub xhttp_request_path: String,
    pub http2_frames: XHttpHttp2FrameReport,
}

pub fn aead_tcp_exchange_over_xhttp_http2_stream<S>(
    stream: &mut S,
    proxy: &str,
    uuid: &str,
    target: &str,
    xhttp_options: &XHttpLifecycleOptions,
    payload: &[u8],
) -> Result<VMessAeadXHttpHttp2ExchangeReport, OutboundError>
where
    S: Read + Write,
{
    if xhttp_options.mode != "packet-up" {
        return Err(OutboundError::BadVmess(format!(
            "VMess xHTTP HTTP/2 exchange requires packet-up mode, got {}",
            xhttp_options.mode
        )));
    }
    if xhttp_options.alpn != "h2" {
        return Err(OutboundError::BadVmess(format!(
            "VMess xHTTP HTTP/2 exchange requires h2 ALPN, got {}",
            xhttp_options.alpn
        )));
    }

    let packet = build_aead_request(uuid, target, VMessNetwork::Tcp, payload)?;
    let mut request_payload = Vec::with_capacity(packet.header.len() + packet.chunk.len());
    request_payload.extend_from_slice(&packet.header);
    request_payload.extend_from_slice(&packet.chunk);
    let request_frames = write_xhttp_http2_request(stream, xhttp_options, &request_payload)?;

    let (response_payload, response_frames) = read_xhttp_http2_response(stream)?;
    let mut response_cursor = Cursor::new(&response_payload);
    let (response_header_len, echoed_payload, response_chunk_len) =
        read_aead_response_header_and_chunk(&mut response_cursor, &packet.request)?;
    if response_cursor.position() as usize != response_payload.len() {
        return Err(OutboundError::BadVmess(format!(
            "VMess xHTTP HTTP/2 response has trailing bytes: {}",
            response_payload.len() - response_cursor.position() as usize
        )));
    }
    if echoed_payload != payload {
        return Err(OutboundError::BadVmess(
            "VMess xHTTP HTTP/2 payload response mismatch".to_owned(),
        ));
    }

    Ok(VMessAeadXHttpHttp2ExchangeReport {
        proxy: proxy.to_owned(),
        target: target.to_owned(),
        xhttp_host: xhttp_options.host.clone(),
        xhttp_path: crate::shared_transport::ir::normalize_xhttp_path_and_query(
            &xhttp_options.path,
        )
        .path,
        xhttp_request_path: request_frames.request_path.clone(),
        xhttp_mode: xhttp_options.mode.clone(),
        xhttp_alpn: xhttp_options.alpn.clone(),
        use_h3: request_frames.use_h3,
        uuid: normalize_vmess_uuid(uuid),
        cmd_key_hex: packet.request.cmd_key_hex,
        command: VMessNetwork::Tcp.byte(),
        security: VMESS_AEAD_SECURITY_AES_128_GCM,
        request_header_len: packet.header.len(),
        request_chunk_len: packet.chunk.len(),
        response_header_len,
        response_chunk_len,
        xhttp_request_body_len: request_payload.len(),
        xhttp_response_body_len: response_payload.len(),
        payload_len: payload.len(),
        echoed_payload,
        http2_lifecycle: true,
        h2_packet_up_validated: true,
        h3_deferred: true,
        tls_utls_deferred: true,
        reality_rejected_for_vmess: true,
        download_settings_deferred: true,
        stream_modes_deferred: true,
        http2_client_preface_validated: request_frames.http2_client_preface_validated,
        http2_settings_validated: request_frames.settings_frame_validated
            && response_frames.response_settings_ack_validated,
        http2_headers_validated: request_frames.headers_frame_validated
            && response_frames.response_headers_validated,
        http2_data_validated: request_frames.data_frame_validated
            && response_frames.response_data_validated,
        request_frames,
        response_frames,
        true_dataplane: true,
        default_go_path: true,
    })
}

pub fn read_aead_tcp_request_from_xhttp_http2_stream<S>(
    stream: &mut S,
    uuid: &str,
    xhttp_options: &XHttpLifecycleOptions,
) -> Result<VMessAeadXHttpHttp2Request, OutboundError>
where
    S: Read,
{
    let request = read_xhttp_http2_request(stream, xhttp_options)?;
    let xhttp_request_body_len = request.payload.len();
    let mut cursor = Cursor::new(request.payload);
    let tcp = read_aead_tcp_request_from_stream(&mut cursor, uuid)?;
    if cursor.position() as usize != cursor.get_ref().len() {
        return Err(OutboundError::BadVmess(format!(
            "VMess xHTTP HTTP/2 request has trailing bytes: {}",
            cursor.get_ref().len() - cursor.position() as usize
        )));
    }
    Ok(VMessAeadXHttpHttp2Request {
        request: tcp,
        xhttp_request_body_len,
        xhttp_request_path: request.report.request_path.clone(),
        http2_frames: request.report,
    })
}

pub fn write_aead_xhttp_http2_response<S>(
    stream: &mut S,
    request: &VMessAeadTcpRequest,
    payload: &[u8],
) -> Result<XHttpHttp2FrameReport, OutboundError>
where
    S: Write,
{
    let response = aead_tcp_response_packet(request, payload)?;
    write_xhttp_http2_response(stream, &response)
}
