use std::io::{Read, Write};

use crate::error::OutboundError;

use super::grpc_hunk_frame;

pub const HTTP2_CLIENT_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

pub const HTTP2_FRAME_DATA: u8 = 0x0;
pub const HTTP2_FRAME_HEADERS: u8 = 0x1;
pub const HTTP2_FRAME_SETTINGS: u8 = 0x4;

pub const HTTP2_FLAG_ACK: u8 = 0x1;
pub const HTTP2_FLAG_END_HEADERS: u8 = 0x4;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GrpcHttp2LifecycleOptions {
    pub authority: String,
    pub service_name: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GrpcHttp2FrameReport {
    pub client_preface_len: usize,
    pub request_settings_frame_len: usize,
    pub request_headers_frame_len: usize,
    pub request_data_frame_len: usize,
    pub response_settings_ack_len: usize,
    pub response_headers_frame_len: usize,
    pub response_data_frame_len: usize,
    pub request_stream_id: u32,
    pub response_stream_id: u32,
    pub service_name: String,
    pub authority: String,
    pub http2_client_preface_validated: bool,
    pub settings_frame_validated: bool,
    pub headers_frame_validated: bool,
    pub data_frame_validated: bool,
    pub response_settings_ack_validated: bool,
    pub response_headers_validated: bool,
    pub response_data_validated: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GrpcHttp2Request {
    pub grpc_payload: Vec<u8>,
    pub report: GrpcHttp2FrameReport,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Http2Frame {
    pub frame_type: u8,
    pub flags: u8,
    pub stream_id: u32,
    pub payload: Vec<u8>,
}

impl GrpcHttp2LifecycleOptions {
    pub fn service_name_or_default(&self) -> String {
        if self.service_name.is_empty() {
            "GunService".to_owned()
        } else {
            self.service_name.clone()
        }
    }
}

pub fn write_grpc_http2_request(
    stream: &mut impl Write,
    options: &GrpcHttp2LifecycleOptions,
    grpc_payload: &[u8],
) -> Result<GrpcHttp2FrameReport, OutboundError> {
    let service_name = options.service_name_or_default();
    let request_settings = http2_frame(HTTP2_FRAME_SETTINGS, 0, 0, &[])?;
    let headers_payload = grpc_request_headers_payload(&service_name, &options.authority);
    let request_headers = http2_frame(
        HTTP2_FRAME_HEADERS,
        HTTP2_FLAG_END_HEADERS,
        1,
        &headers_payload,
    )?;
    let request_data = http2_frame(HTTP2_FRAME_DATA, 0, 1, grpc_payload)?;

    stream
        .write_all(HTTP2_CLIENT_PREFACE)
        .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
    stream
        .write_all(&request_settings)
        .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
    stream
        .write_all(&request_headers)
        .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
    stream
        .write_all(&request_data)
        .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
    stream
        .flush()
        .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;

    Ok(GrpcHttp2FrameReport {
        client_preface_len: HTTP2_CLIENT_PREFACE.len(),
        request_settings_frame_len: request_settings.len(),
        request_headers_frame_len: request_headers.len(),
        request_data_frame_len: request_data.len(),
        response_settings_ack_len: 0,
        response_headers_frame_len: 0,
        response_data_frame_len: 0,
        request_stream_id: 1,
        response_stream_id: 0,
        service_name,
        authority: options.authority.clone(),
        http2_client_preface_validated: true,
        settings_frame_validated: true,
        headers_frame_validated: true,
        data_frame_validated: true,
        response_settings_ack_validated: false,
        response_headers_validated: false,
        response_data_validated: false,
    })
}

pub fn read_grpc_http2_request(
    stream: &mut impl Read,
    options: &GrpcHttp2LifecycleOptions,
) -> Result<GrpcHttp2Request, OutboundError> {
    let mut preface = [0_u8; HTTP2_CLIENT_PREFACE.len()];
    stream
        .read_exact(&mut preface)
        .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
    if preface != HTTP2_CLIENT_PREFACE {
        return Err(OutboundError::BadSharedTransport(
            "grpc http2 client preface mismatch".to_owned(),
        ));
    }

    let settings = read_http2_frame(stream)?;
    validate_frame(&settings, HTTP2_FRAME_SETTINGS, 0, 0, "request settings")?;
    let headers = read_http2_frame(stream)?;
    validate_frame(
        &headers,
        HTTP2_FRAME_HEADERS,
        HTTP2_FLAG_END_HEADERS,
        1,
        "request headers",
    )?;
    let data = read_http2_frame(stream)?;
    validate_frame(&data, HTTP2_FRAME_DATA, 0, 1, "request data")?;

    let service_name = options.service_name_or_default();
    let expected_headers = grpc_request_headers_payload(&service_name, &options.authority);
    if headers.payload != expected_headers {
        return Err(OutboundError::BadSharedTransport(
            "grpc http2 request headers mismatch".to_owned(),
        ));
    }
    Ok(GrpcHttp2Request {
        grpc_payload: data.payload.clone(),
        report: GrpcHttp2FrameReport {
            client_preface_len: HTTP2_CLIENT_PREFACE.len(),
            request_settings_frame_len: settings.payload.len() + 9,
            request_headers_frame_len: headers.payload.len() + 9,
            request_data_frame_len: data.payload.len() + 9,
            response_settings_ack_len: 0,
            response_headers_frame_len: 0,
            response_data_frame_len: 0,
            request_stream_id: 1,
            response_stream_id: 0,
            service_name,
            authority: options.authority.clone(),
            http2_client_preface_validated: true,
            settings_frame_validated: true,
            headers_frame_validated: true,
            data_frame_validated: true,
            response_settings_ack_validated: false,
            response_headers_validated: false,
            response_data_validated: false,
        },
    })
}

pub fn write_grpc_http2_response(
    stream: &mut impl Write,
    grpc_payload: &[u8],
) -> Result<GrpcHttp2FrameReport, OutboundError> {
    let settings_ack = http2_frame(HTTP2_FRAME_SETTINGS, HTTP2_FLAG_ACK, 0, &[])?;
    let headers_payload = grpc_response_headers_payload();
    let headers = http2_frame(
        HTTP2_FRAME_HEADERS,
        HTTP2_FLAG_END_HEADERS,
        1,
        &headers_payload,
    )?;
    let data = http2_frame(HTTP2_FRAME_DATA, 0, 1, grpc_payload)?;

    stream
        .write_all(&settings_ack)
        .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
    stream
        .write_all(&headers)
        .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
    stream
        .write_all(&data)
        .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
    stream
        .flush()
        .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;

    Ok(GrpcHttp2FrameReport {
        client_preface_len: 0,
        request_settings_frame_len: 0,
        request_headers_frame_len: 0,
        request_data_frame_len: 0,
        response_settings_ack_len: settings_ack.len(),
        response_headers_frame_len: headers.len(),
        response_data_frame_len: data.len(),
        request_stream_id: 0,
        response_stream_id: 1,
        service_name: String::new(),
        authority: String::new(),
        http2_client_preface_validated: false,
        settings_frame_validated: false,
        headers_frame_validated: false,
        data_frame_validated: false,
        response_settings_ack_validated: true,
        response_headers_validated: true,
        response_data_validated: true,
    })
}

pub fn read_grpc_http2_response(
    stream: &mut impl Read,
) -> Result<(Vec<u8>, GrpcHttp2FrameReport), OutboundError> {
    let settings_ack = read_http2_frame(stream)?;
    validate_frame(
        &settings_ack,
        HTTP2_FRAME_SETTINGS,
        HTTP2_FLAG_ACK,
        0,
        "response settings ack",
    )?;
    let headers = read_http2_frame(stream)?;
    validate_frame(
        &headers,
        HTTP2_FRAME_HEADERS,
        HTTP2_FLAG_END_HEADERS,
        1,
        "response headers",
    )?;
    if headers.payload != grpc_response_headers_payload() {
        return Err(OutboundError::BadSharedTransport(
            "grpc http2 response headers mismatch".to_owned(),
        ));
    }
    let data = read_http2_frame(stream)?;
    validate_frame(&data, HTTP2_FRAME_DATA, 0, 1, "response data")?;
    Ok((
        data.payload.clone(),
        GrpcHttp2FrameReport {
            client_preface_len: 0,
            request_settings_frame_len: 0,
            request_headers_frame_len: 0,
            request_data_frame_len: 0,
            response_settings_ack_len: settings_ack.payload.len() + 9,
            response_headers_frame_len: headers.payload.len() + 9,
            response_data_frame_len: data.payload.len() + 9,
            request_stream_id: 0,
            response_stream_id: 1,
            service_name: String::new(),
            authority: String::new(),
            http2_client_preface_validated: false,
            settings_frame_validated: false,
            headers_frame_validated: false,
            data_frame_validated: false,
            response_settings_ack_validated: true,
            response_headers_validated: true,
            response_data_validated: true,
        },
    ))
}

pub fn grpc_hunk_http2_data(payload: &[u8]) -> Result<Vec<u8>, OutboundError> {
    grpc_hunk_frame(payload)
}

pub fn http2_frame(
    frame_type: u8,
    flags: u8,
    stream_id: u32,
    payload: &[u8],
) -> Result<Vec<u8>, OutboundError> {
    if payload.len() > 0x00ff_ffff {
        return Err(OutboundError::BadSharedTransport(
            "http2 payload too large".to_owned(),
        ));
    }
    if stream_id > 0x7fff_ffff {
        return Err(OutboundError::BadSharedTransport(
            "http2 stream id exceeds 31 bits".to_owned(),
        ));
    }
    let len = payload.len() as u32;
    let mut frame = Vec::with_capacity(payload.len() + 9);
    frame.push((len >> 16) as u8);
    frame.push((len >> 8) as u8);
    frame.push(len as u8);
    frame.push(frame_type);
    frame.push(flags);
    frame.extend_from_slice(&(stream_id & 0x7fff_ffff).to_be_bytes());
    frame.extend_from_slice(payload);
    Ok(frame)
}

pub fn read_http2_frame(stream: &mut impl Read) -> Result<Http2Frame, OutboundError> {
    let mut header = [0_u8; 9];
    stream
        .read_exact(&mut header)
        .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
    let len = ((header[0] as usize) << 16) | ((header[1] as usize) << 8) | header[2] as usize;
    let frame_type = header[3];
    let flags = header[4];
    let stream_id = u32::from_be_bytes([header[5], header[6], header[7], header[8]]) & 0x7fff_ffff;
    let mut payload = vec![0_u8; len];
    stream
        .read_exact(&mut payload)
        .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
    Ok(Http2Frame {
        frame_type,
        flags,
        stream_id,
        payload,
    })
}

fn validate_frame(
    frame: &Http2Frame,
    expected_type: u8,
    expected_flags: u8,
    expected_stream_id: u32,
    label: &str,
) -> Result<(), OutboundError> {
    if frame.frame_type != expected_type {
        return Err(OutboundError::BadSharedTransport(format!(
            "{label} frame type mismatch: got {}, want {expected_type}",
            frame.frame_type
        )));
    }
    if frame.flags != expected_flags {
        return Err(OutboundError::BadSharedTransport(format!(
            "{label} flags mismatch: got {}, want {expected_flags}",
            frame.flags
        )));
    }
    if frame.stream_id != expected_stream_id {
        return Err(OutboundError::BadSharedTransport(format!(
            "{label} stream id mismatch: got {}, want {expected_stream_id}",
            frame.stream_id
        )));
    }
    Ok(())
}

fn grpc_request_headers_payload(service_name: &str, authority: &str) -> Vec<u8> {
    let path = format!("/{service_name}/Tun");
    let mut payload = vec![0x83, 0x87];
    push_hpack_literal_indexed_name(&mut payload, 4, path.as_bytes());
    push_hpack_literal_indexed_name(&mut payload, 1, authority.as_bytes());
    push_hpack_literal_new_name(&mut payload, b"content-type", b"application/grpc");
    push_hpack_literal_new_name(&mut payload, b"te", b"trailers");
    payload
}

fn grpc_response_headers_payload() -> Vec<u8> {
    let mut payload = vec![0x88];
    push_hpack_literal_new_name(&mut payload, b"content-type", b"application/grpc");
    payload
}

fn push_hpack_literal_indexed_name(out: &mut Vec<u8>, name_index: u8, value: &[u8]) {
    out.push(name_index & 0x0f);
    push_hpack_string(out, value);
}

fn push_hpack_literal_new_name(out: &mut Vec<u8>, name: &[u8], value: &[u8]) {
    out.push(0);
    push_hpack_string(out, name);
    push_hpack_string(out, value);
}

fn push_hpack_string(out: &mut Vec<u8>, value: &[u8]) {
    assert!(
        value.len() < 128,
        "grpc hpack helper only supports short literals"
    );
    out.push(value.len() as u8);
    out.extend_from_slice(value);
}
