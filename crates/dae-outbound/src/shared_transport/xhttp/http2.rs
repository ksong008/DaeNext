use std::io::{Read, Write};

use crate::error::OutboundError;
use crate::shared_transport::grpc_http2::{
    HTTP2_CLIENT_PREFACE, HTTP2_FLAG_ACK, HTTP2_FLAG_END_HEADERS, HTTP2_FRAME_DATA,
    HTTP2_FRAME_HEADERS, HTTP2_FRAME_SETTINGS, Http2Frame, http2_frame, read_http2_frame,
};
use crate::shared_transport::ir;

use super::hpack::{xhttp_request_headers_payload, xhttp_response_headers_payload};
use super::http1::xhttp_request_path;
use super::options::XHttpLifecycleOptions;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct XHttpHttp2FrameReport {
    pub client_preface_len: usize,
    pub request_settings_frame_len: usize,
    pub request_headers_frame_len: usize,
    pub request_data_frame_len: usize,
    pub response_settings_ack_len: usize,
    pub response_headers_frame_len: usize,
    pub response_data_frame_len: usize,
    pub request_stream_id: u32,
    pub response_stream_id: u32,
    pub host: String,
    pub path: String,
    pub request_path: String,
    pub mode: String,
    pub alpn: String,
    pub use_h3: bool,
    pub http2_client_preface_validated: bool,
    pub settings_frame_validated: bool,
    pub headers_frame_validated: bool,
    pub data_frame_validated: bool,
    pub response_settings_ack_validated: bool,
    pub response_headers_validated: bool,
    pub response_data_validated: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct XHttpHttp2Request {
    pub payload: Vec<u8>,
    pub report: XHttpHttp2FrameReport,
}

pub fn write_xhttp_http2_request(
    stream: &mut impl Write,
    options: &XHttpLifecycleOptions,
    payload: &[u8],
) -> Result<XHttpHttp2FrameReport, OutboundError> {
    let request_settings = http2_frame(HTTP2_FRAME_SETTINGS, 0, 0, &[])?;
    let headers_payload = xhttp_request_headers_payload(options);
    let request_headers = http2_frame(
        HTTP2_FRAME_HEADERS,
        HTTP2_FLAG_END_HEADERS,
        1,
        &headers_payload,
    )?;
    let request_data = http2_frame(HTTP2_FRAME_DATA, 0, 1, payload)?;

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

    Ok(request_report(
        options,
        request_settings.len(),
        request_headers.len(),
        request_data.len(),
    ))
}

pub fn read_xhttp_http2_request(
    stream: &mut impl Read,
    options: &XHttpLifecycleOptions,
) -> Result<XHttpHttp2Request, OutboundError> {
    let mut preface = [0_u8; HTTP2_CLIENT_PREFACE.len()];
    stream
        .read_exact(&mut preface)
        .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
    if preface != HTTP2_CLIENT_PREFACE {
        return Err(OutboundError::BadSharedTransport(
            "xhttp http2 client preface mismatch".to_owned(),
        ));
    }

    let settings = read_http2_frame(stream)?;
    validate_http2_frame(
        &settings,
        HTTP2_FRAME_SETTINGS,
        0,
        0,
        "xhttp request settings",
    )?;
    let headers = read_http2_frame(stream)?;
    validate_http2_frame(
        &headers,
        HTTP2_FRAME_HEADERS,
        HTTP2_FLAG_END_HEADERS,
        1,
        "xhttp request headers",
    )?;
    // A-13: 语义验证（HPACK 解码后比较）。
    let decoded = crate::shared_transport::hpack_decode::decode_header_block(&headers.payload)?;
    // 与 xhttp_request_headers_payload 实际编码一致。
    let expected: &[(&str, &str)] = &[
        (":method", "POST"),
        (":scheme", "https"),
        (":path", &xhttp_request_path(options)),
        (":authority", &options.host),
        ("content-type", "application/octet-stream"),
        ("x-dae-xhttp-mode", &options.mode),
        ("x-dae-xhttp-alpn", &options.alpn),
    ];
    if !crate::shared_transport::hpack_decode::semantic_headers_match(&decoded, expected) {
        return Err(OutboundError::BadSharedTransport(
            "xhttp http2 request headers mismatch".to_owned(),
        ));
    }
    let data = read_http2_frame(stream)?;
    validate_http2_frame(&data, HTTP2_FRAME_DATA, 0, 1, "xhttp request data")?;

    Ok(XHttpHttp2Request {
        payload: data.payload.clone(),
        report: request_report(
            options,
            settings.payload.len() + 9,
            headers.payload.len() + 9,
            data.payload.len() + 9,
        ),
    })
}

pub fn write_xhttp_http2_response(
    stream: &mut impl Write,
    payload: &[u8],
) -> Result<XHttpHttp2FrameReport, OutboundError> {
    let settings_ack = http2_frame(HTTP2_FRAME_SETTINGS, HTTP2_FLAG_ACK, 0, &[])?;
    let headers_payload = xhttp_response_headers_payload();
    let headers = http2_frame(
        HTTP2_FRAME_HEADERS,
        HTTP2_FLAG_END_HEADERS,
        1,
        &headers_payload,
    )?;
    let data = http2_frame(HTTP2_FRAME_DATA, 0, 1, payload)?;

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

    Ok(response_report(
        settings_ack.len(),
        headers.len(),
        data.len(),
    ))
}

pub fn read_xhttp_http2_response(
    stream: &mut impl Read,
) -> Result<(Vec<u8>, XHttpHttp2FrameReport), OutboundError> {
    let settings_ack = read_http2_frame(stream)?;
    validate_http2_frame(
        &settings_ack,
        HTTP2_FRAME_SETTINGS,
        HTTP2_FLAG_ACK,
        0,
        "xhttp response settings ack",
    )?;
    let headers = read_http2_frame(stream)?;
    validate_http2_frame(
        &headers,
        HTTP2_FRAME_HEADERS,
        HTTP2_FLAG_END_HEADERS,
        1,
        "xhttp response headers",
    )?;
    // A-13: 语义验证。
    let decoded = crate::shared_transport::hpack_decode::decode_header_block(&headers.payload)?;
    let expected: &[(&str, &str)] = &[
        (":status", "200"),
        ("content-type", "application/octet-stream"),
    ];
    if !crate::shared_transport::hpack_decode::semantic_headers_match(&decoded, expected) {
        return Err(OutboundError::BadSharedTransport(
            "xhttp http2 response headers mismatch".to_owned(),
        ));
    }
    let data = read_http2_frame(stream)?;
    validate_http2_frame(&data, HTTP2_FRAME_DATA, 0, 1, "xhttp response data")?;
    Ok((
        data.payload.clone(),
        response_report(
            settings_ack.payload.len() + 9,
            headers.payload.len() + 9,
            data.payload.len() + 9,
        ),
    ))
}

fn request_report(
    options: &XHttpLifecycleOptions,
    request_settings_frame_len: usize,
    request_headers_frame_len: usize,
    request_data_frame_len: usize,
) -> XHttpHttp2FrameReport {
    let alpn = ir::validate_xhttp_alpn(&options.security, &options.alpn);
    XHttpHttp2FrameReport {
        client_preface_len: HTTP2_CLIENT_PREFACE.len(),
        request_settings_frame_len,
        request_headers_frame_len,
        request_data_frame_len,
        response_settings_ack_len: 0,
        response_headers_frame_len: 0,
        response_data_frame_len: 0,
        request_stream_id: 1,
        response_stream_id: 0,
        host: options.host.clone(),
        path: ir::normalize_xhttp_path_and_query(&options.path).path,
        request_path: xhttp_request_path(options),
        mode: options.mode.clone(),
        alpn: options.alpn.clone(),
        use_h3: alpn.use_h3,
        http2_client_preface_validated: true,
        settings_frame_validated: true,
        headers_frame_validated: true,
        data_frame_validated: true,
        response_settings_ack_validated: false,
        response_headers_validated: false,
        response_data_validated: false,
    }
}

fn response_report(
    response_settings_ack_len: usize,
    response_headers_frame_len: usize,
    response_data_frame_len: usize,
) -> XHttpHttp2FrameReport {
    XHttpHttp2FrameReport {
        client_preface_len: 0,
        request_settings_frame_len: 0,
        request_headers_frame_len: 0,
        request_data_frame_len: 0,
        response_settings_ack_len,
        response_headers_frame_len,
        response_data_frame_len,
        request_stream_id: 0,
        response_stream_id: 1,
        host: String::new(),
        path: String::new(),
        request_path: String::new(),
        mode: String::new(),
        alpn: String::new(),
        use_h3: false,
        http2_client_preface_validated: false,
        settings_frame_validated: false,
        headers_frame_validated: false,
        data_frame_validated: false,
        response_settings_ack_validated: true,
        response_headers_validated: true,
        response_data_validated: true,
    }
}

fn validate_http2_frame(
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
