use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use crate::error::OutboundError;
use crate::shared_transport::ir;

use super::grpc_http2::{
    HTTP2_CLIENT_PREFACE, HTTP2_FLAG_ACK, HTTP2_FLAG_END_HEADERS, HTTP2_FRAME_DATA,
    HTTP2_FRAME_HEADERS, HTTP2_FRAME_SETTINGS, Http2Frame, http2_frame, read_http2_frame,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct XHttpXmuxOptions {
    pub max_connections: u32,
    pub c_max_reuse_times: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct XHttpLifecycleOptions {
    pub host: String,
    pub path: String,
    pub mode: String,
    pub security: String,
    pub alpn: String,
    pub session_id: String,
    pub seq: u64,
    pub xmux: Option<XHttpXmuxOptions>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct XHttpLifecycleReport {
    pub transport: &'static str,
    pub host: String,
    pub path: String,
    pub mode: String,
    pub alpn: String,
    pub use_h3: bool,
    pub payload_len: usize,
    pub echoed_payload: Vec<u8>,
    pub lifecycle_harness: bool,
    pub full_h2_h3_stack: bool,
    pub default_go_path: bool,
}

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

impl XHttpLifecycleOptions {
    pub fn new(
        host: impl Into<String>,
        path: impl Into<String>,
        mode: impl Into<String>,
        security: impl Into<String>,
        alpn: impl Into<String>,
        session_id: impl Into<String>,
        seq: u64,
    ) -> Result<Self, OutboundError> {
        let security = security.into();
        let alpn = alpn.into();
        let mode = mode.into();
        let mode_result = ir::normalize_xhttp_mode(&mode, "https", &security, false);
        if !mode_result.ok {
            return Err(OutboundError::BadSharedTransport(
                mode_result.error_contains,
            ));
        }
        let alpn_result = ir::validate_xhttp_alpn(&security, &alpn);
        if !alpn_result.ok {
            return Err(OutboundError::BadSharedTransport(
                alpn_result.error_contains,
            ));
        }
        Ok(Self {
            host: host.into(),
            path: path.into(),
            mode: mode_result.normalized,
            security,
            alpn,
            session_id: session_id.into(),
            seq,
            xmux: None,
        })
    }

    pub fn with_xmux(mut self, xmux: XHttpXmuxOptions) -> Self {
        self.xmux = Some(xmux);
        self
    }
}

impl XHttpXmuxOptions {
    pub fn new(max_connections: u32, c_max_reuse_times: u32) -> Result<Self, OutboundError> {
        if max_connections == 0 {
            return Err(OutboundError::BadSharedTransport(
                "xhttp xmux maxConnections must be greater than zero".to_owned(),
            ));
        }
        if c_max_reuse_times == 0 {
            return Err(OutboundError::BadSharedTransport(
                "xhttp xmux cMaxReuseTimes must be greater than zero".to_owned(),
            ));
        }
        Ok(Self {
            max_connections,
            c_max_reuse_times,
        })
    }
}

pub fn xhttp_packet_request(options: &XHttpLifecycleOptions, payload: &[u8]) -> Vec<u8> {
    let path = xhttp_request_path(options);
    format!(
        "POST {path} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/octet-stream\r\nX-DAE-XHTTP-Mode: {}\r\nX-DAE-XHTTP-ALPN: {}\r\nContent-Length: {}\r\n\r\n",
        options.host,
        options.mode,
        options.alpn,
        payload.len()
    )
    .into_bytes()
    .into_iter()
    .chain(payload.iter().copied())
    .collect()
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
    if headers.payload != xhttp_request_headers_payload(options) {
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
    if headers.payload != xhttp_response_headers_payload() {
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

pub fn xhttp_packet_exchange(
    endpoint: &str,
    options: &XHttpLifecycleOptions,
    payload: &[u8],
    timeout: Duration,
) -> Result<XHttpLifecycleReport, OutboundError> {
    let mut stream = TcpStream::connect(endpoint)
        .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
    set_timeout(&stream, timeout)?;
    let request = xhttp_packet_request(options, payload);
    stream
        .write_all(&request)
        .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
    let echoed_payload = read_http_response_body(&mut stream)?;
    let alpn = ir::validate_xhttp_alpn(&options.security, &options.alpn);
    Ok(XHttpLifecycleReport {
        transport: "xhttp-packet",
        host: options.host.clone(),
        path: ir::normalize_xhttp_path_and_query(&options.path).path,
        mode: options.mode.clone(),
        alpn: options.alpn.clone(),
        use_h3: alpn.use_h3,
        payload_len: payload.len(),
        echoed_payload,
        lifecycle_harness: true,
        full_h2_h3_stack: false,
        default_go_path: true,
    })
}

pub fn xhttp_request_path(options: &XHttpLifecycleOptions) -> String {
    let path = ir::normalize_xhttp_path_and_query(&options.path);
    let lifecycle = format!("session={}&seq={}", options.session_id, options.seq);
    if path.query.is_empty() {
        format!("{}?{lifecycle}", path.path)
    } else {
        format!("{}?{}&{lifecycle}", path.path, path.query)
    }
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

fn xhttp_request_headers_payload(options: &XHttpLifecycleOptions) -> Vec<u8> {
    let mut payload = vec![0x83, 0x87];
    push_hpack_literal_indexed_name(&mut payload, 4, xhttp_request_path(options).as_bytes());
    push_hpack_literal_indexed_name(&mut payload, 1, options.host.as_bytes());
    push_hpack_literal_new_name(&mut payload, b"content-type", b"application/octet-stream");
    push_hpack_literal_new_name(&mut payload, b"x-dae-xhttp-mode", options.mode.as_bytes());
    push_hpack_literal_new_name(&mut payload, b"x-dae-xhttp-alpn", options.alpn.as_bytes());
    payload
}

fn xhttp_response_headers_payload() -> Vec<u8> {
    let mut payload = vec![0x88];
    push_hpack_literal_new_name(&mut payload, b"content-type", b"application/octet-stream");
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
        "xhttp hpack helper only supports short literals"
    );
    out.push(value.len() as u8);
    out.extend_from_slice(value);
}

fn read_http_response_body(stream: &mut TcpStream) -> Result<Vec<u8>, OutboundError> {
    let (head, mut leftover) = read_http_head_and_leftover(stream)?;
    let content_length = content_length(&head)?;
    while leftover.len() < content_length {
        let mut buf = vec![0_u8; content_length - leftover.len()];
        let n = stream
            .read(&mut buf)
            .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
        if n == 0 {
            break;
        }
        leftover.extend_from_slice(&buf[..n]);
    }
    leftover.truncate(content_length);
    Ok(leftover)
}

fn read_http_head_and_leftover(stream: &mut TcpStream) -> Result<(String, Vec<u8>), OutboundError> {
    let mut data = Vec::new();
    let mut buf = [0_u8; 256];
    loop {
        let n = stream
            .read(&mut buf)
            .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
        if n == 0 {
            return Err(OutboundError::BadSharedTransport(
                "incomplete xhttp response".to_owned(),
            ));
        }
        data.extend_from_slice(&buf[..n]);
        if let Some(index) = data.windows(4).position(|window| window == b"\r\n\r\n") {
            let body_start = index + 4;
            let leftover = data[body_start..].to_vec();
            data.truncate(body_start);
            let head = String::from_utf8(data)
                .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
            return Ok((head, leftover));
        }
    }
}

fn content_length(head: &str) -> Result<usize, OutboundError> {
    for line in head.split("\r\n") {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        if key.eq_ignore_ascii_case("content-length") {
            return value
                .trim()
                .parse::<usize>()
                .map_err(|err| OutboundError::BadSharedTransport(err.to_string()));
        }
    }
    Ok(0)
}

fn set_timeout(stream: &TcpStream, timeout: Duration) -> Result<(), OutboundError> {
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))
}
