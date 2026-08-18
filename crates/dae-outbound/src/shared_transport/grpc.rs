use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use crate::error::OutboundError;
use crate::shared_transport::ir;

pub const GRPC_CONTENT_TYPE_HEADER: &str = "content-type";
pub const GRPC_CONTENT_TYPE_APPLICATION: &str = "application/grpc";
pub const GRPC_TE_HEADER: &str = "te";
pub const GRPC_TE_TRAILERS: &str = "trailers";
pub const GRPC_ENCODING_HEADER: &str = "grpc-encoding";
pub const GRPC_ACCEPT_ENCODING_HEADER: &str = "grpc-accept-encoding";
pub const GRPC_IDENTITY_ENCODING: &str = "identity";

/// Maximum accepted gRPC hunk message size on the read path.
///
/// Mirrors the resident dataplane bound
/// (`RESIDENT_WEBSOCKET_MAX_MESSAGE_BYTES`, 16 MiB) so this public helper
/// cannot be driven into a multi-gigabyte allocation by a peer-declared
/// `u32` length prefix.
pub const GRPC_MAX_HUNK_MESSAGE_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub enum GrpcMode {
    #[default]
    Gun,
    Multi,
}

impl GrpcMode {
    pub fn parse_link_value(value: &str) -> Result<Self, OutboundError> {
        match value.trim().to_ascii_lowercase().as_str() {
            "" | "gun" => Ok(Self::Gun),
            "multi" => Ok(Self::Multi),
            value => Err(OutboundError::BadSharedTransport(format!(
                "unsupported Xray gRPC mode: {value}"
            ))),
        }
    }

    pub const fn link_value(self) -> &'static str {
        match self {
            Self::Gun => "gun",
            Self::Multi => "multi",
        }
    }

    pub const fn stream_method(self) -> &'static str {
        match self {
            Self::Gun => "Tun",
            Self::Multi => "TunMulti",
        }
    }
}

pub fn grpc_request_path(service_name: &str, mode: GrpcMode) -> String {
    let (service, method) = if let Some(custom_path) = service_name.strip_prefix('/') {
        let (service, methods) = custom_path.rsplit_once('/').unwrap_or(("", custom_path));
        let method = match mode {
            GrpcMode::Gun => methods.split('|').next().unwrap_or_default(),
            GrpcMode::Multi => methods.split_once('|').map_or(methods, |(_, multi)| multi),
        };
        (
            service
                .split('/')
                .map(xray_path_escape)
                .collect::<Vec<_>>()
                .join("/"),
            xray_path_escape(method),
        )
    } else {
        (
            xray_path_escape(service_name),
            mode.stream_method().to_owned(),
        )
    };
    format!("/{service}/{method}")
}

fn xray_path_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric()
            || matches!(
                byte,
                b'-' | b'_' | b'.' | b'~' | b'+' | b':' | b'@' | b'&' | b'$' | b'='
            )
        {
            escaped.push(char::from(byte));
        } else {
            use std::fmt::Write as _;
            write!(escaped, "%{byte:02X}").expect("writing to a String cannot fail");
        }
    }
    escaped
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GrpcLifecycleOptions {
    pub address: String,
    pub service_name: String,
    pub server_name: String,
    pub dialer_id: String,
    pub allow_insecure: bool,
    pub mark: u32,
    pub mptcp: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GrpcCacheReport {
    pub key: String,
    pub reused: bool,
    pub live_entries: usize,
    pub use_count: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GrpcLifecycleReport {
    pub transport: &'static str,
    pub service_name: String,
    pub cache_key: String,
    pub payload_len: usize,
    pub echoed_payload: Vec<u8>,
    pub stream_harness: bool,
    pub full_grpc_http2_stack: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct GrpcLifecycleCache {
    entries: HashMap<String, usize>,
    closed_entries: usize,
}

impl GrpcLifecycleOptions {
    pub fn new(
        address: impl Into<String>,
        service_name: impl Into<String>,
        server_name: impl Into<String>,
        dialer_id: impl Into<String>,
        allow_insecure: bool,
        mark: u32,
        mptcp: bool,
    ) -> Self {
        Self {
            address: address.into(),
            service_name: service_name.into(),
            server_name: server_name.into(),
            dialer_id: dialer_id.into(),
            allow_insecure,
            mark,
            mptcp,
        }
    }

    pub fn cache_key(&self) -> String {
        ir::grpc_cache_key_lossless(
            &self.address,
            &self.server_name,
            &self.dialer_id,
            self.allow_insecure,
            self.mark,
            self.mptcp,
        )
    }
}

impl GrpcLifecycleCache {
    pub fn get_or_insert(&mut self, options: &GrpcLifecycleOptions) -> GrpcCacheReport {
        let key = options.cache_key();
        let reused = self.entries.contains_key(&key);
        let use_count = {
            let count = self.entries.entry(key.clone()).or_insert(0);
            *count += 1;
            *count
        };
        GrpcCacheReport {
            key,
            reused,
            live_entries: self.entries.len(),
            use_count,
        }
    }

    pub fn clean(&mut self) -> usize {
        let closed = self.entries.len();
        self.entries.clear();
        self.closed_entries += closed;
        closed
    }

    pub fn closed_entries(&self) -> usize {
        self.closed_entries
    }

    pub fn live_entries(&self) -> usize {
        self.entries.len()
    }
}

pub fn grpc_stream_preface(service_name: &str) -> Result<Vec<u8>, OutboundError> {
    let service_name = if service_name.is_empty() {
        "GunService"
    } else {
        service_name
    };
    // F-12: gRPC service name 进入请求行，拒绝 CTL 注入。
    super::dataplane::validate_http_field(service_name, "gRPC service name")?;
    Ok(format!(
        "POST /{service_name}/Tun HTTP/2\r\n\
         {GRPC_CONTENT_TYPE_HEADER}: {GRPC_CONTENT_TYPE_APPLICATION}\r\n\
         {GRPC_TE_HEADER}: {GRPC_TE_TRAILERS}\r\n\
         {GRPC_ENCODING_HEADER}: {GRPC_IDENTITY_ENCODING}\r\n\
         {GRPC_ACCEPT_ENCODING_HEADER}: {GRPC_IDENTITY_ENCODING}\r\n\r\n"
    )
    .into_bytes())
}

pub fn grpc_hunk_frame(payload: &[u8]) -> Result<Vec<u8>, OutboundError> {
    let message = grpc_hunk_message(payload)?;
    if message.len() > u32::MAX as usize {
        return Err(OutboundError::BadSharedTransport(
            "grpc hunk too large".to_owned(),
        ));
    }
    let mut frame = Vec::with_capacity(message.len() + 5);
    frame.push(0);
    frame.extend_from_slice(&(message.len() as u32).to_be_bytes());
    frame.extend_from_slice(&message);
    Ok(frame)
}

pub fn grpc_multi_hunk_frame(payloads: &[&[u8]]) -> Result<Vec<u8>, OutboundError> {
    let mut message = Vec::new();
    for payload in payloads {
        message.push(0x0a);
        push_grpc_varint(payload.len() as u64, &mut message);
        message.extend_from_slice(payload);
    }
    grpc_frame_message(message, "grpc MultiHunk")
}

pub fn grpc_data_frame(mode: GrpcMode, payload: &[u8]) -> Result<Vec<u8>, OutboundError> {
    match mode {
        GrpcMode::Gun => grpc_hunk_frame(payload),
        GrpcMode::Multi => grpc_multi_hunk_frame(&[payload]),
    }
}

pub fn grpc_hunk_frame_len(payload: &[u8]) -> Result<usize, OutboundError> {
    Ok(grpc_hunk_frame(payload)?.len())
}

pub fn grpc_hunk_message(payload: &[u8]) -> Result<Vec<u8>, OutboundError> {
    let mut message = Vec::with_capacity(1 + grpc_varint_len(payload.len() as u64) + payload.len());
    message.push(0x0a);
    push_grpc_varint(payload.len() as u64, &mut message);
    message.extend_from_slice(payload);
    Ok(message)
}

pub fn grpc_hunk_payload(message: &[u8]) -> Result<Vec<u8>, OutboundError> {
    grpc_hunk_payload_ref(message).map(<[u8]>::to_vec)
}

pub fn grpc_hunk_payload_ref(message: &[u8]) -> Result<&[u8], OutboundError> {
    let mut cursor = 0;
    let mut data = None;
    while cursor < message.len() {
        let tag = read_grpc_varint(message, &mut cursor)?;
        let field = tag >> 3;
        let wire_type = tag & 0x07;
        match (field, wire_type) {
            (1, 2) => {
                let len = grpc_len_as_usize(read_grpc_varint(message, &mut cursor)?)?;
                let end = cursor.checked_add(len).ok_or_else(|| {
                    OutboundError::BadSharedTransport("grpc Hunk data length overflows".to_owned())
                })?;
                if end > message.len() {
                    return Err(OutboundError::BadSharedTransport(
                        "grpc Hunk data is truncated".to_owned(),
                    ));
                }
                data = Some(&message[cursor..end]);
                cursor = end;
            }
            (_, 0) => {
                let _ = read_grpc_varint(message, &mut cursor)?;
            }
            (_, 1) => {
                cursor = cursor.checked_add(8).ok_or_else(|| {
                    OutboundError::BadSharedTransport(
                        "grpc Hunk fixed64 field length overflows".to_owned(),
                    )
                })?;
                if cursor > message.len() {
                    return Err(OutboundError::BadSharedTransport(
                        "grpc Hunk fixed64 field is truncated".to_owned(),
                    ));
                }
            }
            (_, 2) => {
                let len = grpc_len_as_usize(read_grpc_varint(message, &mut cursor)?)?;
                cursor = cursor.checked_add(len).ok_or_else(|| {
                    OutboundError::BadSharedTransport(
                        "grpc Hunk length-delimited field overflows".to_owned(),
                    )
                })?;
                if cursor > message.len() {
                    return Err(OutboundError::BadSharedTransport(
                        "grpc Hunk length-delimited field is truncated".to_owned(),
                    ));
                }
            }
            (_, 5) => {
                cursor = cursor.checked_add(4).ok_or_else(|| {
                    OutboundError::BadSharedTransport(
                        "grpc Hunk fixed32 field length overflows".to_owned(),
                    )
                })?;
                if cursor > message.len() {
                    return Err(OutboundError::BadSharedTransport(
                        "grpc Hunk fixed32 field is truncated".to_owned(),
                    ));
                }
            }
            (_, _) => {
                return Err(OutboundError::BadSharedTransport(format!(
                    "unsupported grpc Hunk protobuf wire type {wire_type}"
                )));
            }
        }
    }
    Ok(data.unwrap_or_default())
}

pub fn grpc_multi_hunk_payloads(message: &[u8]) -> Result<Vec<&[u8]>, OutboundError> {
    let mut cursor = 0;
    let mut payloads = Vec::new();
    while cursor < message.len() {
        let tag = read_grpc_varint(message, &mut cursor)?;
        if tag != 0x0a {
            return Err(OutboundError::BadSharedTransport(format!(
                "unsupported grpc MultiHunk protobuf tag {tag}"
            )));
        }
        let len = grpc_len_as_usize(read_grpc_varint(message, &mut cursor)?)?;
        let end = cursor.checked_add(len).ok_or_else(|| {
            OutboundError::BadSharedTransport("grpc MultiHunk data length overflows".to_owned())
        })?;
        if end > message.len() {
            return Err(OutboundError::BadSharedTransport(
                "grpc MultiHunk data is truncated".to_owned(),
            ));
        }
        payloads.push(&message[cursor..end]);
        cursor = end;
    }
    Ok(payloads)
}

fn grpc_frame_message(message: Vec<u8>, context: &str) -> Result<Vec<u8>, OutboundError> {
    if message.len() > u32::MAX as usize {
        return Err(OutboundError::BadSharedTransport(format!(
            "{context} too large"
        )));
    }
    let mut frame = Vec::with_capacity(message.len() + 5);
    frame.push(0);
    frame.extend_from_slice(&(message.len() as u32).to_be_bytes());
    frame.extend_from_slice(&message);
    Ok(frame)
}

pub fn read_grpc_hunk_frame(stream: &mut impl Read) -> Result<Vec<u8>, OutboundError> {
    let mut head = [0_u8; 5];
    stream
        .read_exact(&mut head)
        .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
    if head[0] != 0 {
        return Err(OutboundError::BadSharedTransport(
            "compressed grpc hunk unsupported by resident matrix harness".to_owned(),
        ));
    }
    let len = u32::from_be_bytes([head[1], head[2], head[3], head[4]]) as usize;
    if len > GRPC_MAX_HUNK_MESSAGE_BYTES {
        return Err(OutboundError::BadSharedTransport(format!(
            "grpc hunk message too large: {len} bytes"
        )));
    }
    let mut message = vec![0_u8; len];
    stream
        .read_exact(&mut message)
        .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
    grpc_hunk_payload(&message)
}

pub fn grpc_hunk_exchange(
    endpoint: &str,
    options: &GrpcLifecycleOptions,
    payload: &[u8],
    timeout: Duration,
) -> Result<GrpcLifecycleReport, OutboundError> {
    let mut stream = TcpStream::connect(endpoint)
        .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
    set_timeout(&stream, timeout)?;
    stream
        .write_all(&grpc_stream_preface(&options.service_name)?)
        .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
    stream
        .write_all(&grpc_hunk_frame(payload)?)
        .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
    let echoed_payload = read_grpc_hunk_frame(&mut stream)?;
    Ok(GrpcLifecycleReport {
        transport: "grpc-hunk",
        service_name: if options.service_name.is_empty() {
            "GunService".to_owned()
        } else {
            options.service_name.clone()
        },
        cache_key: options.cache_key(),
        payload_len: payload.len(),
        echoed_payload,
        stream_harness: true,
        full_grpc_http2_stack: false,
    })
}

fn set_timeout(stream: &TcpStream, timeout: Duration) -> Result<(), OutboundError> {
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))
}

fn push_grpc_varint(mut value: u64, out: &mut Vec<u8>) {
    while value >= 0x80 {
        out.push((value as u8 & 0x7f) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

fn read_grpc_varint(input: &[u8], cursor: &mut usize) -> Result<u64, OutboundError> {
    let mut value = 0_u64;
    for shift in (0..64).step_by(7) {
        if *cursor >= input.len() {
            return Err(OutboundError::BadSharedTransport(
                "grpc Hunk protobuf varint is truncated".to_owned(),
            ));
        }
        let byte = input[*cursor];
        *cursor += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err(OutboundError::BadSharedTransport(
        "grpc Hunk protobuf varint overflows u64".to_owned(),
    ))
}

fn grpc_varint_len(mut value: u64) -> usize {
    let mut len = 1;
    while value >= 0x80 {
        value >>= 7;
        len += 1;
    }
    len
}

fn grpc_len_as_usize(value: u64) -> Result<usize, OutboundError> {
    usize::try_from(value).map_err(|_| {
        OutboundError::BadSharedTransport("grpc Hunk protobuf length exceeds usize".to_owned())
    })
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    #[test]
    fn read_grpc_hunk_frame_rejects_oversized_length_before_allocation() {
        let mut head = Vec::new();
        head.push(0); // uncompressed flag
        head.extend_from_slice(&u32::MAX.to_be_bytes());
        let mut reader = Cursor::new(head);
        let err = read_grpc_hunk_frame(&mut reader).unwrap_err();
        assert!(err.to_string().contains("too large"));
    }

    #[test]
    fn read_grpc_hunk_frame_accepts_bounded_message() {
        let payload = b"hello grpc";
        // message = protobuf field 1 (wire type 2, length-delimited) with the
        // Hunk data as its value
        let mut message = Vec::new();
        message.push(0x0a);
        message.push(payload.len() as u8);
        message.extend_from_slice(payload);
        let mut frame = Vec::new();
        frame.push(0);
        frame.extend_from_slice(&(message.len() as u32).to_be_bytes());
        frame.extend_from_slice(&message);
        let mut reader = Cursor::new(frame);
        let decoded = read_grpc_hunk_frame(&mut reader).unwrap();
        assert_eq!(decoded, payload);
    }

    use super::*;

    #[test]
    fn xray_official_grpc_paths_match_upstream_vectors() {
        assert_eq!(grpc_request_path("hello", GrpcMode::Gun), "/hello/Tun");
        assert_eq!(
            grpc_request_path("hello", GrpcMode::Multi),
            "/hello/TunMulti"
        );
        assert_eq!(
            grpc_request_path("hello/world!", GrpcMode::Gun),
            "/hello%2Fworld%21/Tun"
        );
        assert_eq!(
            grpc_request_path("/my/sample/path/tun_service|multi_service", GrpcMode::Gun),
            "/my/sample/path/tun_service"
        );
        assert_eq!(
            grpc_request_path("/my/sample/path/tun_service|multi_service", GrpcMode::Multi),
            "/my/sample/path/multi_service"
        );
        assert_eq!(
            grpc_request_path("/hello /world!/a|b", GrpcMode::Multi),
            "/hello%20/world%21/b"
        );
    }

    #[test]
    fn multi_hunk_uses_official_repeated_bytes_wire_shape() {
        let frame = grpc_multi_hunk_frame(&[b"a", b"bc"]).unwrap();
        assert_eq!(frame, [0, 0, 0, 0, 7, 0x0a, 1, b'a', 0x0a, 2, b'b', b'c']);
        let payloads = grpc_multi_hunk_payloads(&frame[5..]).unwrap();
        assert_eq!(payloads, [b"a".as_slice(), b"bc".as_slice()]);
    }

    #[test]
    fn unknown_grpc_mode_fails_closed() {
        assert!(GrpcMode::parse_link_value("guna").is_err());
        assert!(GrpcMode::parse_link_value("custom").is_err());
    }
}
