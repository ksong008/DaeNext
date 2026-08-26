use serde_json::{Value, json};
use std::collections::HashMap;
use std::io::{self, Read};
use std::net::TcpStream;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

pub const MAX_BODY_BYTES: usize = 1 << 20;
pub const MAX_BUNDLE_BODY_BYTES: usize = 16 << 20;
pub const MAX_HTTP_HEADER_BYTES: usize = 64 << 10;
pub const MAX_HTTP_HEADER_COUNT: usize = 128;
pub const PRODUCT_HTTP_HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);
pub const PRODUCT_HTTP_HEADER_RATE_GRACE: Duration = Duration::from_secs(2);
pub const PRODUCT_HTTP_HEADER_MIN_BYTES_PER_SECOND: usize = 64;
pub const PRODUCT_HTTP_BODY_READ_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
pub const PRODUCT_HTTP_BODY_READ_TIMEOUT: Duration = Duration::from_secs(30);
pub const PRODUCT_HTTP_BUNDLE_BODY_READ_TIMEOUT: Duration = Duration::from_secs(300);
pub const DAE_BUNDLE_IMPORT_PATH: &str = "/api/user/me/dae-bundle";

pub fn split_path_query(raw: &str) -> (String, HashMap<String, Vec<String>>) {
    let (path, query) = raw.split_once('?').unwrap_or((raw, ""));
    let mut output = HashMap::new();
    for pair in query.split('&').filter(|pair| !pair.is_empty()) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        output
            .entry(percent_decode(key))
            .or_insert_with(Vec::new)
            .push(percent_decode(value));
    }
    (percent_decode(path), output)
}

pub fn percent_decode(value: &str) -> String {
    let mut output = Vec::with_capacity(value.len());
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' if index + 2 < bytes.len() => {
                if let (Some(high), Some(low)) =
                    (hex_value(bytes[index + 1]), hex_value(bytes[index + 2]))
                {
                    output.push((high << 4) | low);
                    index += 3;
                    continue;
                }
                output.push(bytes[index]);
                index += 1;
            }
            b'+' => {
                output.push(b' ');
                index += 1;
            }
            byte => {
                output.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&output).into_owned()
}

pub fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[derive(Debug)]
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub query: HashMap<String, Vec<String>>,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

#[derive(Debug)]
pub struct HttpResponse {
    pub status: u16,
    pub content_type: String,
    pub body: Vec<u8>,
    pub extra_headers: Vec<(String, String)>,
}

impl HttpResponse {
    pub fn json(status: u16, value: Value) -> Self {
        Self {
            status,
            content_type: "application/json".to_owned(),
            body: format!("{value}\n").into_bytes(),
            extra_headers: Vec::new(),
        }
    }

    pub fn text(status: u16, content_type: impl Into<String>, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            content_type: content_type.into(),
            body: body.into(),
            extra_headers: Vec::new(),
        }
    }

    pub fn empty(status: u16) -> Self {
        Self {
            status,
            content_type: "text/plain; charset=utf-8".to_owned(),
            body: Vec::new(),
            extra_headers: Vec::new(),
        }
    }

    pub fn with_status(mut self, status: u16) -> Self {
        self.status = status;
        self
    }
}

mod connections;
mod error;
mod job_queue;
mod listener_readiness;
mod metrics;
mod parser;
mod policy;

pub use connections::*;
pub use error::*;
pub use job_queue::*;
pub use listener_readiness::*;
pub use metrics::*;
pub use parser::*;
pub use policy::*;

pub fn http_request_read_error_response(error: &HttpRequestReadError) -> Option<HttpResponse> {
    match error.kind() {
        HttpRequestReadErrorKind::IdleHeaderTimeout
        | HttpRequestReadErrorKind::ConnectionClosed => None,
        HttpRequestReadErrorKind::PartialHeaderTimeout => Some(HttpResponse::json(
            408,
            json!({
                "error": "request header read timeout",
                "errorCode": "request_header_timeout",
                "retryable": true,
            }),
        )),
        HttpRequestReadErrorKind::BodyTimeout => Some(HttpResponse::json(
            408,
            json!({
                "error": "request body read timeout",
                "errorCode": "request_body_timeout",
                "retryable": true,
            }),
        )),
        HttpRequestReadErrorKind::InvalidRequest | HttpRequestReadErrorKind::Io => Some(
            HttpResponse::json(400, json!({"error": format!("bad request: {error}")})),
        ),
    }
}
