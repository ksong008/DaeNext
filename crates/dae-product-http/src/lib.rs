use serde_json::{Value, json};
use std::collections::HashMap;
use std::io::{self, Read};
use std::net::{IpAddr, TcpStream};
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

#[derive(Clone, Debug)]
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub query: HashMap<String, Vec<String>>,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

pub fn json_body(request: &HttpRequest) -> Result<Value, String> {
    if request.body.is_empty() {
        return Ok(json!({}));
    }
    serde_json::from_slice(&request.body).map_err(|err| format!("invalid json body: {err}"))
}

pub fn required_str<'a>(body: &'a Value, key: &str) -> Option<&'a str> {
    body.get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
}

pub fn string_array(body: &Value, key: &str) -> Vec<String> {
    body.get(key)
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

pub fn integer_array(body: &Value, key: &str) -> Vec<i64> {
    body.get(key)
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(|value| {
                    value
                        .as_i64()
                        .or_else(|| value.as_str().and_then(|value| value.parse::<i64>().ok()))
                })
                .collect()
        })
        .unwrap_or_default()
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ProductHttpRequestContext {
    pub peer_ip: Option<IpAddr>,
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

#[cfg(test)]
mod tests {
    use super::{HttpRequest, ProductHttpRequestContext, integer_array, json_body, string_array};
    use serde_json::json;
    use std::collections::HashMap;

    #[test]
    fn request_context_defaults_without_peer_identity() {
        assert_eq!(ProductHttpRequestContext::default().peer_ip, None);
    }

    #[test]
    fn request_body_helpers_preserve_product_parsing_contracts() {
        let request = HttpRequest {
            method: "POST".to_owned(),
            path: "/api/test".to_owned(),
            query: HashMap::new(),
            headers: HashMap::new(),
            body: br#"{"ids":[1,"2","invalid"],"names":["a",2]}"#.to_vec(),
        };
        let body = json_body(&request).unwrap();
        assert_eq!(integer_array(&body, "ids"), vec![1, 2]);
        assert_eq!(string_array(&body, "names"), vec!["a"]);
        assert_eq!(super::required_str(&body, "missing"), None);
        assert_eq!(body, json!({"ids": [1, "2", "invalid"], "names": ["a", 2]}));
    }
}
