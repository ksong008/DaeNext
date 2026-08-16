use base64::Engine;

use crate::error::OutboundError;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpTransportMode {
    pub enabled: bool,
    pub path: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpConnectOptions {
    pub target: String,
    pub username: String,
    pub password: String,
    pub host_override: String,
    pub transport: HttpTransportMode,
}

impl HttpConnectOptions {
    pub fn connect(target: impl Into<String>) -> Self {
        Self {
            target: target.into(),
            username: String::new(),
            password: String::new(),
            host_override: String::new(),
            transport: HttpTransportMode {
                enabled: false,
                path: "/".to_owned(),
            },
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpForwardRequest {
    pub method: String,
    pub path: String,
    pub host: String,
    pub headers: Vec<(String, String)>,
}

pub fn basic_auth_header(username: &str, password: &str) -> Option<String> {
    if username.is_empty() {
        return None;
    }
    let encoded =
        base64::engine::general_purpose::STANDARD.encode(format!("{username}:{password}"));
    Some(format!("Basic {encoded}"))
}

/// Rejects proxy authorities and header values that could smuggle request
/// lines or headers (CR/LF and other C0/C1 control characters).
///
/// `authority` flows from user-provided links whose query parameters are
/// percent-decoded by the URL parser, so a malicious subscription can carry
/// `%0d%0a` and previously reached the wire verbatim (header injection).
fn validate_http_authority(authority: &str) -> Result<(), OutboundError> {
    if authority.is_empty() {
        return Err(OutboundError::BadHttpProxy(
            "empty proxy authority".to_owned(),
        ));
    }
    if authority.chars().any(is_http_control_character) {
        return Err(OutboundError::BadHttpProxy(format!(
            "proxy authority contains control characters: {authority:?}"
        )));
    }
    Ok(())
}

/// Reject C0, DEL and C1 control characters without interpreting ordinary
/// UTF-8 continuation bytes as controls.
fn is_http_control_character(character: char) -> bool {
    character.is_control()
}

fn validate_http_header_value(value: &str, label: &str) -> Result<(), OutboundError> {
    if value.chars().any(is_http_control_character) {
        return Err(OutboundError::BadHttpProxy(format!(
            "{label} contains control characters"
        )));
    }
    Ok(())
}

/// RFC 7230 `token` production: `!#$%&'*+-.^_`|~` plus alphanumerics.
/// Header field names and request methods must be tokens; anything else can
/// desynchronise the rebuilt request line or header block.
fn is_http_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

fn validate_http_header_name(name: &str, label: &str) -> Result<(), OutboundError> {
    if name.is_empty() || !name.bytes().all(is_http_token_byte) {
        return Err(OutboundError::BadHttpProxy(format!(
            "{label} is not a valid HTTP token: {name:?}"
        )));
    }
    Ok(())
}

pub fn connect_request(options: &HttpConnectOptions) -> Result<Vec<u8>, OutboundError> {
    if options.transport.enabled {
        return transport_put_request(options);
    }
    let authority = if options.host_override.is_empty() {
        options.target.as_str()
    } else {
        options.host_override.as_str()
    };
    validate_http_authority(authority)?;
    let mut out = String::new();
    out.push_str("CONNECT ");
    out.push_str(authority);
    out.push_str(" HTTP/1.1\r\nHost: ");
    out.push_str(authority);
    out.push_str("\r\nUser-Agent: dae-rust-native/1.0\r\n");
    if let Some(auth) = basic_auth_header(&options.username, &options.password) {
        out.push_str("Proxy-Authorization: ");
        out.push_str(&auth);
        out.push_str("\r\n");
    }
    out.push_str("\r\n");
    Ok(out.into_bytes())
}

pub fn forward_http_request(raw: &[u8]) -> Result<Vec<u8>, OutboundError> {
    let request = parse_forward_request(raw)?;
    validate_http_authority(&request.host)?;
    validate_http_header_value(&request.path, "HTTP request path")?;
    validate_http_header_name(&request.method, "HTTP request method")?;
    let mut out = String::new();
    out.push_str(&request.method);
    out.push(' ');
    out.push_str("http://");
    out.push_str(&request.host);
    out.push_str(&request.path);
    out.push_str(" HTTP/1.1\r\nHost: ");
    out.push_str(&request.host);
    out.push_str("\r\nUser-Agent: dae-rust-native/1.0\r\n");
    for (name, value) in request.headers {
        if name.eq_ignore_ascii_case("host") || name.eq_ignore_ascii_case("proxy-connection") {
            continue;
        }
        // Header names and values flow from the client's original request
        // into the rebuilt one; reject anything that is not a token/visible
        // value so a crafted request cannot smuggle malformed fields.
        validate_http_header_name(&name, "HTTP header name")?;
        validate_http_header_value(&value, "HTTP header value")?;
        out.push_str(&name);
        out.push_str(": ");
        out.push_str(&value);
        out.push_str("\r\n");
    }
    out.push_str("\r\n");
    Ok(out.into_bytes())
}

pub fn parse_connect_response(input: &[u8]) -> Result<u16, OutboundError> {
    let text =
        std::str::from_utf8(input).map_err(|err| OutboundError::BadHttpProxy(err.to_string()))?;
    let line = text
        .split("\r\n")
        .next()
        .ok_or_else(|| OutboundError::BadHttpProxy("empty response".to_owned()))?;
    let mut parts = line.split_whitespace();
    let _version = parts
        .next()
        .ok_or_else(|| OutboundError::BadHttpProxy("missing response version".to_owned()))?;
    let status = parts
        .next()
        .ok_or_else(|| OutboundError::BadHttpProxy("missing response status".to_owned()))?
        .parse::<u16>()
        .map_err(|err| OutboundError::BadHttpProxy(err.to_string()))?;
    Ok(status)
}

fn transport_put_request(options: &HttpConnectOptions) -> Result<Vec<u8>, OutboundError> {
    let host = if options.host_override.is_empty() {
        "www.fixture.invalid"
    } else {
        options.host_override.as_str()
    };
    validate_http_authority(host)?;
    let path = if options.transport.path.is_empty() {
        "/"
    } else {
        options.transport.path.as_str()
    };
    validate_http_header_value(path, "HTTP transport path")?;
    let mut out = String::new();
    out.push_str("PUT http://");
    out.push_str(host);
    out.push_str(path);
    out.push_str(" HTTP/1.1\r\nHost: ");
    out.push_str(host);
    out.push_str("\r\nUser-Agent: dae-rust-native/1.0\r\nContent-Length: 0\r\n");
    if let Some(auth) = basic_auth_header(&options.username, &options.password) {
        out.push_str("Proxy-Authorization: ");
        out.push_str(&auth);
        out.push_str("\r\n");
    }
    out.push_str("\r\n");
    Ok(out.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options_with_host_override(host: &str) -> HttpConnectOptions {
        let mut options = HttpConnectOptions::connect("proxy.example:443");
        options.host_override = host.to_owned();
        options
    }

    #[test]
    fn connect_request_rejects_crlf_injected_host_override() {
        // A malicious subscription can percent-decode %0d%0a into the host
        // query parameter; the request builder must refuse it instead of
        // writing an injected header onto the wire.
        let options = options_with_host_override("front.example\r\nX-Injected: yes");
        assert!(connect_request(&options).is_err());
    }

    #[test]
    fn connect_request_rejects_control_characters_in_target() {
        let mut options = HttpConnectOptions::connect("proxy.example:443");
        options.target = "proxy.example:443\nInjected".to_owned();
        assert!(connect_request(&options).is_err());
    }

    #[test]
    fn transport_put_request_rejects_crlf_injected_host() {
        let mut options = HttpConnectOptions::connect("proxy.example:443");
        options.transport.enabled = true;
        options.host_override = "front.example\r\nX: y".to_owned();
        assert!(connect_request(&options).is_err());
    }

    #[test]
    fn connect_request_accepts_plain_authority() {
        let options = options_with_host_override("front.example");
        let request = connect_request(&options).unwrap();
        let text = String::from_utf8(request).unwrap();
        assert!(text.starts_with("CONNECT front.example HTTP/1.1\r\n"));
    }

    #[test]
    fn forward_http_request_rebuilds_valid_request() {
        let raw = b"GET / HTTP/1.1\r\nHost: origin.example\r\nX-A: 1\r\n\r\n";
        let request = forward_http_request(raw).unwrap();
        let text = String::from_utf8(request).unwrap();
        assert!(text.contains("Host: origin.example"));
    }

    #[test]
    fn forward_http_request_rejects_control_bytes_in_host_value() {
        // A stray 0x01 (or any C0 byte) inside the Host value must be
        // rejected instead of reaching the rebuilt request line.
        let raw = b"GET / HTTP/1.1\r\nHost: origin.example\x01X-Evil\r\n\r\n";
        assert!(forward_http_request(raw).is_err());
    }

    #[test]
    fn forward_http_request_rejects_c1_control_character_in_header_value() {
        let raw = "GET / HTTP/1.1\r\nHost: origin.example\r\nX-A: b\u{0085}c\r\n\r\n";
        assert!(forward_http_request(raw.as_bytes()).is_err());
    }

    #[test]
    fn forward_http_request_accepts_visible_unicode_header_value() {
        let raw = "GET / HTTP/1.1\r\nHost: origin.example\r\nX-Price: 10 \u{20ac}\r\n\r\n";
        let request = forward_http_request(raw.as_bytes()).unwrap();
        let text = String::from_utf8(request).unwrap();
        assert!(text.contains("X-Price: 10 \u{20ac}\r\n"));
    }

    #[test]
    fn forward_http_request_rejects_non_token_header_name() {
        let raw = b"GET / HTTP/1.1\r\nHost: origin.example\r\nBad Name: x\r\n\r\n";
        assert!(forward_http_request(raw).is_err());
    }

    #[test]
    fn forward_http_request_rejects_control_characters_in_header_value() {
        let raw = b"GET / HTTP/1.1\r\nHost: origin.example\r\nX-Test: a\x01b\r\n\r\n";
        assert!(forward_http_request(raw).is_err());
    }

    #[test]
    fn forward_http_request_rejects_non_token_method() {
        // \x01 is not whitespace, so it stays inside the method token and
        // must be rejected by the token check.
        let raw = b"GET\x01 / HTTP/1.1\r\nHost: origin.example\r\n\r\n";
        assert!(forward_http_request(raw).is_err());
    }
}

fn parse_forward_request(raw: &[u8]) -> Result<HttpForwardRequest, OutboundError> {
    let text =
        std::str::from_utf8(raw).map_err(|err| OutboundError::BadHttpProxy(err.to_string()))?;
    let (head, _) = text
        .split_once("\r\n\r\n")
        .ok_or_else(|| OutboundError::BadHttpProxy("incomplete HTTP request".to_owned()))?;
    let mut lines = head.split("\r\n");
    let first = lines
        .next()
        .ok_or_else(|| OutboundError::BadHttpProxy("missing request line".to_owned()))?;
    let mut first_parts = first.split_whitespace();
    let method = first_parts
        .next()
        .ok_or_else(|| OutboundError::BadHttpProxy("missing method".to_owned()))?
        .to_owned();
    let path = first_parts
        .next()
        .ok_or_else(|| OutboundError::BadHttpProxy("missing path".to_owned()))?
        .to_owned();
    let mut host = String::new();
    let mut headers = Vec::new();
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim().to_owned();
        let value = value.trim().to_owned();
        if name.eq_ignore_ascii_case("host") {
            host = value.clone();
        }
        headers.push((name, value));
    }
    if host.is_empty() {
        return Err(OutboundError::BadHttpProxy(
            "missing Host header".to_owned(),
        ));
    }
    Ok(HttpForwardRequest {
        method,
        path,
        host,
        headers,
    })
}
