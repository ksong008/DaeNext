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

pub fn connect_request(options: &HttpConnectOptions) -> Vec<u8> {
    if options.transport.enabled {
        return transport_put_request(options);
    }
    let authority = if options.host_override.is_empty() {
        options.target.as_str()
    } else {
        options.host_override.as_str()
    };
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
    out.into_bytes()
}

pub fn forward_http_request(raw: &[u8]) -> Result<Vec<u8>, OutboundError> {
    let request = parse_forward_request(raw)?;
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

fn transport_put_request(options: &HttpConnectOptions) -> Vec<u8> {
    let host = if options.host_override.is_empty() {
        "www.fixture.invalid"
    } else {
        options.host_override.as_str()
    };
    let path = if options.transport.path.is_empty() {
        "/"
    } else {
        options.transport.path.as_str()
    };
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
    out.into_bytes()
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
