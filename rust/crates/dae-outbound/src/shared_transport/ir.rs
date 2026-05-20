use base64::{Engine as _, engine::general_purpose};
use serde_json::Value;

use crate::error::OutboundError;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct XHttpModeResult {
    pub normalized: String,
    pub ok: bool,
    pub error_contains: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct XHttpAlpnResult {
    pub ok: bool,
    pub use_h3: bool,
    pub error_contains: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct XHttpPathResult {
    pub path: String,
    pub query: String,
}

pub fn parse_bool(value: &str) -> bool {
    matches!(value, "1" | "t" | "T" | "TRUE" | "true" | "True")
}

pub fn reality_sid_decode(input: &str) -> Result<[u8; 8], OutboundError> {
    let decoded = hex_decode(input)?;
    if decoded.len() != 8 {
        return Err(OutboundError::BadSharedTransport(
            "invalid reality sid".to_owned(),
        ));
    }
    let mut out = [0_u8; 8];
    out.copy_from_slice(&decoded);
    Ok(out)
}

pub fn reality_pbk_decode(input: &str) -> Result<Vec<u8>, OutboundError> {
    let decoded = general_purpose::URL_SAFE_NO_PAD
        .decode(input)
        .or_else(|_| general_purpose::URL_SAFE.decode(input))
        .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
    if decoded.len() != 32 {
        return Err(OutboundError::BadSharedTransport(
            "invalid reality pbk".to_owned(),
        ));
    }
    Ok(decoded)
}

pub fn reality_spider_y(spx: &str) -> [i64; 10] {
    let mut out = [0_i64; 10];
    let query = spx.split_once('?').map(|(_, query)| query).unwrap_or("");
    for pair in query.split('&') {
        let Some((key, value)) = pair.split_once('=') else {
            continue;
        };
        let index = match key {
            "p" => 0,
            "c" => 2,
            "t" => 4,
            "i" => 6,
            "r" => 8,
            _ => continue,
        };
        let (first, second) = value.split_once('-').unwrap_or((value, value));
        out[index] = parse_i64_digits(first);
        out[index + 1] = parse_i64_digits(second);
    }
    out
}

pub fn grpc_cache_key(
    address: &str,
    server_name: &str,
    dialer_id: &str,
    allow_insecure: bool,
    mark: u32,
    mptcp: bool,
) -> String {
    let magic = magic_network_encode("tcp", mark, mptcp);
    let magic = general_purpose::URL_SAFE_NO_PAD.encode(magic);
    format!(
        "{address}|{server_name}|{dialer_id}|{}|magic:{magic}",
        if allow_insecure { "true" } else { "false" },
    )
}

pub fn normalize_xhttp_mode(
    mode: &str,
    scheme: &str,
    security: &str,
    has_download_settings: bool,
) -> XHttpModeResult {
    let mode = mode.trim().to_ascii_lowercase();
    match mode.as_str() {
        "" | "auto" => {
            if scheme != "https" {
                return xhttp_mode_err("auto mode without tls is not supported yet");
            }
            if security.eq_ignore_ascii_case("reality") {
                if has_download_settings {
                    return xhttp_mode_ok("stream-up");
                }
                return xhttp_mode_ok("stream-one");
            }
            xhttp_mode_ok("packet-up")
        }
        "stream-up" => xhttp_mode_ok(&mode),
        "stream-one" => {
            if scheme == "https" {
                xhttp_mode_ok(&mode)
            } else {
                xhttp_mode_err("stream-one without tls is not supported yet")
            }
        }
        "packet-up" => {
            if scheme == "https" {
                xhttp_mode_ok(&mode)
            } else {
                xhttp_mode_err("packet-up without tls is not supported yet")
            }
        }
        _ => xhttp_mode_err("unsupported mode"),
    }
}

pub fn validate_xhttp_alpn(security: &str, alpn: &str) -> XHttpAlpnResult {
    if !security.eq_ignore_ascii_case("tls") && !security.eq_ignore_ascii_case("reality") {
        return xhttp_alpn_ok(alpn, false);
    }
    if should_use_h3(alpn) {
        if security.eq_ignore_ascii_case("reality") {
            return xhttp_alpn_err("reality with h3 is not supported");
        }
        return xhttp_alpn_ok(alpn, true);
    }
    if should_use_http1(alpn) || supports_h2(alpn) {
        return xhttp_alpn_ok(alpn, false);
    }
    xhttp_alpn_err("alpn")
}

pub fn normalize_xhttp_path_and_query(input: &str) -> XHttpPathResult {
    let (mut path, query) = input.split_once('?').unwrap_or((input, ""));
    if path.is_empty() {
        path = "/";
    }
    let mut normalized = path.to_owned();
    if !normalized.starts_with('/') {
        normalized.insert(0, '/');
    }
    if !normalized.ends_with('/') {
        normalized.push('/');
    }
    XHttpPathResult {
        path: normalized,
        query: query.to_owned(),
    }
}

pub fn canonical_json(raw: &str) -> Result<String, OutboundError> {
    let value = serde_json::from_str::<Value>(raw)
        .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
    serde_json::to_string(&value).map_err(|err| OutboundError::BadSharedTransport(err.to_string()))
}

pub fn magic_network_encode(network: &str, mark: u32, mptcp: bool) -> Vec<u8> {
    let network_bytes = network.as_bytes();
    let mut out = Vec::with_capacity(2 + network_bytes.len() + 4 + 1);
    out.push(0);
    out.push(network_bytes.len() as u8);
    out.extend_from_slice(network_bytes);
    out.extend_from_slice(&mark.to_be_bytes());
    out.push(u8::from(mptcp));
    out
}

fn xhttp_mode_ok(normalized: &str) -> XHttpModeResult {
    XHttpModeResult {
        normalized: normalized.to_owned(),
        ok: true,
        error_contains: String::new(),
    }
}

fn xhttp_mode_err(error_contains: &str) -> XHttpModeResult {
    XHttpModeResult {
        normalized: String::new(),
        ok: false,
        error_contains: error_contains.to_owned(),
    }
}

fn xhttp_alpn_ok(alpn: &str, use_h3: bool) -> XHttpAlpnResult {
    XHttpAlpnResult {
        ok: true,
        use_h3: use_h3 && should_use_h3(alpn),
        error_contains: String::new(),
    }
}

fn xhttp_alpn_err(error_contains: &str) -> XHttpAlpnResult {
    XHttpAlpnResult {
        ok: false,
        use_h3: false,
        error_contains: error_contains.to_owned(),
    }
}

fn should_use_h3(alpn: &str) -> bool {
    let mut parts = alpn.split(',');
    let first = parts.next().unwrap_or_default();
    parts.next().is_none() && first.trim().eq_ignore_ascii_case("h3")
}

fn should_use_http1(alpn: &str) -> bool {
    let mut parts = alpn.split(',');
    let first = parts.next().unwrap_or_default();
    parts.next().is_none() && first.trim().eq_ignore_ascii_case("http/1.1")
}

fn supports_h2(alpn: &str) -> bool {
    if alpn.trim().is_empty() {
        return true;
    }
    alpn.split(',')
        .any(|part| part.trim().eq_ignore_ascii_case("h2"))
}

fn parse_i64_digits(input: &str) -> i64 {
    input.bytes().fold(0_i64, |acc, byte| {
        if byte.is_ascii_digit() {
            acc * 10 + i64::from(byte - b'0')
        } else {
            acc
        }
    })
}

fn hex_decode(input: &str) -> Result<Vec<u8>, OutboundError> {
    if input.len() % 2 != 0 {
        return Err(OutboundError::BadSharedTransport(
            "odd hex length".to_owned(),
        ));
    }
    input
        .as_bytes()
        .chunks(2)
        .map(|chunk| Ok((hex_nibble(chunk[0])? << 4) | hex_nibble(chunk[1])?))
        .collect()
}

fn hex_nibble(byte: u8) -> Result<u8, OutboundError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(OutboundError::BadSharedTransport(format!(
            "bad hex byte: {byte}"
        ))),
    }
}
