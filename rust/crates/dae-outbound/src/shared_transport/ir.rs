use base64::{Engine as _, engine::general_purpose};
use serde_json::Value;

use crate::error::OutboundError;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct XHttpModeResult {
    pub normalized: String,
    pub ok: bool,
    pub error_contains: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct XHttpModeRefResult {
    pub normalized: &'static str,
    pub ok: bool,
    pub error_contains: &'static str,
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
    let mut magic_raw = [0_u8; 10];
    let magic_raw_len = write_magic_network_to_slice("tcp", mark, mptcp, &mut magic_raw);
    let magic = String::from_utf8_lossy(&magic_raw[..magic_raw_len]);
    let allow_insecure = if allow_insecure { "true" } else { "false" };
    let mut out = String::with_capacity(
        address.len()
            + server_name.len()
            + dialer_id.len()
            + allow_insecure.len()
            + magic.len()
            + 4,
    );
    out.push_str(address);
    out.push('|');
    out.push_str(server_name);
    out.push('|');
    out.push_str(dialer_id);
    out.push('|');
    out.push_str(allow_insecure);
    out.push('|');
    out.push_str(&magic);
    out
}

pub fn grpc_cache_key_lossless(
    address: &str,
    server_name: &str,
    dialer_id: &str,
    allow_insecure: bool,
    mark: u32,
    mptcp: bool,
) -> String {
    let mut magic_raw = [0_u8; 10];
    let magic_raw_len = write_magic_network_to_slice("tcp", mark, mptcp, &mut magic_raw);
    let mut magic_encoded = [0_u8; 16];
    let magic_len = general_purpose::URL_SAFE_NO_PAD
        .encode_slice(&magic_raw[..magic_raw_len], &mut magic_encoded)
        .expect("fixed grpc magic-network buffer is large enough");
    let magic = std::str::from_utf8(&magic_encoded[..magic_len])
        .expect("base64 output is always valid utf-8");
    let allow_insecure = if allow_insecure { "true" } else { "false" };
    let mut out = String::with_capacity(
        address.len()
            + server_name.len()
            + dialer_id.len()
            + allow_insecure.len()
            + "magic:".len()
            + magic.len()
            + 4,
    );
    out.push_str(address);
    out.push('|');
    out.push_str(server_name);
    out.push('|');
    out.push_str(dialer_id);
    out.push('|');
    out.push_str(allow_insecure);
    out.push_str("|magic:");
    out.push_str(magic);
    out
}

pub fn normalize_xhttp_mode(
    mode: &str,
    scheme: &str,
    security: &str,
    has_download_settings: bool,
) -> XHttpModeResult {
    let result = normalize_xhttp_mode_ref(mode, scheme, security, has_download_settings);
    XHttpModeResult {
        normalized: result.normalized.to_owned(),
        ok: result.ok,
        error_contains: result.error_contains.to_owned(),
    }
}

pub fn normalize_xhttp_mode_ref(
    mode: &str,
    scheme: &str,
    security: &str,
    has_download_settings: bool,
) -> XHttpModeRefResult {
    let mode = mode.trim();
    if mode.is_empty() || mode.eq_ignore_ascii_case("auto") {
        if scheme != "https" {
            return xhttp_mode_ref_err("auto mode without tls is not supported yet");
        }
        if security.eq_ignore_ascii_case("reality") {
            if has_download_settings {
                return xhttp_mode_ref_ok("stream-up");
            }
            return xhttp_mode_ref_ok("stream-one");
        }
        return xhttp_mode_ref_ok("packet-up");
    }
    if mode.eq_ignore_ascii_case("stream-up") {
        return xhttp_mode_ref_ok("stream-up");
    }
    if mode.eq_ignore_ascii_case("stream-one") {
        if scheme == "https" {
            return xhttp_mode_ref_ok("stream-one");
        }
        return xhttp_mode_ref_err("stream-one without tls is not supported yet");
    }
    if mode.eq_ignore_ascii_case("packet-up") {
        if scheme == "https" {
            return xhttp_mode_ref_ok("packet-up");
        }
        return xhttp_mode_ref_err("packet-up without tls is not supported yet");
    }
    xhttp_mode_ref_err("unsupported mode")
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
    write_magic_network_to(network_bytes, mark, mptcp, &mut out);
    out
}

fn write_magic_network_to_slice(network: &str, mark: u32, mptcp: bool, out: &mut [u8]) -> usize {
    let network_bytes = network.as_bytes();
    let needed = 2 + network_bytes.len() + 4 + 1;
    out[0] = 0;
    out[1] = network_bytes.len() as u8;
    out[2..2 + network_bytes.len()].copy_from_slice(network_bytes);
    let mark_offset = 2 + network_bytes.len();
    out[mark_offset..mark_offset + 4].copy_from_slice(&mark.to_be_bytes());
    out[mark_offset + 4] = u8::from(mptcp);
    needed
}

fn write_magic_network_to(network_bytes: &[u8], mark: u32, mptcp: bool, out: &mut Vec<u8>) {
    out.push(0);
    out.push(network_bytes.len() as u8);
    out.extend_from_slice(network_bytes);
    out.extend_from_slice(&mark.to_be_bytes());
    out.push(u8::from(mptcp));
}

fn xhttp_mode_ref_ok(normalized: &'static str) -> XHttpModeRefResult {
    XHttpModeRefResult {
        normalized,
        ok: true,
        error_contains: "",
    }
}

fn xhttp_mode_ref_err(error_contains: &'static str) -> XHttpModeRefResult {
    XHttpModeRefResult {
        normalized: "",
        ok: false,
        error_contains,
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
