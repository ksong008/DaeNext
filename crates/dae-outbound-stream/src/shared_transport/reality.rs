use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::OnceLock;
use std::time::Duration;

use crate::error::OutboundError;
use crate::shared_transport::ir;

pub const REALITY_CLIENT_VERSION_ENV: &str = "DAE_REALITY_CLIENT_VERSION";
pub const REALITY_VERSION: [u8; 3] = [26, 6, 27];
pub const REALITY_HARNESS_MAGIC: &[u8; 10] = b"DAEREALITY";

static REALITY_CLIENT_VERSION: OnceLock<[u8; 3]> = OnceLock::new();

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RealityMutationOptions {
    pub server_name: String,
    pub fingerprint: String,
    pub sid: [u8; 8],
    pub public_key: Vec<u8>,
    pub spider_x: String,
    pub unix_seconds: u32,
    pub entropy: [u8; 16],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RealityMutationReport {
    pub transport: &'static str,
    pub server_name: String,
    pub fingerprint: String,
    pub sid_hex: String,
    pub public_key_len: usize,
    pub spider_y: [i64; 10],
    pub session_id_hex: String,
    pub payload_len: usize,
    pub echoed_payload: Vec<u8>,
    pub mutation_harness: bool,
    pub full_utls_stack: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RealityHarnessMessage {
    pub session_id: [u8; 32],
    pub server_name: String,
    pub payload: Vec<u8>,
}

pub fn reality_client_version() -> [u8; 3] {
    *REALITY_CLIENT_VERSION.get_or_init(|| {
        std::env::var(REALITY_CLIENT_VERSION_ENV)
            .ok()
            .and_then(|value| parse_reality_client_version(&value))
            .unwrap_or(REALITY_VERSION)
    })
}

pub fn parse_reality_client_version(input: &str) -> Option<[u8; 3]> {
    let mut out = [0_u8; 3];
    let mut parts = input.split('.');
    for slot in &mut out {
        let part = parts.next()?;
        if part.is_empty() {
            return None;
        }
        let value = part.parse::<u16>().ok()?;
        *slot = u8::try_from(value).ok()?;
    }
    if parts.next().is_some() {
        return None;
    }
    Some(out)
}

impl RealityMutationOptions {
    pub fn new(
        server_name: impl Into<String>,
        fingerprint: impl Into<String>,
        sid_hex: &str,
        public_key: &str,
        spider_x: impl Into<String>,
        unix_seconds: u32,
        entropy_hex: &str,
    ) -> Result<Self, OutboundError> {
        let spider_x = spider_x.into();
        if !spider_x.starts_with('/') {
            return Err(OutboundError::BadSharedTransport(
                "invalid reality spiderX".to_owned(),
            ));
        }
        let entropy = fixed_hex::<16>(entropy_hex, "invalid reality entropy")?;
        Ok(Self {
            server_name: normalize_server_name(&server_name.into()),
            fingerprint: fingerprint.into(),
            sid: ir::reality_sid_decode(sid_hex)?,
            public_key: ir::reality_pbk_decode(public_key)?,
            spider_x,
            unix_seconds,
            entropy,
        })
    }
}

pub fn reality_session_id(options: &RealityMutationOptions) -> [u8; 32] {
    let mut session_id = [0_u8; 32];
    session_id[..3].copy_from_slice(&reality_client_version());
    session_id[3] = 0;
    session_id[4..8].copy_from_slice(&options.unix_seconds.to_be_bytes());
    session_id[8..16].copy_from_slice(&options.sid);
    session_id[16..].copy_from_slice(&options.entropy);
    session_id
}

pub fn reality_mutation_report(
    options: &RealityMutationOptions,
    echoed_payload: Vec<u8>,
    payload_len: usize,
) -> RealityMutationReport {
    RealityMutationReport {
        transport: "reality-mutation",
        server_name: options.server_name.clone(),
        fingerprint: options.fingerprint.clone(),
        sid_hex: hex_encode(&options.sid),
        public_key_len: options.public_key.len(),
        spider_y: ir::reality_spider_y(&options.spider_x),
        session_id_hex: hex_encode(&reality_session_id(options)),
        payload_len,
        echoed_payload,
        mutation_harness: true,
        full_utls_stack: false,
    }
}

pub fn reality_mutation_exchange(
    endpoint: &str,
    options: &RealityMutationOptions,
    payload: &[u8],
    timeout: Duration,
) -> Result<RealityMutationReport, OutboundError> {
    let mut stream = TcpStream::connect(endpoint)
        .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
    set_timeout(&stream, timeout)?;
    write_reality_harness_message(&mut stream, options, payload)?;
    let echoed_payload = read_len_payload(&mut stream)?;
    Ok(reality_mutation_report(
        options,
        echoed_payload,
        payload.len(),
    ))
}

pub fn write_reality_harness_message(
    stream: &mut TcpStream,
    options: &RealityMutationOptions,
    payload: &[u8],
) -> Result<(), OutboundError> {
    if options.server_name.len() > u8::MAX as usize || payload.len() > u16::MAX as usize {
        return Err(OutboundError::BadSharedTransport(
            "reality harness message too large".to_owned(),
        ));
    }
    stream
        .write_all(REALITY_HARNESS_MAGIC)
        .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
    stream
        .write_all(&reality_session_id(options))
        .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
    stream
        .write_all(&[options.server_name.len() as u8])
        .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
    stream
        .write_all(options.server_name.as_bytes())
        .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
    write_len_payload(stream, payload)
}

pub fn read_reality_harness_message(
    stream: &mut TcpStream,
) -> Result<RealityHarnessMessage, OutboundError> {
    let mut magic = [0_u8; 10];
    stream
        .read_exact(&mut magic)
        .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
    if &magic != REALITY_HARNESS_MAGIC {
        return Err(OutboundError::BadSharedTransport(
            "bad reality harness magic".to_owned(),
        ));
    }
    let mut session_id = [0_u8; 32];
    stream
        .read_exact(&mut session_id)
        .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
    let mut len = [0_u8; 1];
    stream
        .read_exact(&mut len)
        .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
    let mut server_name = vec![0_u8; len[0] as usize];
    stream
        .read_exact(&mut server_name)
        .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
    let payload = read_len_payload(stream)?;
    Ok(RealityHarnessMessage {
        session_id,
        server_name: String::from_utf8(server_name)
            .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?,
        payload,
    })
}

pub fn write_len_payload(stream: &mut TcpStream, payload: &[u8]) -> Result<(), OutboundError> {
    if payload.len() > u16::MAX as usize {
        return Err(OutboundError::BadSharedTransport(
            "payload too large".to_owned(),
        ));
    }
    stream
        .write_all(&(payload.len() as u16).to_be_bytes())
        .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
    stream
        .write_all(payload)
        .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))
}

pub fn read_len_payload(stream: &mut TcpStream) -> Result<Vec<u8>, OutboundError> {
    let mut len = [0_u8; 2];
    stream
        .read_exact(&mut len)
        .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
    let mut payload = vec![0_u8; u16::from_be_bytes(len) as usize];
    stream
        .read_exact(&mut payload)
        .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
    Ok(payload)
}

fn normalize_server_name(server_name: &str) -> String {
    if server_name.eq_ignore_ascii_case("nosni") {
        String::new()
    } else {
        server_name.to_owned()
    }
}

fn fixed_hex<const N: usize>(input: &str, err: &str) -> Result<[u8; N], OutboundError> {
    let decoded = hex_decode(input)?;
    if decoded.len() != N {
        return Err(OutboundError::BadSharedTransport(err.to_owned()));
    }
    let mut out = [0_u8; N];
    out.copy_from_slice(&decoded);
    Ok(out)
}

fn hex_decode(input: &str) -> Result<Vec<u8>, OutboundError> {
    if !input.len().is_multiple_of(2) {
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

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn set_timeout(stream: &TcpStream, timeout: Duration) -> Result<(), OutboundError> {
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reality_client_version_parser_accepts_three_u8_parts() {
        assert_eq!(parse_reality_client_version("26.6.27"), Some([26, 6, 27]));
        assert_eq!(parse_reality_client_version("0.0.0"), Some([0, 0, 0]));
        assert_eq!(
            parse_reality_client_version("255.255.255"),
            Some([255, 255, 255])
        );
    }

    #[test]
    fn reality_client_version_parser_rejects_invalid_shapes() {
        for input in ["", "26.6", "26.6.27.1", "26..27", "256.6.27", "x.6.27"] {
            assert_eq!(parse_reality_client_version(input), None);
        }
    }
}
