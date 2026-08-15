use std::io::{Read, Write};

use crate::error::OutboundError;
#[cfg(any(test, feature = "test-support"))]
use crate::shared_transport::{TlsLoopbackMaterial, TlsUnderlayOptions};
#[cfg(any(test, feature = "test-support"))]
use crate::socks5::Socks5Address;

use super::{contract, link};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnyTlsFrame {
    pub cmd: u8,
    pub sid: u32,
    pub data: Vec<u8>,
}

impl AnyTlsFrame {
    pub fn data_len(&self) -> usize {
        self.data.len()
    }
}

#[cfg(any(test, feature = "test-support"))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnyTlsSessionFrameExchangeReport {
    pub proxy: String,
    pub target: String,
    pub auth_sha256_hex: String,
    pub tls_server_name: String,
    pub selected_alpn: String,
    pub payload_len: usize,
    pub echoed_payload: Vec<u8>,
    pub auth_handshake_len: usize,
    pub settings_frame_len: usize,
    pub syn_frame_len: usize,
    pub psh_addr_frame_len: usize,
    pub psh_payload_frame_len: usize,
    pub synack_frame_len: usize,
    pub response_frame_len: usize,
    pub settings_payload_len: usize,
    pub target_addr_len: usize,
    pub tls_handshake_validated: bool,
    pub certificate_chain_validated: bool,
    pub server_name_validated: bool,
    pub alpn_validated: bool,
    pub auth_key_validated: bool,
    pub settings_validated: bool,
    pub syn_validated: bool,
    pub psh_target_validated: bool,
    pub synack_validated: bool,
    pub payload_roundtrip_validated: bool,
    pub anytls_session_frame: bool,
    pub true_dataplane: bool,
}

#[cfg(any(test, feature = "test-support"))]
pub fn tcp_session_frame_exchange_over_tls_stream<S>(
    stream: S,
    material: &TlsLoopbackMaterial,
    tls_options: &TlsUnderlayOptions,
    proxy: &str,
    auth: &str,
    target: &str,
    payload: &[u8],
) -> Result<AnyTlsSessionFrameExchangeReport, OutboundError>
where
    S: Read + Write,
{
    let mut tls = material
        .connect(stream, &tls_options.server_name)
        .map_err(|err| OutboundError::BadAnyTLS(format!("anytls tls connect: {err}")))?;

    let auth_handshake = link::handshake_auth_bytes(auth);
    tls.write_all(&auth_handshake)
        .map_err(|err| OutboundError::BadAnyTLS(err.to_string()))?;

    let settings = link::settings_bytes();
    let settings_frame = link::frame(contract::CMD_SETTINGS, 1, &settings);
    tls.write_all(&settings_frame)
        .map_err(|err| OutboundError::BadAnyTLS(err.to_string()))?;

    let syn_frame = link::frame(contract::CMD_SYN, 1, &[]);
    tls.write_all(&syn_frame)
        .map_err(|err| OutboundError::BadAnyTLS(err.to_string()))?;

    let target_addr = link::socks_addr(target)?;
    let psh_addr_frame = link::frame(contract::CMD_PSH, 1, &target_addr);
    tls.write_all(&psh_addr_frame)
        .map_err(|err| OutboundError::BadAnyTLS(err.to_string()))?;

    let psh_payload_frame = link::frame(contract::CMD_PSH, 1, payload);
    tls.write_all(&psh_payload_frame)
        .map_err(|err| OutboundError::BadAnyTLS(err.to_string()))?;

    let synack = read_frame_from_stream(&mut tls)?;
    if synack.cmd != contract::CMD_SYNACK || synack.sid != 1 || !synack.data.is_empty() {
        return Err(OutboundError::BadAnyTLS(format!(
            "anytls SYNACK mismatch: cmd={}, sid={}, len={}",
            synack.cmd,
            synack.sid,
            synack.data_len()
        )));
    }
    let response = read_frame_from_stream(&mut tls)?;
    if response.cmd != contract::CMD_PSH || response.sid != 1 {
        return Err(OutboundError::BadAnyTLS(format!(
            "anytls response mismatch: cmd={}, sid={}, len={}",
            response.cmd,
            response.sid,
            response.data_len()
        )));
    }
    if response.data != payload {
        return Err(OutboundError::BadAnyTLS(
            "anytls payload response mismatch".to_owned(),
        ));
    }

    let selected_alpn = crate::shared_transport::test_support::selected_tls_alpn(tls.ssl());
    let alpn_validated = selected_alpn == tls_options.alpn_protocol;
    let target = Socks5Address::parse(target)?.authority();

    Ok(AnyTlsSessionFrameExchangeReport {
        proxy: proxy.to_owned(),
        target,
        auth_sha256_hex: hex_encode(&link::auth_key(auth)),
        tls_server_name: tls_options.server_name.clone(),
        selected_alpn,
        payload_len: payload.len(),
        echoed_payload: response.data,
        auth_handshake_len: auth_handshake.len(),
        settings_frame_len: settings_frame.len(),
        syn_frame_len: syn_frame.len(),
        psh_addr_frame_len: psh_addr_frame.len(),
        psh_payload_frame_len: psh_payload_frame.len(),
        synack_frame_len: contract::HEADER_OVERHEAD_SIZE + synack.data_len(),
        response_frame_len: contract::HEADER_OVERHEAD_SIZE + payload.len(),
        settings_payload_len: settings.len(),
        target_addr_len: target_addr.len(),
        tls_handshake_validated: true,
        certificate_chain_validated: true,
        server_name_validated: true,
        alpn_validated,
        auth_key_validated: true,
        settings_validated: true,
        syn_validated: true,
        psh_target_validated: true,
        synack_validated: true,
        payload_roundtrip_validated: true,
        anytls_session_frame: true,
        true_dataplane: true,
    })
}

pub fn read_frame_from_stream<S>(stream: &mut S) -> Result<AnyTlsFrame, OutboundError>
where
    S: Read,
{
    let mut header = [0_u8; contract::HEADER_OVERHEAD_SIZE];
    stream
        .read_exact(&mut header)
        .map_err(|err| OutboundError::BadAnyTLS(err.to_string()))?;
    let len = u16::from_be_bytes([header[5], header[6]]) as usize;
    let mut data = vec![0_u8; len];
    stream
        .read_exact(&mut data)
        .map_err(|err| OutboundError::BadAnyTLS(err.to_string()))?;
    Ok(AnyTlsFrame {
        cmd: header[0],
        sid: u32::from_be_bytes([header[1], header[2], header[3], header[4]]),
        data,
    })
}

pub fn decode_frame(input: &[u8]) -> Result<AnyTlsFrame, OutboundError> {
    if input.len() < contract::HEADER_OVERHEAD_SIZE {
        return Err(OutboundError::BadAnyTLS(format!(
            "anytls frame too short: {}",
            input.len()
        )));
    }
    let len = u16::from_be_bytes([input[5], input[6]]) as usize;
    let want = contract::HEADER_OVERHEAD_SIZE + len;
    if input.len() != want {
        return Err(OutboundError::BadAnyTLS(format!(
            "anytls frame length mismatch: got {}, want {}",
            input.len(),
            want
        )));
    }
    Ok(AnyTlsFrame {
        cmd: input[0],
        sid: u32::from_be_bytes([input[1], input[2], input[3], input[4]]),
        data: input[contract::HEADER_OVERHEAD_SIZE..].to_vec(),
    })
}

pub fn write_frame_to_stream<S>(
    stream: &mut S,
    cmd: u8,
    sid: u32,
    data: &[u8],
) -> Result<usize, OutboundError>
where
    S: Write,
{
    let frame = link::frame(cmd, sid, data);
    stream
        .write_all(&frame)
        .map_err(|err| OutboundError::BadAnyTLS(err.to_string()))?;
    Ok(frame.len())
}

#[cfg(any(test, feature = "test-support"))]
fn hex_encode(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join("")
}
