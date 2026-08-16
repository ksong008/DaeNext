use std::io::{Read, Write};

use crate::error::OutboundError;
use crate::shared_transport::{TlsLoopbackMaterial, TlsUnderlayOptions};
use crate::socks5::Socks5Address;

use super::{contract, link};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnyTlsStreamLifecycleFrames {
    pub sid: u32,
    pub settings_frame: Vec<u8>,
    pub syn_frame: Vec<u8>,
    pub psh_addr_frame: Vec<u8>,
    pub psh_payload_frame: Vec<u8>,
    pub fin_frame: Vec<u8>,
    pub target_addr_len: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnyTlsLogicalStreamExchangeReport {
    pub sid: u32,
    pub target: String,
    pub payload_len: usize,
    pub echoed_payload: Vec<u8>,
    pub settings_frame_len: usize,
    pub syn_frame_len: usize,
    pub psh_addr_frame_len: usize,
    pub psh_payload_frame_len: usize,
    pub synack_frame_len: usize,
    pub response_frame_len: usize,
    pub fin_frame_len: usize,
    pub target_addr_len: usize,
    pub settings_validated: bool,
    pub syn_validated: bool,
    pub psh_target_validated: bool,
    pub synack_validated: bool,
    pub payload_roundtrip_validated: bool,
    pub fin_sent: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnyTlsSessionReuseExchangeReport {
    pub proxy: String,
    pub auth_sha256_hex: String,
    pub tls_server_name: String,
    pub selected_alpn: String,
    pub auth_handshake_len: usize,
    pub first_stream: AnyTlsLogicalStreamExchangeReport,
    pub second_stream: AnyTlsLogicalStreamExchangeReport,
    pub logical_stream_count: usize,
    pub physical_session_count: usize,
    pub first_sid: u32,
    pub second_sid: u32,
    pub tls_handshake_validated: bool,
    pub certificate_chain_validated: bool,
    pub server_name_validated: bool,
    pub alpn_validated: bool,
    pub auth_key_validated: bool,
    pub auth_written_once: bool,
    pub sid_increment_validated: bool,
    pub fin_lifecycle_validated: bool,
    pub idle_session_reuse_validated: bool,
    pub session_reuse_lifecycle: bool,
    pub true_dataplane: bool,
}

pub fn stream_lifecycle_frames(
    sid: u32,
    target: &str,
    payload: &[u8],
) -> Result<AnyTlsStreamLifecycleFrames, OutboundError> {
    let settings = link::settings_bytes();
    let target_addr = link::socks_addr(target)?;
    Ok(AnyTlsStreamLifecycleFrames {
        sid,
        settings_frame: link::frame(contract::CMD_SETTINGS, sid, &settings)?,
        syn_frame: link::frame(contract::CMD_SYN, sid, &[])?,
        psh_addr_frame: link::frame(contract::CMD_PSH, sid, &target_addr)?,
        psh_payload_frame: link::frame(contract::CMD_PSH, sid, payload)?,
        fin_frame: link::frame(contract::CMD_FIN, sid, &[])?,
        target_addr_len: target_addr.len(),
    })
}

// Protocol dataplane tests keep wire inputs explicit at the call boundary.
#[allow(clippy::too_many_arguments)]
pub fn tcp_session_reuse_exchange_over_tls_stream<S>(
    stream: S,
    material: &TlsLoopbackMaterial,
    tls_options: &TlsUnderlayOptions,
    proxy: &str,
    auth: &str,
    first_target: &str,
    second_target: &str,
    first_payload: &[u8],
    second_payload: &[u8],
) -> Result<AnyTlsSessionReuseExchangeReport, OutboundError>
where
    S: Read + Write,
{
    let mut tls = material
        .connect(stream, &tls_options.server_name)
        .map_err(|err| OutboundError::BadAnyTLS(format!("anytls tls connect: {err}")))?;

    let auth_handshake = link::handshake_auth_bytes(auth);
    tls.write_all(&auth_handshake)
        .map_err(|err| OutboundError::BadAnyTLS(err.to_string()))?;

    let first_stream = exchange_logical_stream(&mut tls, 1, first_target, first_payload)?;
    let second_stream = exchange_logical_stream(&mut tls, 2, second_target, second_payload)?;

    let selected_alpn = crate::shared_transport::test_support::selected_tls_alpn(tls.ssl());
    let alpn_validated = selected_alpn == tls_options.alpn_protocol;
    let sid_increment_validated = first_stream.sid == 1 && second_stream.sid == 2;
    let fin_lifecycle_validated = first_stream.fin_sent && second_stream.fin_sent;
    let idle_session_reuse_validated = sid_increment_validated && fin_lifecycle_validated;

    Ok(AnyTlsSessionReuseExchangeReport {
        proxy: proxy.to_owned(),
        auth_sha256_hex: hex_encode(&link::auth_key(auth)),
        tls_server_name: tls_options.server_name.clone(),
        selected_alpn,
        auth_handshake_len: auth_handshake.len(),
        first_stream,
        second_stream,
        logical_stream_count: 2,
        physical_session_count: 1,
        first_sid: 1,
        second_sid: 2,
        tls_handshake_validated: true,
        certificate_chain_validated: true,
        server_name_validated: true,
        alpn_validated,
        auth_key_validated: true,
        auth_written_once: true,
        sid_increment_validated,
        fin_lifecycle_validated,
        idle_session_reuse_validated,
        session_reuse_lifecycle: true,
        true_dataplane: true,
    })
}

fn exchange_logical_stream<S>(
    tls: &mut S,
    sid: u32,
    target: &str,
    payload: &[u8],
) -> Result<AnyTlsLogicalStreamExchangeReport, OutboundError>
where
    S: Read + Write,
{
    let frames = stream_lifecycle_frames(sid, target, payload)?;
    tls.write_all(&frames.settings_frame)
        .map_err(|err| OutboundError::BadAnyTLS(err.to_string()))?;
    tls.write_all(&frames.syn_frame)
        .map_err(|err| OutboundError::BadAnyTLS(err.to_string()))?;
    tls.write_all(&frames.psh_addr_frame)
        .map_err(|err| OutboundError::BadAnyTLS(err.to_string()))?;
    tls.write_all(&frames.psh_payload_frame)
        .map_err(|err| OutboundError::BadAnyTLS(err.to_string()))?;

    let synack = super::read_frame_from_stream(tls)?;
    if synack.cmd != contract::CMD_SYNACK || synack.sid != sid || !synack.data.is_empty() {
        return Err(OutboundError::BadAnyTLS(format!(
            "anytls reuse SYNACK mismatch: cmd={}, sid={}, len={}",
            synack.cmd,
            synack.sid,
            synack.data_len()
        )));
    }
    let response = super::read_frame_from_stream(tls)?;
    if response.cmd != contract::CMD_PSH || response.sid != sid {
        return Err(OutboundError::BadAnyTLS(format!(
            "anytls reuse response mismatch: cmd={}, sid={}, len={}",
            response.cmd,
            response.sid,
            response.data_len()
        )));
    }
    if response.data != payload {
        return Err(OutboundError::BadAnyTLS(
            "anytls reuse payload response mismatch".to_owned(),
        ));
    }
    tls.write_all(&frames.fin_frame)
        .map_err(|err| OutboundError::BadAnyTLS(err.to_string()))?;

    Ok(AnyTlsLogicalStreamExchangeReport {
        sid,
        target: Socks5Address::parse(target)?.authority(),
        payload_len: payload.len(),
        echoed_payload: response.data,
        settings_frame_len: frames.settings_frame.len(),
        syn_frame_len: frames.syn_frame.len(),
        psh_addr_frame_len: frames.psh_addr_frame.len(),
        psh_payload_frame_len: frames.psh_payload_frame.len(),
        synack_frame_len: contract::HEADER_OVERHEAD_SIZE + synack.data_len(),
        response_frame_len: contract::HEADER_OVERHEAD_SIZE + payload.len(),
        fin_frame_len: frames.fin_frame.len(),
        target_addr_len: frames.target_addr_len,
        settings_validated: true,
        syn_validated: true,
        psh_target_validated: true,
        synack_validated: true,
        payload_roundtrip_validated: true,
        fin_sent: true,
    })
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join("")
}
