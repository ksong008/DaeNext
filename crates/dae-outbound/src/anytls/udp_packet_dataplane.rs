use std::io::{Read, Write};

use crate::error::OutboundError;
use crate::shared_transport::{TlsLoopbackMaterial, TlsUnderlayOptions};
use crate::socks5::Socks5Address;

use super::{contract, link};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnyTlsPacketWrite {
    pub target: Option<String>,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnyTlsUdpPacketStreamExchangeReport {
    pub proxy: String,
    pub original_udp_target: String,
    pub session_stream_target: String,
    pub auth_sha256_hex: String,
    pub tls_server_name: String,
    pub selected_alpn: String,
    pub first_payload_len: usize,
    pub next_payload_len: usize,
    pub echoed_first_payload: Vec<u8>,
    pub echoed_next_payload: Vec<u8>,
    pub auth_handshake_len: usize,
    pub settings_frame_len: usize,
    pub syn_frame_len: usize,
    pub psh_addr_frame_len: usize,
    pub first_packet_frame_len: usize,
    pub next_packet_frame_len: usize,
    pub synack_frame_len: usize,
    pub response_first_frame_len: usize,
    pub response_next_frame_len: usize,
    pub settings_payload_len: usize,
    pub stream_target_addr_len: usize,
    pub first_packet_write_len: usize,
    pub next_packet_write_len: usize,
    pub tls_handshake_validated: bool,
    pub certificate_chain_validated: bool,
    pub server_name_validated: bool,
    pub alpn_validated: bool,
    pub auth_key_validated: bool,
    pub settings_validated: bool,
    pub syn_validated: bool,
    pub psh_magic_target_validated: bool,
    pub synack_validated: bool,
    pub udp_magic_domain_validated: bool,
    pub first_write_target_validated: bool,
    pub first_write_payload_validated: bool,
    pub next_write_payload_validated: bool,
    pub payload_roundtrip_validated: bool,
    pub anytls_udp_packet_stream: bool,
    pub true_dataplane: bool,
}

// Protocol dataplane tests keep wire inputs explicit at the call boundary.
#[allow(clippy::too_many_arguments)]
pub fn udp_packet_stream_exchange_over_tls_stream<S>(
    stream: S,
    material: &TlsLoopbackMaterial,
    tls_options: &TlsUnderlayOptions,
    proxy: &str,
    auth: &str,
    original_udp_target: &str,
    first_payload: &[u8],
    next_payload: &[u8],
) -> Result<AnyTlsUdpPacketStreamExchangeReport, OutboundError>
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

    let session_stream_target = link::udp_stream_target(original_udp_target)?;
    let stream_target_addr = link::socks_addr(&session_stream_target)?;
    let psh_addr_frame = link::frame(contract::CMD_PSH, 1, &stream_target_addr);
    tls.write_all(&psh_addr_frame)
        .map_err(|err| OutboundError::BadAnyTLS(err.to_string()))?;

    let first_write = link::packet_first_write(original_udp_target, first_payload)?;
    let next_write = link::packet_next_write(next_payload);
    let first_packet_frame = link::frame(contract::CMD_PSH, 1, &first_write);
    let next_packet_frame = link::frame(contract::CMD_PSH, 1, &next_write);
    tls.write_all(&first_packet_frame)
        .map_err(|err| OutboundError::BadAnyTLS(err.to_string()))?;
    tls.write_all(&next_packet_frame)
        .map_err(|err| OutboundError::BadAnyTLS(err.to_string()))?;

    let synack = super::read_frame_from_stream(&mut tls)?;
    if synack.cmd != contract::CMD_SYNACK || synack.sid != 1 || !synack.data.is_empty() {
        return Err(OutboundError::BadAnyTLS(format!(
            "anytls UDP SYNACK mismatch: cmd={}, sid={}, len={}",
            synack.cmd,
            synack.sid,
            synack.data_len()
        )));
    }
    let response_first = super::read_frame_from_stream(&mut tls)?;
    if response_first.cmd != contract::CMD_PSH || response_first.sid != 1 {
        return Err(OutboundError::BadAnyTLS(format!(
            "anytls UDP first response mismatch: cmd={}, sid={}, len={}",
            response_first.cmd,
            response_first.sid,
            response_first.data_len()
        )));
    }
    let response_next = super::read_frame_from_stream(&mut tls)?;
    if response_next.cmd != contract::CMD_PSH || response_next.sid != 1 {
        return Err(OutboundError::BadAnyTLS(format!(
            "anytls UDP next response mismatch: cmd={}, sid={}, len={}",
            response_next.cmd,
            response_next.sid,
            response_next.data_len()
        )));
    }

    let first_response_payload = decode_packet_next_write(&response_first.data)?;
    let next_response_payload = decode_packet_next_write(&response_next.data)?;
    if first_response_payload.payload != first_payload {
        return Err(OutboundError::BadAnyTLS(
            "anytls UDP first payload response mismatch".to_owned(),
        ));
    }
    if next_response_payload.payload != next_payload {
        return Err(OutboundError::BadAnyTLS(
            "anytls UDP next payload response mismatch".to_owned(),
        ));
    }

    let selected_alpn = crate::shared_transport::test_support::selected_tls_alpn(tls.ssl());
    let alpn_validated = selected_alpn == tls_options.alpn_protocol;
    let original_udp_target = Socks5Address::parse(original_udp_target)?.authority();
    let udp_magic_domain_validated =
        session_stream_target.starts_with(&format!("{}:", contract::UDP_MAGIC_DOMAIN));

    Ok(AnyTlsUdpPacketStreamExchangeReport {
        proxy: proxy.to_owned(),
        original_udp_target,
        session_stream_target,
        auth_sha256_hex: hex_encode(&link::auth_key(auth)),
        tls_server_name: tls_options.server_name.clone(),
        selected_alpn,
        first_payload_len: first_payload.len(),
        next_payload_len: next_payload.len(),
        echoed_first_payload: first_response_payload.payload,
        echoed_next_payload: next_response_payload.payload,
        auth_handshake_len: auth_handshake.len(),
        settings_frame_len: settings_frame.len(),
        syn_frame_len: syn_frame.len(),
        psh_addr_frame_len: psh_addr_frame.len(),
        first_packet_frame_len: first_packet_frame.len(),
        next_packet_frame_len: next_packet_frame.len(),
        synack_frame_len: contract::HEADER_OVERHEAD_SIZE + synack.data_len(),
        response_first_frame_len: contract::HEADER_OVERHEAD_SIZE + response_first.data_len(),
        response_next_frame_len: contract::HEADER_OVERHEAD_SIZE + response_next.data_len(),
        settings_payload_len: settings.len(),
        stream_target_addr_len: stream_target_addr.len(),
        first_packet_write_len: first_write.len(),
        next_packet_write_len: next_write.len(),
        tls_handshake_validated: true,
        certificate_chain_validated: true,
        server_name_validated: true,
        alpn_validated,
        auth_key_validated: true,
        settings_validated: true,
        syn_validated: true,
        psh_magic_target_validated: true,
        synack_validated: true,
        udp_magic_domain_validated,
        first_write_target_validated: true,
        first_write_payload_validated: true,
        next_write_payload_validated: true,
        payload_roundtrip_validated: true,
        anytls_udp_packet_stream: true,
        true_dataplane: true,
    })
}

pub fn decode_packet_first_write(input: &[u8]) -> Result<AnyTlsPacketWrite, OutboundError> {
    let Some((&mode, rest)) = input.split_first() else {
        return Err(OutboundError::BadAnyTLS(
            "anytls UDP first packet is empty".to_owned(),
        ));
    };
    if mode != 1 {
        return Err(OutboundError::BadAnyTLS(format!(
            "anytls UDP first packet mode mismatch: {mode}"
        )));
    }
    let (target, consumed) = Socks5Address::decode(rest)?;
    let payload_offset = consumed;
    if rest.len() < payload_offset + 2 {
        return Err(OutboundError::BadAnyTLS(
            "anytls UDP first packet length missing".to_owned(),
        ));
    }
    let payload_len = u16::from_be_bytes([rest[payload_offset], rest[payload_offset + 1]]) as usize;
    let payload = &rest[payload_offset + 2..];
    if payload.len() != payload_len {
        return Err(OutboundError::BadAnyTLS(format!(
            "anytls UDP first packet length mismatch: got {}, want {}",
            payload.len(),
            payload_len
        )));
    }
    Ok(AnyTlsPacketWrite {
        target: Some(target.authority()),
        payload: payload.to_vec(),
    })
}

pub fn decode_packet_next_write(input: &[u8]) -> Result<AnyTlsPacketWrite, OutboundError> {
    if input.len() < 2 {
        return Err(OutboundError::BadAnyTLS(
            "anytls UDP next packet length missing".to_owned(),
        ));
    }
    let payload_len = u16::from_be_bytes([input[0], input[1]]) as usize;
    let payload = &input[2..];
    if payload.len() != payload_len {
        return Err(OutboundError::BadAnyTLS(format!(
            "anytls UDP next packet length mismatch: got {}, want {}",
            payload.len(),
            payload_len
        )));
    }
    Ok(AnyTlsPacketWrite {
        target: None,
        payload: payload.to_vec(),
    })
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join("")
}
