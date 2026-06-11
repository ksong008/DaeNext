use std::io::{Read, Write};

use crate::error::OutboundError;
use crate::socks5::Socks5Address;

use super::metadata::{TrojanMetadata, TrojanNetwork};
use super::packet::{self, CRLF};

pub const PASSWORD_SHA224_HEX_LEN: usize = 56;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrojanTcpExchangeReport {
    pub proxy: String,
    pub target: String,
    pub password_sha224_hex: String,
    pub command: u8,
    pub payload_len: usize,
    pub echoed_payload: Vec<u8>,
    pub true_dataplane: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrojanUdpOverTcpExchangeReport {
    pub proxy: String,
    pub session_target: String,
    pub packet_target: String,
    pub password_sha224_hex: String,
    pub command: u8,
    pub payload_len: usize,
    pub packet_len: usize,
    pub echoed_payload: Vec<u8>,
    pub true_dataplane: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrojanRequestHeader {
    pub password_sha224_hex: String,
    pub command: u8,
    pub metadata: TrojanMetadata,
    pub target: String,
    pub header_len: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrojanTcpRequest {
    pub password_sha224_hex: String,
    pub command: u8,
    pub metadata: TrojanMetadata,
    pub target: String,
    pub payload: Vec<u8>,
    pub header_len: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrojanUdpPacket {
    pub target: String,
    pub payload: Vec<u8>,
    pub payload_len: usize,
    pub packet_len: usize,
}

pub fn tcp_exchange_over_stream<S>(
    stream: &mut S,
    proxy: &str,
    password: &str,
    target: &str,
    payload: &[u8],
) -> Result<TrojanTcpExchangeReport, OutboundError>
where
    S: Read + Write,
{
    let metadata = TrojanMetadata::parse("tcp", target)?;
    let target = metadata.authority();
    let request = packet::tcp_request_header(password, "tcp", &target, payload)?;
    stream
        .write_all(&request)
        .map_err(|err| OutboundError::BadTrojan(err.to_string()))?;

    let mut echoed_payload = vec![0_u8; payload.len()];
    stream
        .read_exact(&mut echoed_payload)
        .map_err(|err| OutboundError::BadTrojan(err.to_string()))?;

    Ok(TrojanTcpExchangeReport {
        proxy: proxy.to_owned(),
        target,
        password_sha224_hex: packet::password_sha224_hex(password),
        command: TrojanNetwork::Tcp.byte(),
        payload_len: payload.len(),
        echoed_payload,
        true_dataplane: true,
    })
}

pub fn udp_over_tcp_exchange_over_stream<S>(
    stream: &mut S,
    proxy: &str,
    password: &str,
    session_target: &str,
    packet_target: &str,
    payload: &[u8],
) -> Result<TrojanUdpOverTcpExchangeReport, OutboundError>
where
    S: Read + Write,
{
    let session_metadata = TrojanMetadata::parse("udp", session_target)?;
    let session_target = session_metadata.authority();
    let packet = packet::udp_packet(packet_target, payload)?;
    let request = packet::tcp_request_header(password, "udp", &session_target, &packet)?;
    stream
        .write_all(&request)
        .map_err(|err| OutboundError::BadTrojan(err.to_string()))?;

    let response = read_udp_packet_from_stream(stream)?;
    Ok(TrojanUdpOverTcpExchangeReport {
        proxy: proxy.to_owned(),
        session_target,
        packet_target: response.target,
        password_sha224_hex: packet::password_sha224_hex(password),
        command: TrojanNetwork::Udp.byte(),
        payload_len: payload.len(),
        packet_len: response.packet_len,
        echoed_payload: response.payload,
        true_dataplane: true,
    })
}

pub fn read_request_header_from_stream<S>(
    stream: &mut S,
) -> Result<TrojanRequestHeader, OutboundError>
where
    S: Read,
{
    let mut password = [0_u8; PASSWORD_SHA224_HEX_LEN];
    read_exact(stream, &mut password, "trojan password sha224 hex")?;
    if !password.iter().all(u8::is_ascii_hexdigit) {
        return Err(OutboundError::BadTrojan(
            "trojan password sha224 is not hex".to_owned(),
        ));
    }
    let password_sha224_hex = String::from_utf8(password.to_vec())
        .map_err(|err| OutboundError::BadTrojan(err.to_string()))?;

    read_crlf(stream, "after trojan password")?;

    let mut command = [0_u8; 1];
    read_exact(stream, &mut command, "trojan command")?;
    let network = match command[0] {
        value if value == TrojanNetwork::Tcp.byte() => TrojanNetwork::Tcp,
        value if value == TrojanNetwork::Udp.byte() => TrojanNetwork::Udp,
        value => {
            return Err(OutboundError::BadTrojan(format!(
                "unexpected trojan command: {value}"
            )));
        }
    };

    let address_bytes = read_socks5_address_bytes(stream)?;
    let (address, consumed) = Socks5Address::decode(&address_bytes)?;
    if consumed != address_bytes.len() {
        return Err(OutboundError::BadTrojan(format!(
            "trailing trojan target metadata bytes: {}",
            address_bytes.len() - consumed
        )));
    }
    read_crlf(stream, "after trojan target metadata")?;

    let metadata = TrojanMetadata { network, address };
    let target = metadata.authority();
    Ok(TrojanRequestHeader {
        password_sha224_hex,
        command: command[0],
        metadata,
        target,
        header_len: PASSWORD_SHA224_HEX_LEN + CRLF.len() + 1 + address_bytes.len() + CRLF.len(),
    })
}

pub fn read_tcp_request_from_stream<S>(
    stream: &mut S,
    payload_len: usize,
) -> Result<TrojanTcpRequest, OutboundError>
where
    S: Read,
{
    let header = read_request_header_from_stream(stream)?;
    if header.command != TrojanNetwork::Tcp.byte() {
        return Err(OutboundError::BadTrojan(format!(
            "unexpected trojan tcp command: {}",
            header.command
        )));
    }

    let mut payload = vec![0_u8; payload_len];
    read_exact(stream, &mut payload, "trojan tcp payload")?;
    Ok(TrojanTcpRequest {
        password_sha224_hex: header.password_sha224_hex,
        command: header.command,
        metadata: header.metadata,
        target: header.target,
        payload,
        header_len: header.header_len,
    })
}

pub fn decode_udp_packet(input: &[u8]) -> Result<TrojanUdpPacket, OutboundError> {
    let (address, consumed) = Socks5Address::decode(input)?;
    if input.len() < consumed + 4 {
        return Err(OutboundError::BadTrojan(
            "trojan UDP packet length/CRLF missing".to_owned(),
        ));
    }
    let payload_len = u16::from_be_bytes([input[consumed], input[consumed + 1]]) as usize;
    if input[consumed + 2..consumed + 4] != *CRLF {
        return Err(OutboundError::BadTrojan(
            "trojan UDP packet missing CRLF".to_owned(),
        ));
    }
    let payload_start = consumed + 4;
    let packet_len = payload_start + payload_len;
    if input.len() != packet_len {
        return Err(OutboundError::BadTrojan(format!(
            "trojan UDP packet length mismatch: got {}, want {}",
            input.len(),
            packet_len
        )));
    }
    Ok(TrojanUdpPacket {
        target: address.authority(),
        payload: input[payload_start..packet_len].to_vec(),
        payload_len,
        packet_len,
    })
}

pub fn read_udp_packet_from_stream<S>(stream: &mut S) -> Result<TrojanUdpPacket, OutboundError>
where
    S: Read,
{
    let address_bytes = read_socks5_address_bytes(stream)?;
    let mut length_and_crlf = [0_u8; 4];
    read_exact(
        stream,
        &mut length_and_crlf,
        "trojan UDP packet length and CRLF",
    )?;
    let payload_len = u16::from_be_bytes([length_and_crlf[0], length_and_crlf[1]]) as usize;
    if length_and_crlf[2..4] != *CRLF {
        return Err(OutboundError::BadTrojan(
            "trojan UDP packet missing CRLF".to_owned(),
        ));
    }
    let mut payload = vec![0_u8; payload_len];
    read_exact(stream, &mut payload, "trojan UDP packet payload")?;
    let mut packet = Vec::with_capacity(address_bytes.len() + 4 + payload.len());
    packet.extend_from_slice(&address_bytes);
    packet.extend_from_slice(&length_and_crlf);
    packet.extend_from_slice(&payload);
    decode_udp_packet(&packet)
}

fn read_crlf(stream: &mut impl Read, context: &str) -> Result<(), OutboundError> {
    let mut crlf = [0_u8; 2];
    read_exact(stream, &mut crlf, context)?;
    if crlf != *CRLF {
        return Err(OutboundError::BadTrojan(format!(
            "bad CRLF {context}: {crlf:02x?}"
        )));
    }
    Ok(())
}

fn read_exact(stream: &mut impl Read, buf: &mut [u8], context: &str) -> Result<(), OutboundError> {
    stream
        .read_exact(buf)
        .map_err(|err| OutboundError::BadTrojan(format!("read {context} failed: {err}")))
}

fn read_socks5_address_bytes(stream: &mut impl Read) -> Result<Vec<u8>, OutboundError> {
    let mut atyp = [0_u8; 1];
    read_exact(stream, &mut atyp, "trojan address type")?;
    let mut out = atyp.to_vec();
    match atyp[0] {
        1 => {
            let mut rest = [0_u8; 6];
            read_exact(stream, &mut rest, "trojan ipv4 address")?;
            out.extend_from_slice(&rest);
        }
        3 => {
            let mut len = [0_u8; 1];
            read_exact(stream, &mut len, "trojan domain length")?;
            out.extend_from_slice(&len);
            let mut rest = vec![0_u8; len[0] as usize + 2];
            read_exact(stream, &mut rest, "trojan domain address")?;
            out.extend_from_slice(&rest);
        }
        4 => {
            let mut rest = [0_u8; 18];
            read_exact(stream, &mut rest, "trojan ipv6 address")?;
            out.extend_from_slice(&rest);
        }
        value => {
            return Err(OutboundError::BadTrojan(format!(
                "bad trojan address type: {value}"
            )));
        }
    }
    Ok(out)
}
