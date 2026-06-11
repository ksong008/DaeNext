use std::net::UdpSocket;
use std::time::Duration;

use crate::error::OutboundError;

pub const QUIC_H3_HARNESS_MAGIC: &[u8; 8] = b"DAEQUIC3";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuicH3HarnessOptions {
    pub flow_id: u32,
    pub datagram_id: u32,
    pub alpn: String,
    pub mark: u32,
    pub mptcp: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuicH3Datagram {
    pub flow_id: u32,
    pub datagram_id: u32,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuicH3HarnessReport {
    pub transport: &'static str,
    pub alpn: String,
    pub flow_id: u32,
    pub datagram_id: u32,
    pub payload_len: usize,
    pub echoed_payload: Vec<u8>,
    pub udp_datagram_harness: bool,
    pub full_quic_h3_stack: bool,
}

impl QuicH3HarnessOptions {
    pub fn new(
        flow_id: u32,
        datagram_id: u32,
        alpn: impl Into<String>,
        mark: u32,
        mptcp: bool,
    ) -> Self {
        Self {
            flow_id,
            datagram_id,
            alpn: alpn.into(),
            mark,
            mptcp,
        }
    }
}

pub fn quic_h3_datagram_packet(
    options: &QuicH3HarnessOptions,
    payload: &[u8],
) -> Result<Vec<u8>, OutboundError> {
    if payload.len() > u16::MAX as usize {
        return Err(OutboundError::BadSharedTransport(
            "quic h3 harness payload too large".to_owned(),
        ));
    }
    let mut packet = Vec::with_capacity(payload.len() + 18);
    packet.extend_from_slice(QUIC_H3_HARNESS_MAGIC);
    packet.extend_from_slice(&options.flow_id.to_be_bytes());
    packet.extend_from_slice(&options.datagram_id.to_be_bytes());
    packet.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    packet.extend_from_slice(payload);
    Ok(packet)
}

pub fn parse_quic_h3_datagram(packet: &[u8]) -> Result<QuicH3Datagram, OutboundError> {
    if packet.len() < 18 || &packet[..8] != QUIC_H3_HARNESS_MAGIC {
        return Err(OutboundError::BadSharedTransport(
            "bad quic h3 harness packet".to_owned(),
        ));
    }
    let flow_id = u32::from_be_bytes([packet[8], packet[9], packet[10], packet[11]]);
    let datagram_id = u32::from_be_bytes([packet[12], packet[13], packet[14], packet[15]]);
    let payload_len = u16::from_be_bytes([packet[16], packet[17]]) as usize;
    if packet.len() < 18 + payload_len {
        return Err(OutboundError::BadSharedTransport(
            "short quic h3 harness payload".to_owned(),
        ));
    }
    Ok(QuicH3Datagram {
        flow_id,
        datagram_id,
        payload: packet[18..18 + payload_len].to_vec(),
    })
}

pub fn quic_h3_datagram_exchange(
    endpoint: &str,
    options: &QuicH3HarnessOptions,
    payload: &[u8],
    timeout: Duration,
) -> Result<QuicH3HarnessReport, OutboundError> {
    let socket = UdpSocket::bind("127.0.0.1:0")
        .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
    socket
        .set_read_timeout(Some(timeout))
        .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
    socket
        .set_write_timeout(Some(timeout))
        .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
    socket
        .send_to(&quic_h3_datagram_packet(options, payload)?, endpoint)
        .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
    let mut buf = [0_u8; 2048];
    let (n, _) = socket
        .recv_from(&mut buf)
        .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
    let datagram = parse_quic_h3_datagram(&buf[..n])?;
    Ok(QuicH3HarnessReport {
        transport: "quic-h3-datagram",
        alpn: options.alpn.clone(),
        flow_id: datagram.flow_id,
        datagram_id: datagram.datagram_id,
        payload_len: payload.len(),
        echoed_payload: datagram.payload,
        udp_datagram_harness: true,
        full_quic_h3_stack: false,
    })
}
