use std::io::{Read, Write};
use std::net::{IpAddr, TcpStream};
use std::time::Duration;

use crate::error::OutboundError;

pub const SESSION_STATUS_NEW: u8 = 0x01;
pub const SESSION_STATUS_KEEP: u8 = 0x02;
pub const SESSION_STATUS_END: u8 = 0x03;
pub const SESSION_STATUS_KEEPALIVE: u8 = 0x04;
pub const OPTION_NONE: u8 = 0x00;
pub const OPTION_DATA: u8 = 0x01;
pub const OPTION_ERROR: u8 = 0x02;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MuxFrameOptions {
    pub id: [u8; 2],
    pub port: u16,
    pub host: String,
    pub network: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MuxFrame {
    pub id: [u8; 2],
    pub status: u8,
    pub option: u8,
    pub metadata: Vec<u8>,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MuxLifecycleReport {
    pub transport: &'static str,
    pub id_hex: String,
    pub payload_len: usize,
    pub echoed_payload: Vec<u8>,
    pub multiplexing_harness: bool,
    pub full_mux_runtime_stack: bool,
    pub default_go_path: bool,
}

impl MuxFrameOptions {
    pub fn new(
        id: [u8; 2],
        host: impl Into<String>,
        port: u16,
        network: impl Into<String>,
    ) -> Self {
        Self {
            id,
            port,
            host: host.into(),
            network: network.into(),
        }
    }
}

pub fn mux_new_frame(options: &MuxFrameOptions) -> Vec<u8> {
    let mut metadata = Vec::new();
    metadata.extend_from_slice(&options.id);
    metadata.push(SESSION_STATUS_NEW);
    metadata.push(OPTION_NONE);
    metadata.push(if options.network == "udp" { 0x02 } else { 0x01 });
    metadata.extend_from_slice(&options.port.to_be_bytes());
    match options.host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => {
            metadata.push(0x01);
            metadata.extend_from_slice(&ip.octets());
        }
        Ok(IpAddr::V6(ip)) => {
            metadata.push(0x03);
            metadata.extend_from_slice(&ip.octets());
        }
        Err(_) => {
            metadata.push(0x02);
            metadata.extend_from_slice(options.host.as_bytes());
        }
    }
    length_prefixed(metadata)
}

pub fn mux_data_frame(id: [u8; 2], payload: &[u8]) -> Result<Vec<u8>, OutboundError> {
    if payload.len() > u16::MAX as usize {
        return Err(OutboundError::BadSharedTransport(
            "mux payload too large".to_owned(),
        ));
    }
    let mut frame = Vec::with_capacity(payload.len() + 8);
    frame.extend_from_slice(&4_u16.to_be_bytes());
    frame.extend_from_slice(&id);
    frame.push(SESSION_STATUS_KEEP);
    frame.push(OPTION_DATA);
    frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    frame.extend_from_slice(payload);
    Ok(frame)
}

pub fn mux_end_frame(id: [u8; 2]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(6);
    frame.extend_from_slice(&4_u16.to_be_bytes());
    frame.extend_from_slice(&id);
    frame.push(SESSION_STATUS_END);
    frame.push(OPTION_NONE);
    frame
}

pub fn read_mux_frame(stream: &mut TcpStream) -> Result<MuxFrame, OutboundError> {
    loop {
        let mut len = [0_u8; 2];
        stream
            .read_exact(&mut len)
            .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
        let metadata_len = u16::from_be_bytes(len) as usize;
        if metadata_len < 4 || metadata_len > 512 {
            return Err(OutboundError::BadSharedTransport(
                "invalid mux metadata length".to_owned(),
            ));
        }
        let mut metadata = vec![0_u8; metadata_len];
        stream
            .read_exact(&mut metadata)
            .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
        let id = [metadata[0], metadata[1]];
        let status = metadata[2];
        let option = metadata[3];
        if status == SESSION_STATUS_KEEPALIVE {
            continue;
        }
        let payload = if option == OPTION_DATA {
            let mut payload_len = [0_u8; 2];
            stream
                .read_exact(&mut payload_len)
                .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
            let mut payload = vec![0_u8; u16::from_be_bytes(payload_len) as usize];
            stream
                .read_exact(&mut payload)
                .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
            payload
        } else {
            Vec::new()
        };
        return Ok(MuxFrame {
            id,
            status,
            option,
            metadata,
            payload,
        });
    }
}

pub fn mux_frame_exchange(
    endpoint: &str,
    options: &MuxFrameOptions,
    payload: &[u8],
    timeout: Duration,
) -> Result<MuxLifecycleReport, OutboundError> {
    let mut stream = TcpStream::connect(endpoint)
        .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
    set_timeout(&stream, timeout)?;
    stream
        .write_all(&mux_new_frame(options))
        .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
    stream
        .write_all(&mux_data_frame(options.id, payload)?)
        .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
    let echoed = read_mux_frame(&mut stream)?;
    stream
        .write_all(&mux_end_frame(options.id))
        .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
    Ok(MuxLifecycleReport {
        transport: "mux-frame",
        id_hex: hex_encode(&options.id),
        payload_len: payload.len(),
        echoed_payload: echoed.payload,
        multiplexing_harness: true,
        full_mux_runtime_stack: false,
        default_go_path: true,
    })
}

fn length_prefixed(metadata: Vec<u8>) -> Vec<u8> {
    let mut frame = Vec::with_capacity(metadata.len() + 2);
    frame.extend_from_slice(&(metadata.len() as u16).to_be_bytes());
    frame.extend_from_slice(&metadata);
    frame
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
