use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{IpAddr, TcpStream};
use std::time::Duration;

use dae_outbound_core::error::OutboundError;

pub const SESSION_STATUS_NEW: u8 = 0x01;
pub const SESSION_STATUS_KEEP: u8 = 0x02;
pub const SESSION_STATUS_END: u8 = 0x03;
pub const SESSION_STATUS_KEEPALIVE: u8 = 0x04;
pub const OPTION_NONE: u8 = 0x00;
pub const OPTION_DATA: u8 = 0x01;
pub const OPTION_ERROR: u8 = 0x02;
pub const MUX_MAX_METADATA_BYTES: usize = 512;
pub const MUX_MAX_PAYLOAD_BYTES: usize = u16::MAX as usize;
pub const MUX_DATA_FRAME_HEADER_BYTES: usize = 8;
pub const MUX_MAX_FRAME_BYTES: usize = 2 + MUX_MAX_METADATA_BYTES + 2 + MUX_MAX_PAYLOAD_BYTES;

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

#[derive(Debug, Default)]
pub struct MuxFrameDecoder {
    pending: VecDeque<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MuxLifecycleReport {
    pub transport: &'static str,
    pub id_hex: String,
    pub payload_len: usize,
    pub echoed_payload: Vec<u8>,
    pub multiplexing_harness: bool,
    pub full_mux_runtime_stack: bool,
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

pub fn mux_new_frame(options: &MuxFrameOptions) -> Result<Vec<u8>, OutboundError> {
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
            if options.host.len() > u8::MAX as usize {
                return Err(OutboundError::BadSharedTransport(
                    "mux domain address too long".to_owned(),
                ));
            }
            metadata.push(0x02);
            metadata.push(options.host.len() as u8);
            metadata.extend_from_slice(options.host.as_bytes());
        }
    }
    Ok(length_prefixed(metadata))
}

pub fn mux_data_frame(id: [u8; 2], payload: &[u8]) -> Result<Vec<u8>, OutboundError> {
    let header = mux_data_frame_header(id, payload.len())?;
    let mut frame = Vec::with_capacity(payload.len() + header.len());
    frame.extend_from_slice(&header);
    frame.extend_from_slice(payload);
    Ok(frame)
}

pub fn mux_data_frame_header(
    id: [u8; 2],
    payload_len: usize,
) -> Result<[u8; MUX_DATA_FRAME_HEADER_BYTES], OutboundError> {
    if payload_len > u16::MAX as usize {
        return Err(OutboundError::BadSharedTransport(
            "mux payload too large".to_owned(),
        ));
    }
    let [payload_high, payload_low] = (payload_len as u16).to_be_bytes();
    Ok([
        0,
        4,
        id[0],
        id[1],
        SESSION_STATUS_KEEP,
        OPTION_DATA,
        payload_high,
        payload_low,
    ])
}

pub fn mux_end_frame(id: [u8; 2]) -> Vec<u8> {
    mux_end_frame_with_option(id, OPTION_NONE)
}

pub fn mux_error_frame(id: [u8; 2]) -> Vec<u8> {
    mux_end_frame_with_option(id, OPTION_ERROR)
}

fn mux_end_frame_with_option(id: [u8; 2], option: u8) -> Vec<u8> {
    let mut frame = Vec::with_capacity(6);
    frame.extend_from_slice(&4_u16.to_be_bytes());
    frame.extend_from_slice(&id);
    frame.push(SESSION_STATUS_END);
    frame.push(option);
    frame
}

impl MuxFrameDecoder {
    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<MuxFrame>, OutboundError> {
        self.pending.extend(bytes.iter().copied());
        let mut frames = Vec::new();
        while let Some((frame_end, frame)) = self.next_frame()? {
            self.pending.drain(..frame_end);
            frames.push(frame);
        }
        if self.pending.len() > MUX_MAX_FRAME_BYTES {
            return Err(OutboundError::BadSharedTransport(
                "mux pending frame exceeds the wire limit".to_owned(),
            ));
        }
        Ok(frames)
    }

    fn next_frame(&mut self) -> Result<Option<(usize, MuxFrame)>, OutboundError> {
        let pending = self.pending.make_contiguous();
        if pending.len() < 2 {
            return Ok(None);
        }
        let metadata_len = u16::from_be_bytes([pending[0], pending[1]]) as usize;
        if !(4..=MUX_MAX_METADATA_BYTES).contains(&metadata_len) {
            return Err(OutboundError::BadSharedTransport(
                "invalid mux metadata length".to_owned(),
            ));
        }
        let metadata_end = 2 + metadata_len;
        if pending.len() < metadata_end {
            return Ok(None);
        }
        let metadata = &pending[2..metadata_end];
        let id = [metadata[0], metadata[1]];
        let (status, option) = validate_mux_metadata(metadata)?;
        let (frame_end, payload) = if option & OPTION_DATA != 0 {
            if pending.len() < metadata_end + 2 {
                return Ok(None);
            }
            let payload_len =
                u16::from_be_bytes([pending[metadata_end], pending[metadata_end + 1]]) as usize;
            let frame_end = metadata_end + 2 + payload_len;
            if pending.len() < frame_end {
                return Ok(None);
            }
            (frame_end, pending[metadata_end + 2..frame_end].to_vec())
        } else {
            (metadata_end, Vec::new())
        };
        Ok(Some((
            frame_end,
            MuxFrame {
                id,
                status,
                option,
                metadata: metadata.to_vec(),
                payload,
            },
        )))
    }
}

pub fn read_mux_frame(stream: &mut impl Read) -> Result<MuxFrame, OutboundError> {
    loop {
        let mut len = [0_u8; 2];
        stream
            .read_exact(&mut len)
            .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
        let metadata_len = u16::from_be_bytes(len) as usize;
        if !(4..=MUX_MAX_METADATA_BYTES).contains(&metadata_len) {
            return Err(OutboundError::BadSharedTransport(
                "invalid mux metadata length".to_owned(),
            ));
        }
        let mut metadata = vec![0_u8; metadata_len];
        stream
            .read_exact(&mut metadata)
            .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
        let id = [metadata[0], metadata[1]];
        let (status, option) = validate_mux_metadata(&metadata)?;
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
        if status == SESSION_STATUS_KEEPALIVE {
            continue;
        }
        return Ok(MuxFrame {
            id,
            status,
            option,
            metadata,
            payload,
        });
    }
}

fn validate_mux_metadata(metadata: &[u8]) -> Result<(u8, u8), OutboundError> {
    let status = metadata[2];
    let option = metadata[3];
    if !matches!(
        status,
        SESSION_STATUS_NEW | SESSION_STATUS_KEEP | SESSION_STATUS_END | SESSION_STATUS_KEEPALIVE
    ) {
        return Err(OutboundError::BadSharedTransport(
            "invalid mux session status".to_owned(),
        ));
    }
    if option & !(OPTION_DATA | OPTION_ERROR) != 0 {
        return Err(OutboundError::BadSharedTransport(
            "invalid mux frame option".to_owned(),
        ));
    }
    if status == SESSION_STATUS_NEW && metadata.len() < 8 {
        return Err(OutboundError::BadSharedTransport(
            "incomplete mux new-session metadata".to_owned(),
        ));
    }
    Ok((status, option))
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
        .write_all(&mux_new_frame(options)?)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_frame_header_matches_allocating_frame() {
        let id = 0x1234_u16.to_be_bytes();
        let payload = vec![0x5a; 16 * 1024];
        let frame = mux_data_frame(id, &payload).unwrap();
        assert_eq!(
            &frame[..MUX_DATA_FRAME_HEADER_BYTES],
            &mux_data_frame_header(id, payload.len()).unwrap()
        );
        assert_eq!(&frame[MUX_DATA_FRAME_HEADER_BYTES..], payload.as_slice());
    }

    #[test]
    fn streaming_decoder_preserves_partial_and_coalesced_frames() {
        let id = 7_u16.to_be_bytes();
        let new = mux_new_frame(&MuxFrameOptions::new(id, "example.com", 443, "tcp")).unwrap();
        let data = mux_data_frame(id, b"payload").unwrap();
        let end = mux_end_frame(id);
        let wire = [new, data, end].concat();
        let mut decoder = MuxFrameDecoder::default();
        let mut frames = Vec::new();
        for chunk in wire.chunks(3) {
            frames.extend(decoder.push(chunk).unwrap());
        }
        assert_eq!(frames.len(), 3);
        assert_eq!(frames[0].status, SESSION_STATUS_NEW);
        assert_eq!(frames[1].status, SESSION_STATUS_KEEP);
        assert_eq!(frames[1].payload, b"payload");
        assert_eq!(frames[2].status, SESSION_STATUS_END);
    }

    #[test]
    fn streaming_decoder_rejects_invalid_metadata_status_and_option() {
        let mut decoder = MuxFrameDecoder::default();
        assert!(decoder.push(&[0, 3, 0, 1, SESSION_STATUS_KEEP]).is_err());

        let mut decoder = MuxFrameDecoder::default();
        assert!(decoder.push(&[0, 4, 0, 1, 0xff, OPTION_NONE]).is_err());

        let mut decoder = MuxFrameDecoder::default();
        assert!(
            decoder
                .push(&[0, 4, 0, 1, SESSION_STATUS_KEEP, 0x80])
                .is_err()
        );
    }

    #[test]
    fn streaming_decoder_bounds_incomplete_pending_wire_bytes() {
        let mut wire = vec![0x02, 0x00];
        wire.resize(MUX_MAX_FRAME_BYTES + 1, 0);
        let mut decoder = MuxFrameDecoder::default();
        assert!(decoder.push(&wire).is_err());
    }

    #[test]
    fn synchronous_decoder_consumes_keepalive_payload_before_next_frame() {
        let id = 9_u16.to_be_bytes();
        let mut keepalive = Vec::new();
        keepalive.extend_from_slice(&4_u16.to_be_bytes());
        keepalive.extend_from_slice(&id);
        keepalive.push(SESSION_STATUS_KEEPALIVE);
        keepalive.push(OPTION_DATA);
        keepalive.extend_from_slice(&3_u16.to_be_bytes());
        keepalive.extend_from_slice(b"pad");
        keepalive.extend_from_slice(&mux_data_frame(id, b"next").unwrap());
        let mut wire = std::io::Cursor::new(keepalive);
        let frame = read_mux_frame(&mut wire).unwrap();
        assert_eq!(frame.status, SESSION_STATUS_KEEP);
        assert_eq!(frame.payload, b"next");
    }
}
