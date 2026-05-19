use std::io::{Cursor, Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::error::OutboundError;
use crate::shared_transport::{
    DEFAULT_WS_KEY, HttpUpgradeOptions, MuxFrameOptions, WS_MASK_KEY, mux, mux_data_frame,
    mux_end_frame, mux_new_frame, read_http_head, read_websocket_binary_frame,
    validate_http_status, websocket_client_binary_frame, websocket_handshake_request,
};
use crate::vmess::{VMessMetadata, VMessNetwork};

use super::packet;

pub const VLESS_VERSION: u8 = 0;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VlessTcpExchangeReport {
    pub proxy: String,
    pub target: String,
    pub key_hex: String,
    pub command: u8,
    pub payload_len: usize,
    pub echoed_payload: Vec<u8>,
    pub true_dataplane: bool,
    pub default_go_path: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VlessUdpOverTcpExchangeReport {
    pub proxy: String,
    pub target: String,
    pub key_hex: String,
    pub command: u8,
    pub payload_len: usize,
    pub packet_len: usize,
    pub echoed_payload: Vec<u8>,
    pub response_header_len: usize,
    pub true_dataplane: bool,
    pub default_go_path: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VlessMuxExchangeReport {
    pub proxy: String,
    pub target: String,
    pub key_hex: String,
    pub command: u8,
    pub mux_id_hex: String,
    pub payload_len: usize,
    pub echoed_payload: Vec<u8>,
    pub new_frame_validated: bool,
    pub data_frame_validated: bool,
    pub end_frame_sent: bool,
    pub true_dataplane: bool,
    pub default_go_path: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VlessWebSocketExchangeReport {
    pub proxy: String,
    pub target: String,
    pub ws_host: String,
    pub ws_path: String,
    pub key_hex: String,
    pub command: u8,
    pub request_header_len: usize,
    pub response_header_len: usize,
    pub websocket_request_frame_len: usize,
    pub websocket_response_frame_len: usize,
    pub payload_len: usize,
    pub echoed_payload: Vec<u8>,
    pub websocket_handshake_validated: bool,
    pub websocket_binary_frame_validated: bool,
    pub true_dataplane: bool,
    pub default_go_path: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VlessTcpRequest {
    pub version: u8,
    pub key: [u8; 16],
    pub key_hex: String,
    pub addons_len: usize,
    pub command: u8,
    pub target: String,
    pub payload: Vec<u8>,
    pub header_len: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VlessUdpRequest {
    pub version: u8,
    pub key: [u8; 16],
    pub key_hex: String,
    pub addons_len: usize,
    pub command: u8,
    pub target: String,
    pub payload_len: usize,
    pub payload: Vec<u8>,
    pub header_len: usize,
    pub packet_len: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VlessMuxRequest {
    pub version: u8,
    pub key: [u8; 16],
    pub key_hex: String,
    pub addons_len: usize,
    pub command: u8,
    pub header_len: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VlessWebSocketRequest {
    pub request: VlessTcpRequest,
    pub websocket_request_frame_len: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct VlessRequestHeader {
    version: u8,
    key: [u8; 16],
    key_hex: String,
    addons_len: usize,
    command: u8,
    target: String,
    header_len: usize,
}

pub fn tcp_exchange_over_stream<S>(
    stream: &mut S,
    proxy: &str,
    key: &[u8; 16],
    target: &str,
    payload: &[u8],
) -> Result<VlessTcpExchangeReport, OutboundError>
where
    S: Read + Write,
{
    let request = packet::first_write_bytes(key, "", "tcp", target, false, payload)?;
    stream
        .write_all(&request)
        .map_err(|err| OutboundError::BadVless(err.to_string()))?;

    let mut echoed_payload = vec![0_u8; payload.len()];
    stream
        .read_exact(&mut echoed_payload)
        .map_err(|err| OutboundError::BadVless(err.to_string()))?;

    Ok(VlessTcpExchangeReport {
        proxy: proxy.to_owned(),
        target: target.to_owned(),
        key_hex: hex_encode(key),
        command: VMessNetwork::Tcp.byte(),
        payload_len: payload.len(),
        echoed_payload,
        true_dataplane: true,
        default_go_path: true,
    })
}

pub fn udp_over_tcp_exchange_over_stream<S>(
    stream: &mut S,
    proxy: &str,
    key: &[u8; 16],
    target: &str,
    payload: &[u8],
) -> Result<VlessUdpOverTcpExchangeReport, OutboundError>
where
    S: Read + Write,
{
    let request = packet::first_write_bytes(key, "", "udp", target, false, payload)?;
    stream
        .write_all(&request)
        .map_err(|err| OutboundError::BadVless(err.to_string()))?;

    let (response_header_len, echoed_payload) = read_udp_response_payload(stream)?;
    if echoed_payload.len() != payload.len() {
        return Err(OutboundError::BadVless(format!(
            "unexpected VLESS UDP response payload length: got {}, want {}",
            echoed_payload.len(),
            payload.len()
        )));
    }

    Ok(VlessUdpOverTcpExchangeReport {
        proxy: proxy.to_owned(),
        target: target.to_owned(),
        key_hex: hex_encode(key),
        command: VMessNetwork::Udp.byte(),
        payload_len: payload.len(),
        packet_len: 2 + payload.len(),
        echoed_payload,
        response_header_len,
        true_dataplane: true,
        default_go_path: true,
    })
}

pub fn mux_exchange_over_stream<S>(
    stream: &mut S,
    proxy: &str,
    key: &[u8; 16],
    mux_id: [u8; 2],
    target: &str,
    network: &str,
    payload: &[u8],
) -> Result<VlessMuxExchangeReport, OutboundError>
where
    S: Read + Write,
{
    let header = packet::request_header(key, "", "tcp", "0.0.0.0:0", true, &[])?;
    let metadata = VMessMetadata::parse(network, target)?;
    let options = MuxFrameOptions::new(mux_id, metadata.hostname(), metadata.port(), network);
    stream
        .write_all(&header)
        .map_err(|err| OutboundError::BadVless(err.to_string()))?;
    stream
        .write_all(&mux_new_frame(&options))
        .map_err(|err| OutboundError::BadVless(err.to_string()))?;
    stream
        .write_all(&mux_data_frame(mux_id, payload)?)
        .map_err(|err| OutboundError::BadVless(err.to_string()))?;

    let echoed = mux::read_mux_frame(stream)?;
    stream
        .write_all(&mux_end_frame(mux_id))
        .map_err(|err| OutboundError::BadVless(err.to_string()))?;
    if echoed.payload != payload {
        return Err(OutboundError::BadVless(
            "VLESS mux payload response mismatch".to_owned(),
        ));
    }

    Ok(VlessMuxExchangeReport {
        proxy: proxy.to_owned(),
        target: target.to_owned(),
        key_hex: hex_encode(key),
        command: VMessNetwork::Mux.byte(),
        mux_id_hex: hex_encode(&mux_id),
        payload_len: payload.len(),
        echoed_payload: echoed.payload,
        new_frame_validated: true,
        data_frame_validated: true,
        end_frame_sent: true,
        true_dataplane: true,
        default_go_path: true,
    })
}

pub fn tcp_exchange_over_websocket_stream<S>(
    stream: &mut S,
    proxy: &str,
    key: &[u8; 16],
    target: &str,
    ws_host: &str,
    ws_path: &str,
    payload: &[u8],
) -> Result<VlessWebSocketExchangeReport, OutboundError>
where
    S: Read + Write,
{
    let ws_options = HttpUpgradeOptions::new(ws_host, ws_path);
    let handshake = websocket_handshake_request(&ws_options, DEFAULT_WS_KEY);
    stream
        .write_all(&handshake)
        .map_err(|err| OutboundError::BadVless(err.to_string()))?;
    let response = read_http_head(stream)?;
    validate_http_status(&response, 101)?;

    let request = packet::first_write_bytes(key, "", "tcp", target, false, payload)?;
    let request_header_len = request.len().saturating_sub(payload.len());
    let request_frame = websocket_client_binary_frame(&request, WS_MASK_KEY)?;
    stream
        .write_all(&request_frame)
        .map_err(|err| OutboundError::BadVless(err.to_string()))?;

    let response_payload = read_websocket_binary_frame(stream)?;
    let websocket_response_frame_len = response_payload.len();
    let (response_header_len, echoed_payload) = decode_response_payload(&response_payload)?;
    if echoed_payload != payload {
        return Err(OutboundError::BadVless(
            "VLESS WebSocket payload response mismatch".to_owned(),
        ));
    }

    Ok(VlessWebSocketExchangeReport {
        proxy: proxy.to_owned(),
        target: target.to_owned(),
        ws_host: ws_options.host,
        ws_path: ws_options.path,
        key_hex: hex_encode(key),
        command: VMessNetwork::Tcp.byte(),
        request_header_len,
        response_header_len,
        websocket_request_frame_len: request_frame.len(),
        websocket_response_frame_len,
        payload_len: payload.len(),
        echoed_payload,
        websocket_handshake_validated: true,
        websocket_binary_frame_validated: true,
        true_dataplane: true,
        default_go_path: true,
    })
}

pub fn read_tcp_request_from_stream<S>(
    stream: &mut S,
    payload_len: usize,
) -> Result<VlessTcpRequest, OutboundError>
where
    S: Read,
{
    let header = read_request_header(stream)?;
    if header.command != VMessNetwork::Tcp.byte() {
        return Err(OutboundError::BadVless(format!(
            "unexpected VLESS TCP command: {}",
            header.command
        )));
    }

    let mut payload = vec![0_u8; payload_len];
    read_exact(stream, &mut payload, "vless payload")?;
    Ok(VlessTcpRequest {
        version: header.version,
        key: header.key,
        key_hex: header.key_hex,
        addons_len: header.addons_len,
        command: header.command,
        target: header.target,
        payload,
        header_len: header.header_len,
    })
}

pub fn read_udp_request_from_stream<S>(stream: &mut S) -> Result<VlessUdpRequest, OutboundError>
where
    S: Read,
{
    let header = read_request_header(stream)?;
    if header.command != VMessNetwork::Udp.byte() {
        return Err(OutboundError::BadVless(format!(
            "unexpected VLESS UDP command: {}",
            header.command
        )));
    }

    let mut length = [0_u8; 2];
    read_exact(stream, &mut length, "vless udp payload length")?;
    let payload_len = u16::from_be_bytes(length) as usize;
    let mut payload = vec![0_u8; payload_len];
    read_exact(stream, &mut payload, "vless udp payload")?;
    Ok(VlessUdpRequest {
        version: header.version,
        key: header.key,
        key_hex: header.key_hex,
        addons_len: header.addons_len,
        command: header.command,
        target: header.target,
        payload_len,
        payload,
        header_len: header.header_len,
        packet_len: 2 + payload_len,
    })
}

pub fn read_mux_request_from_stream<S>(stream: &mut S) -> Result<VlessMuxRequest, OutboundError>
where
    S: Read,
{
    let mut version = [0_u8; 1];
    read_exact(stream, &mut version, "vless mux version")?;
    if version[0] != VLESS_VERSION {
        return Err(OutboundError::BadVless(format!(
            "unexpected VLESS mux version: {}",
            version[0]
        )));
    }

    let mut key = [0_u8; 16];
    read_exact(stream, &mut key, "vless mux key")?;

    let mut addons_len = [0_u8; 1];
    read_exact(stream, &mut addons_len, "vless mux addons length")?;
    let addons_len = addons_len[0] as usize;
    let mut addons = vec![0_u8; addons_len];
    read_exact(stream, &mut addons, "vless mux addons")?;

    let mut command = [0_u8; 1];
    read_exact(stream, &mut command, "vless mux command")?;
    if command[0] != VMessNetwork::Mux.byte() {
        return Err(OutboundError::BadVless(format!(
            "unexpected VLESS mux command: {}",
            command[0]
        )));
    }

    Ok(VlessMuxRequest {
        version: version[0],
        key,
        key_hex: hex_encode(&key),
        addons_len,
        command: command[0],
        header_len: 1 + 16 + 1 + addons_len + 1,
    })
}

pub fn read_tcp_request_from_websocket_stream<S>(
    stream: &mut S,
    payload_len: usize,
) -> Result<VlessWebSocketRequest, OutboundError>
where
    S: Read,
{
    let payload = read_websocket_binary_frame(stream)?;
    let websocket_request_frame_len = payload.len();
    let mut cursor = Cursor::new(payload);
    let request = read_tcp_request_from_stream(&mut cursor, payload_len)?;
    if cursor.position() as usize != websocket_request_frame_len {
        return Err(OutboundError::BadVless(format!(
            "VLESS WebSocket request has trailing bytes: {}",
            websocket_request_frame_len - cursor.position() as usize
        )));
    }
    Ok(VlessWebSocketRequest {
        request,
        websocket_request_frame_len,
    })
}

pub fn response_header_bytes() -> [u8; 2] {
    [VLESS_VERSION, 0]
}

pub fn udp_response_packet(payload: &[u8]) -> Result<Vec<u8>, OutboundError> {
    if payload.len() > u16::MAX as usize {
        return Err(OutboundError::BadVless(format!(
            "vless udp payload too long: {} bytes",
            payload.len()
        )));
    }
    let mut out = Vec::with_capacity(2 + 2 + payload.len());
    out.extend_from_slice(&response_header_bytes());
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

pub fn response_payload_bytes(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + payload.len());
    out.extend_from_slice(&response_header_bytes());
    out.extend_from_slice(payload);
    out
}

fn read_request_header(stream: &mut impl Read) -> Result<VlessRequestHeader, OutboundError> {
    let mut version = [0_u8; 1];
    read_exact(stream, &mut version, "vless version")?;
    if version[0] != VLESS_VERSION {
        return Err(OutboundError::BadVless(format!(
            "unexpected VLESS version: {}",
            version[0]
        )));
    }

    let mut key = [0_u8; 16];
    read_exact(stream, &mut key, "vless key")?;

    let mut addons_len = [0_u8; 1];
    read_exact(stream, &mut addons_len, "vless addons length")?;
    let addons_len = addons_len[0] as usize;
    let mut addons = vec![0_u8; addons_len];
    read_exact(stream, &mut addons, "vless addons")?;

    let mut command = [0_u8; 1];
    read_exact(stream, &mut command, "vless command")?;

    let mut port = [0_u8; 2];
    read_exact(stream, &mut port, "vless target port")?;
    let port = u16::from_be_bytes(port);

    let mut atyp = [0_u8; 1];
    read_exact(stream, &mut atyp, "vless target address type")?;
    let (host, addr_len) = read_vless_host(stream, atyp[0])?;
    let target = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };

    Ok(VlessRequestHeader {
        version: version[0],
        key,
        key_hex: hex_encode(&key),
        addons_len,
        command: command[0],
        target,
        header_len: 1 + 16 + 1 + addons_len + 1 + 2 + 1 + addr_len,
    })
}

fn decode_response_payload(input: &[u8]) -> Result<(usize, Vec<u8>), OutboundError> {
    if input.len() < 2 {
        return Err(OutboundError::BadVless(
            "VLESS response header missing".to_owned(),
        ));
    }
    if input[0] != VLESS_VERSION {
        return Err(OutboundError::BadVless(format!(
            "unexpected VLESS response version: {}",
            input[0]
        )));
    }
    let addons_len = input[1] as usize;
    let response_header_len = 2 + addons_len;
    if input.len() < response_header_len {
        return Err(OutboundError::BadVless(
            "VLESS response addons truncated".to_owned(),
        ));
    }
    Ok((response_header_len, input[response_header_len..].to_vec()))
}

fn read_udp_response_payload(stream: &mut impl Read) -> Result<(usize, Vec<u8>), OutboundError> {
    let mut version = [0_u8; 1];
    read_exact(stream, &mut version, "vless response version")?;
    if version[0] != VLESS_VERSION {
        return Err(OutboundError::BadVless(format!(
            "unexpected VLESS response version: {}",
            version[0]
        )));
    }
    let mut addons_len = [0_u8; 1];
    read_exact(stream, &mut addons_len, "vless response addons length")?;
    let addons_len = addons_len[0] as usize;
    let mut addons = vec![0_u8; addons_len];
    read_exact(stream, &mut addons, "vless response addons")?;

    let mut length = [0_u8; 2];
    read_exact(stream, &mut length, "vless udp response payload length")?;
    let payload_len = u16::from_be_bytes(length) as usize;
    let mut payload = vec![0_u8; payload_len];
    read_exact(stream, &mut payload, "vless udp response payload")?;
    Ok((2 + addons_len, payload))
}

fn read_vless_host(stream: &mut impl Read, atyp: u8) -> Result<(String, usize), OutboundError> {
    match atyp {
        1 => {
            let mut octets = [0_u8; 4];
            read_exact(stream, &mut octets, "vless ipv4 target")?;
            Ok((Ipv4Addr::from(octets).to_string(), 4))
        }
        2 => {
            let mut len = [0_u8; 1];
            read_exact(stream, &mut len, "vless domain length")?;
            let mut host = vec![0_u8; len[0] as usize];
            read_exact(stream, &mut host, "vless domain target")?;
            let host =
                String::from_utf8(host).map_err(|err| OutboundError::BadVless(err.to_string()))?;
            Ok((host, 1 + len[0] as usize))
        }
        3 => {
            let mut octets = [0_u8; 16];
            read_exact(stream, &mut octets, "vless ipv6 target")?;
            Ok((Ipv6Addr::from(octets).to_string(), 16))
        }
        value => Err(OutboundError::BadVless(format!(
            "bad VLESS address type: {value}"
        ))),
    }
}

fn read_exact(stream: &mut impl Read, buf: &mut [u8], context: &str) -> Result<(), OutboundError> {
    stream
        .read_exact(buf)
        .map_err(|err| OutboundError::BadVless(format!("read {context} failed: {err}")))
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
