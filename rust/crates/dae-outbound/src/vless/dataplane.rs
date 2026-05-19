use std::io::{Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::error::OutboundError;
use crate::vmess::VMessNetwork;

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

pub fn read_tcp_request_from_stream<S>(
    stream: &mut S,
    payload_len: usize,
) -> Result<VlessTcpRequest, OutboundError>
where
    S: Read,
{
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
    if command[0] != VMessNetwork::Tcp.byte() {
        return Err(OutboundError::BadVless(format!(
            "unexpected VLESS TCP command: {}",
            command[0]
        )));
    }

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

    let mut payload = vec![0_u8; payload_len];
    read_exact(stream, &mut payload, "vless payload")?;
    Ok(VlessTcpRequest {
        version: version[0],
        key,
        key_hex: hex_encode(&key),
        addons_len,
        command: command[0],
        target,
        payload,
        header_len: 1 + 16 + 1 + addons_len + 1 + 2 + 1 + addr_len,
    })
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
