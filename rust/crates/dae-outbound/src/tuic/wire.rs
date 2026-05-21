use std::net::{Ipv4Addr, Ipv6Addr};

use crate::error::OutboundError;

pub const TUIC_VERSION5: u8 = 0x05;
pub const TUIC_AUTHENTICATE_TYPE: u8 = 0x00;
pub const TUIC_PACKET_TYPE: u8 = 0x02;
pub const TUIC_AUTH_TOKEN_LEN: usize = 32;
pub const TUIC_AUTHENTICATE_FRAME_LEN: usize = 2 + 16 + TUIC_AUTH_TOKEN_LEN;

const ATYP_DOMAIN_NAME: u8 = 0;
const ATYP_IPV4: u8 = 1;
const ATYP_IPV6: u8 = 2;
const ATYP_NONE: u8 = 255;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct TuicAuthenticateFrame {
    pub(super) version: u8,
    pub(super) uuid: [u8; 16],
    pub(super) token: [u8; TUIC_AUTH_TOKEN_LEN],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct TuicPacketFrame {
    pub(super) version: u8,
    pub(super) assoc_id: u16,
    pub(super) packet_id: u16,
    pub(super) frag_total: u8,
    pub(super) frag_id: u8,
    pub(super) size: u16,
    pub(super) target: String,
    pub(super) payload: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TuicAddress {
    atyp: u8,
    addr: Vec<u8>,
    port: u16,
    target: String,
}

pub(super) fn parse_uuid(input: &str) -> Result<[u8; 16], OutboundError> {
    let compact = input.replace('-', "");
    if compact.len() != 32 || !compact.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(bad_wire(format!("parse UUID: {input}")));
    }
    let mut out = [0_u8; 16];
    for index in 0..16 {
        out[index] = u8::from_str_radix(&compact[index * 2..index * 2 + 2], 16)
            .map_err(|err| bad_wire(format!("parse UUID byte: {err}")))?;
    }
    Ok(out)
}

pub(super) fn build_authenticate_frame(
    uuid: [u8; 16],
    token: [u8; TUIC_AUTH_TOKEN_LEN],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(TUIC_AUTHENTICATE_FRAME_LEN);
    out.push(TUIC_VERSION5);
    out.push(TUIC_AUTHENTICATE_TYPE);
    out.extend_from_slice(&uuid);
    out.extend_from_slice(&token);
    out
}

pub(super) fn parse_authenticate_frame(
    input: &[u8],
) -> Result<TuicAuthenticateFrame, OutboundError> {
    if input.len() != TUIC_AUTHENTICATE_FRAME_LEN {
        return Err(bad_wire(format!(
            "invalid TUIC authenticate frame length: {}",
            input.len()
        )));
    }
    if input[1] != TUIC_AUTHENTICATE_TYPE {
        return Err(bad_wire(format!(
            "bad TUIC authenticate command type: {:#x}",
            input[1]
        )));
    }
    let mut uuid = [0_u8; 16];
    uuid.copy_from_slice(&input[2..18]);
    let mut token = [0_u8; TUIC_AUTH_TOKEN_LEN];
    token.copy_from_slice(&input[18..50]);
    Ok(TuicAuthenticateFrame {
        version: input[0],
        uuid,
        token,
    })
}

pub(super) fn build_packet_frame(
    assoc_id: u16,
    packet_id: u16,
    frag_total: u8,
    frag_id: u8,
    target: &str,
    payload: &[u8],
) -> Result<Vec<u8>, OutboundError> {
    if payload.is_empty() || payload.len() > u16::MAX as usize {
        return Err(bad_wire("invalid TUIC packet payload length"));
    }
    let address = build_address(target)?;
    let mut out = Vec::with_capacity(2 + 8 + address.encoded_len() + payload.len());
    out.push(TUIC_VERSION5);
    out.push(TUIC_PACKET_TYPE);
    out.extend_from_slice(&assoc_id.to_be_bytes());
    out.extend_from_slice(&packet_id.to_be_bytes());
    out.push(frag_total);
    out.push(frag_id);
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    address.write_to(&mut out);
    out.extend_from_slice(payload);
    Ok(out)
}

pub(super) fn parse_packet_frame(input: &[u8]) -> Result<TuicPacketFrame, OutboundError> {
    if input.len() < 10 {
        return Err(bad_wire("short TUIC packet frame"));
    }
    if input[1] != TUIC_PACKET_TYPE {
        return Err(bad_wire(format!(
            "bad TUIC packet command type: {:#x}",
            input[1]
        )));
    }
    let assoc_id = u16::from_be_bytes([input[2], input[3]]);
    let packet_id = u16::from_be_bytes([input[4], input[5]]);
    let frag_total = input[6];
    let frag_id = input[7];
    let size = u16::from_be_bytes([input[8], input[9]]);
    let (address, offset) = read_address(input, 10)?;
    let payload_end = offset + size as usize;
    if input.len() != payload_end {
        return Err(bad_wire("TUIC packet payload length mismatch"));
    }
    Ok(TuicPacketFrame {
        version: input[0],
        assoc_id,
        packet_id,
        frag_total,
        frag_id,
        size,
        target: address.target,
        payload: input[offset..payload_end].to_vec(),
    })
}

fn build_address(target: &str) -> Result<TuicAddress, OutboundError> {
    let (host, port) = split_host_port(target)?;
    if let Ok(ipv4) = host.parse::<Ipv4Addr>() {
        return Ok(TuicAddress {
            atyp: ATYP_IPV4,
            addr: ipv4.octets().to_vec(),
            port,
            target: format!("{ipv4}:{port}"),
        });
    }
    if let Ok(ipv6) = host.parse::<Ipv6Addr>() {
        return Ok(TuicAddress {
            atyp: ATYP_IPV6,
            addr: ipv6.octets().to_vec(),
            port,
            target: format!("[{ipv6}]:{port}"),
        });
    }
    if host.is_empty() || host.len() > u8::MAX as usize {
        return Err(bad_wire("invalid TUIC domain address length"));
    }
    let mut addr = Vec::with_capacity(host.len() + 1);
    addr.push(host.len() as u8);
    addr.extend_from_slice(host.as_bytes());
    Ok(TuicAddress {
        atyp: ATYP_DOMAIN_NAME,
        addr,
        port,
        target: format!("{host}:{port}"),
    })
}

fn read_address(input: &[u8], offset: usize) -> Result<(TuicAddress, usize), OutboundError> {
    let Some(&atyp) = input.get(offset) else {
        return Err(bad_wire("missing TUIC address type"));
    };
    if atyp == ATYP_NONE {
        return Ok((
            TuicAddress {
                atyp,
                addr: Vec::new(),
                port: 0,
                target: String::new(),
            },
            offset + 1,
        ));
    }
    let mut cursor = offset + 1;
    let addr = match atyp {
        ATYP_IPV4 => {
            if input.len() < cursor + 4 {
                return Err(bad_wire("short TUIC IPv4 address"));
            }
            let addr = input[cursor..cursor + 4].to_vec();
            cursor += 4;
            addr
        }
        ATYP_IPV6 => {
            if input.len() < cursor + 16 {
                return Err(bad_wire("short TUIC IPv6 address"));
            }
            let addr = input[cursor..cursor + 16].to_vec();
            cursor += 16;
            addr
        }
        ATYP_DOMAIN_NAME => {
            let Some(&len) = input.get(cursor) else {
                return Err(bad_wire("missing TUIC domain length"));
            };
            let domain_len = len as usize;
            if domain_len == 0 || input.len() < cursor + 1 + domain_len {
                return Err(bad_wire("invalid TUIC domain length"));
            }
            let addr = input[cursor..cursor + 1 + domain_len].to_vec();
            cursor += 1 + domain_len;
            addr
        }
        _ => return Err(bad_wire(format!("unsupported TUIC address type: {atyp}"))),
    };
    if input.len() < cursor + 2 {
        return Err(bad_wire("missing TUIC address port"));
    }
    let port = u16::from_be_bytes([input[cursor], input[cursor + 1]]);
    cursor += 2;
    let target = target_from_address(atyp, &addr, port)?;
    Ok((
        TuicAddress {
            atyp,
            addr,
            port,
            target,
        },
        cursor,
    ))
}

fn split_host_port(target: &str) -> Result<(String, u16), OutboundError> {
    if let Some(rest) = target.strip_prefix('[') {
        let (host, port) = rest
            .split_once("]:")
            .ok_or_else(|| bad_wire(format!("invalid TUIC target: {target}")))?;
        return Ok((host.to_owned(), parse_port(port)?));
    }
    let (host, port) = target
        .rsplit_once(':')
        .ok_or_else(|| bad_wire(format!("invalid TUIC target: {target}")))?;
    Ok((host.to_owned(), parse_port(port)?))
}

fn parse_port(input: &str) -> Result<u16, OutboundError> {
    input
        .parse::<u16>()
        .map_err(|err| bad_wire(format!("invalid TUIC target port: {err}")))
}

fn target_from_address(atyp: u8, addr: &[u8], port: u16) -> Result<String, OutboundError> {
    match atyp {
        ATYP_IPV4 => {
            if addr.len() != 4 {
                return Err(bad_wire("invalid TUIC IPv4 address length"));
            }
            Ok(format!(
                "{}.{}.{}.{}:{}",
                addr[0], addr[1], addr[2], addr[3], port
            ))
        }
        ATYP_IPV6 => {
            if addr.len() != 16 {
                return Err(bad_wire("invalid TUIC IPv6 address length"));
            }
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(addr);
            Ok(format!("[{}]:{}", Ipv6Addr::from(octets), port))
        }
        ATYP_DOMAIN_NAME => {
            if addr.is_empty() {
                return Err(bad_wire("invalid TUIC domain address"));
            }
            let domain = std::str::from_utf8(&addr[1..])
                .map_err(|err| bad_wire(format!("TUIC domain utf8: {err}")))?;
            Ok(format!("{domain}:{port}"))
        }
        _ => Err(bad_wire(format!("unsupported TUIC address type: {atyp}"))),
    }
}

impl TuicAddress {
    fn encoded_len(&self) -> usize {
        if self.atyp == ATYP_NONE {
            1
        } else {
            1 + self.addr.len() + 2
        }
    }

    fn write_to(&self, out: &mut Vec<u8>) {
        out.push(self.atyp);
        if self.atyp != ATYP_NONE {
            out.extend_from_slice(&self.addr);
            out.extend_from_slice(&self.port.to_be_bytes());
        }
    }
}

fn bad_wire(message: impl Into<String>) -> OutboundError {
    OutboundError::BadTuic(message.into())
}
