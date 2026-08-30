use std::net::{Ipv4Addr, Ipv6Addr};

use crate::error::OutboundError;
use crate::socks5::Socks5Address;

pub const VMESS_PACKET_ADDR_MAGIC_ADDRESS: &str = "sp.packet-addr.v2fly.arpa";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VMessNetwork {
    Tcp,
    Udp,
    Mux,
}

impl VMessNetwork {
    pub fn parse(input: &str) -> Result<Self, OutboundError> {
        match input {
            "tcp" => Ok(Self::Tcp),
            "udp" => Ok(Self::Udp),
            "mux" => Ok(Self::Mux),
            _ => Err(OutboundError::BadVmess(format!(
                "unsupported vmess network: {input}"
            ))),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Mux => "mux",
        }
    }

    pub fn byte(self) -> u8 {
        match self {
            Self::Tcp => 1,
            Self::Udp => 2,
            Self::Mux => 3,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VMessMetadataType {
    Ipv4,
    Domain,
    Ipv6,
    Msg,
}

impl VMessMetadataType {
    pub fn byte(self) -> u8 {
        match self {
            Self::Ipv4 => 1,
            Self::Domain => 2,
            Self::Ipv6 => 3,
            Self::Msg => 4,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VMessMetadata {
    pub network: VMessNetwork,
    pub address: Socks5Address,
}

impl VMessMetadata {
    pub fn parse(network: &str, target: &str) -> Result<Self, OutboundError> {
        Ok(Self {
            network: VMessNetwork::parse(network)?,
            address: Socks5Address::parse(target)?,
        })
    }

    pub fn metadata_type(&self) -> VMessMetadataType {
        match &self.address {
            Socks5Address::Ipv4 { .. } => VMessMetadataType::Ipv4,
            Socks5Address::Domain { .. } => VMessMetadataType::Domain,
            Socks5Address::Ipv6 { .. } => VMessMetadataType::Ipv6,
        }
    }

    pub fn addr_len(&self) -> usize {
        match &self.address {
            Socks5Address::Ipv4 { .. } => 4,
            Socks5Address::Ipv6 { .. } => 16,
            Socks5Address::Domain { hostname, .. } => 1 + hostname.len(),
        }
    }

    pub fn encode_addr(&self) -> Result<Vec<u8>, OutboundError> {
        let mut out = Vec::with_capacity(self.addr_len());
        self.write_addr_to(&mut out)?;
        Ok(out)
    }

    pub fn write_addr_to(&self, out: &mut Vec<u8>) -> Result<(), OutboundError> {
        match &self.address {
            Socks5Address::Ipv4 { addr, .. } => out.extend_from_slice(&addr.octets()),
            Socks5Address::Ipv6 { addr, .. } => out.extend_from_slice(&addr.octets()),
            Socks5Address::Domain { hostname, .. } => {
                if hostname.len() > u8::MAX as usize {
                    return Err(OutboundError::BadVmess(format!(
                        "domain name too long: {} bytes",
                        hostname.len()
                    )));
                }
                out.push(hostname.len() as u8);
                out.extend_from_slice(hostname.as_bytes());
            }
        }
        Ok(())
    }

    pub fn write_addr_to_slice(&self, out: &mut [u8]) -> Result<usize, OutboundError> {
        let needed = self.addr_len();
        if out.len() < needed {
            return Err(OutboundError::BadVmess(format!(
                "vmess metadata buffer too small: need {needed}, got {}",
                out.len()
            )));
        }
        match &self.address {
            Socks5Address::Ipv4 { addr, .. } => {
                out[..4].copy_from_slice(&addr.octets());
            }
            Socks5Address::Ipv6 { addr, .. } => {
                out[..16].copy_from_slice(&addr.octets());
            }
            Socks5Address::Domain { hostname, .. } => {
                if hostname.len() > u8::MAX as usize {
                    return Err(OutboundError::BadVmess(format!(
                        "domain name too long: {} bytes",
                        hostname.len()
                    )));
                }
                out[0] = hostname.len() as u8;
                out[1..needed].copy_from_slice(hostname.as_bytes());
            }
        }
        Ok(needed)
    }

    pub fn hostname(&self) -> String {
        self.address.host()
    }

    pub fn port(&self) -> u16 {
        self.address.port()
    }
}

pub fn put_packet_addr(addr: &str) -> Result<Vec<u8>, OutboundError> {
    let parsed = Socks5Address::parse(addr)?;
    let mut out = Vec::new();
    match parsed {
        Socks5Address::Ipv4 { addr, port } => {
            out.push(1);
            out.extend_from_slice(&addr.octets());
            out.extend_from_slice(&port.to_be_bytes());
        }
        Socks5Address::Ipv6 { addr, port } => {
            out.push(2);
            out.extend_from_slice(&addr.octets());
            out.extend_from_slice(&port.to_be_bytes());
        }
        Socks5Address::Domain { hostname, .. } => {
            return Err(OutboundError::BadVmess(format!(
                "vmess packet addr requires IP address: {hostname}"
            )));
        }
    }
    Ok(out)
}

pub fn packet_addr_magic_target(packet_target: &str) -> Result<String, OutboundError> {
    let parsed = Socks5Address::parse(packet_target)?;
    match parsed {
        Socks5Address::Ipv4 { port, .. } | Socks5Address::Ipv6 { port, .. } => {
            Ok(format!("{VMESS_PACKET_ADDR_MAGIC_ADDRESS}:{port}"))
        }
        Socks5Address::Domain { hostname, .. } => Err(OutboundError::BadVmess(format!(
            "vmess packet addr requires IP address: {hostname}"
        ))),
    }
}

pub fn put_packet_addr_payload(addr: &str, payload: &[u8]) -> Result<Vec<u8>, OutboundError> {
    let mut out = put_packet_addr(addr)?;
    out.extend_from_slice(payload);
    Ok(out)
}

pub fn parse_packet_addr_payload(input: &[u8]) -> Result<(String, usize, Vec<u8>), OutboundError> {
    let Some((&addr_type, rest)) = input.split_first() else {
        return Err(OutboundError::BadVmess(
            "vmess packet addr payload is empty".to_owned(),
        ));
    };
    match addr_type {
        1 => {
            if rest.len() < 6 {
                return Err(OutboundError::BadVmess(
                    "vmess packet addr ipv4 payload too short".to_owned(),
                ));
            }
            let addr = Ipv4Addr::new(rest[0], rest[1], rest[2], rest[3]);
            let port = u16::from_be_bytes([rest[4], rest[5]]);
            Ok((format!("{addr}:{port}"), 7, rest[6..].to_vec()))
        }
        2 => {
            if rest.len() < 18 {
                return Err(OutboundError::BadVmess(
                    "vmess packet addr ipv6 payload too short".to_owned(),
                ));
            }
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(&rest[..16]);
            let addr = Ipv6Addr::from(octets);
            let port = u16::from_be_bytes([rest[16], rest[17]]);
            Ok((format!("[{addr}]:{port}"), 19, rest[18..].to_vec()))
        }
        _ => Err(OutboundError::BadVmess(format!(
            "invalid vmess packet addr type: {addr_type}"
        ))),
    }
}

pub fn packet_addr_type(input: &[u8]) -> VMessMetadataType {
    match input.first().copied() {
        Some(1) => VMessMetadataType::Ipv4,
        Some(2) => VMessMetadataType::Ipv6,
        _ => VMessMetadataType::Msg,
    }
}

pub fn parse_ip_host(host: &str) -> Option<VMessMetadataType> {
    if host.parse::<Ipv4Addr>().is_ok() {
        return Some(VMessMetadataType::Ipv4);
    }
    if host.parse::<Ipv6Addr>().is_ok() {
        return Some(VMessMetadataType::Ipv6);
    }
    None
}
