use std::net::{Ipv4Addr, Ipv6Addr};

use crate::error::OutboundError;
use crate::socks5::Socks5Address;

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
        Ok(out)
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
