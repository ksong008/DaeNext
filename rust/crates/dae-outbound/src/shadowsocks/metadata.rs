use crate::error::OutboundError;
use crate::socks5::Socks5Address;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MetadataType {
    Ipv4,
    Domain,
    Ipv6,
    Msg,
}

impl MetadataType {
    pub fn byte(self) -> u8 {
        match self {
            Self::Ipv4 => 1,
            Self::Domain => 3,
            Self::Ipv6 => 4,
            Self::Msg => 5,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShadowsocksMetadata {
    pub address: Socks5Address,
}

impl ShadowsocksMetadata {
    pub fn parse(target: &str) -> Result<Self, OutboundError> {
        Ok(Self {
            address: Socks5Address::parse(target)?,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>, OutboundError> {
        self.address.encode()
    }

    pub fn metadata_type(&self) -> MetadataType {
        match &self.address {
            Socks5Address::Ipv4 { .. } => MetadataType::Ipv4,
            Socks5Address::Domain { .. } => MetadataType::Domain,
            Socks5Address::Ipv6 { .. } => MetadataType::Ipv6,
        }
    }

    pub fn hostname(&self) -> String {
        self.address.host()
    }

    pub fn port(&self) -> u16 {
        self.address.port()
    }

    pub fn authority(&self) -> String {
        self.address.authority()
    }
}
