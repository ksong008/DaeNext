use crate::error::OutboundError;
use crate::socks5::Socks5Address;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrojanNetwork {
    Tcp,
    Udp,
}

impl TrojanNetwork {
    pub fn parse(input: &str) -> Result<Self, OutboundError> {
        match input {
            "tcp" => Ok(Self::Tcp),
            "udp" => Ok(Self::Udp),
            _ => Err(OutboundError::BadTrojan(format!(
                "unsupported trojan network: {input}"
            ))),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }

    pub fn byte(self) -> u8 {
        match self {
            Self::Tcp => 1,
            Self::Udp => 3,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrojanMetadata {
    pub network: TrojanNetwork,
    pub address: Socks5Address,
}

impl TrojanMetadata {
    pub fn parse(network: &str, target: &str) -> Result<Self, OutboundError> {
        Ok(Self {
            network: TrojanNetwork::parse(network)?,
            address: Socks5Address::parse(target)?,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>, OutboundError> {
        self.address.encode()
    }

    pub fn metadata_type_byte(&self) -> u8 {
        match &self.address {
            Socks5Address::Ipv4 { .. } => 1,
            Socks5Address::Domain { .. } => 3,
            Socks5Address::Ipv6 { .. } => 4,
        }
    }

    pub fn hostname(&self) -> String {
        self.address.host()
    }

    pub fn port(&self) -> u16 {
        self.address.port()
    }

    pub fn len(&self) -> Result<usize, OutboundError> {
        Ok(self.encode()?.len())
    }

    pub fn authority(&self) -> String {
        self.address.authority()
    }
}
