use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use crate::error::OutboundError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddressKind {
    Ipv4,
    Domain,
    Ipv6,
}

impl AddressKind {
    pub fn atyp(self) -> u8 {
        match self {
            Self::Ipv4 => 1,
            Self::Domain => 3,
            Self::Ipv6 => 4,
        }
    }

    pub fn from_atyp(atyp: u8) -> Result<Self, OutboundError> {
        match atyp {
            1 => Ok(Self::Ipv4),
            3 => Ok(Self::Domain),
            4 => Ok(Self::Ipv6),
            _ => Err(OutboundError::BadSocks5Address(format!(
                "invalid address type: {atyp}"
            ))),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Socks5Address {
    Ipv4 { addr: Ipv4Addr, port: u16 },
    Domain { hostname: String, port: u16 },
    Ipv6 { addr: Ipv6Addr, port: u16 },
}

impl Socks5Address {
    pub fn parse(input: &str) -> Result<Self, OutboundError> {
        let (host, port) = split_host_port(input)?;
        if let Ok(addr) = host.parse::<Ipv4Addr>() {
            return Ok(Self::Ipv4 { addr, port });
        }
        if let Ok(addr) = host.parse::<Ipv6Addr>() {
            return Ok(Self::Ipv6 { addr, port });
        }
        Ok(Self::Domain {
            hostname: host.to_owned(),
            port,
        })
    }

    pub fn decode(input: &[u8]) -> Result<(Self, usize), OutboundError> {
        let Some((&atyp, rest)) = input.split_first() else {
            return Err(OutboundError::BadSocks5Address("too short".to_owned()));
        };
        match AddressKind::from_atyp(atyp)? {
            AddressKind::Ipv4 => {
                if rest.len() < 6 {
                    return Err(OutboundError::BadSocks5Address(
                        "ipv4 address too short".to_owned(),
                    ));
                }
                let addr = Ipv4Addr::new(rest[0], rest[1], rest[2], rest[3]);
                let port = u16::from_be_bytes([rest[4], rest[5]]);
                Ok((Self::Ipv4 { addr, port }, 1 + 4 + 2))
            }
            AddressKind::Ipv6 => {
                if rest.len() < 18 {
                    return Err(OutboundError::BadSocks5Address(
                        "ipv6 address too short".to_owned(),
                    ));
                }
                let mut octets = [0_u8; 16];
                octets.copy_from_slice(&rest[..16]);
                let addr = Ipv6Addr::from(octets);
                let port = u16::from_be_bytes([rest[16], rest[17]]);
                Ok((Self::Ipv6 { addr, port }, 1 + 16 + 2))
            }
            AddressKind::Domain => {
                let Some((&len, rest)) = rest.split_first() else {
                    return Err(OutboundError::BadSocks5Address(
                        "domain length missing".to_owned(),
                    ));
                };
                let len = len as usize;
                if rest.len() < len + 2 {
                    return Err(OutboundError::BadSocks5Address(
                        "domain address too short".to_owned(),
                    ));
                }
                let hostname = std::str::from_utf8(&rest[..len])
                    .map_err(|err| OutboundError::BadSocks5Address(err.to_string()))?
                    .to_owned();
                let port = u16::from_be_bytes([rest[len], rest[len + 1]]);
                Ok((Self::Domain { hostname, port }, 1 + 1 + len + 2))
            }
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, OutboundError> {
        let mut out = Vec::with_capacity(self.encoded_len());
        self.write_to(&mut out)?;
        Ok(out)
    }

    pub fn write_to(&self, out: &mut Vec<u8>) -> Result<(), OutboundError> {
        out.push(self.kind().atyp());
        match self {
            Self::Ipv4 { addr, port } => {
                out.extend_from_slice(&addr.octets());
                out.extend_from_slice(&port.to_be_bytes());
            }
            Self::Ipv6 { addr, port } => {
                out.extend_from_slice(&addr.octets());
                out.extend_from_slice(&port.to_be_bytes());
            }
            Self::Domain { hostname, port } => {
                if hostname.len() > u8::MAX as usize {
                    return Err(OutboundError::BadSocks5Address(format!(
                        "domain name too long: {} bytes",
                        hostname.len()
                    )));
                }
                out.push(hostname.len() as u8);
                out.extend_from_slice(hostname.as_bytes());
                out.extend_from_slice(&port.to_be_bytes());
            }
        }
        Ok(())
    }

    pub fn encoded_len(&self) -> usize {
        match self {
            Self::Ipv4 { .. } => 1 + 4 + 2,
            Self::Domain { hostname, .. } => 1 + 1 + hostname.len() + 2,
            Self::Ipv6 { .. } => 1 + 16 + 2,
        }
    }

    pub fn socket_addr(&self) -> Option<SocketAddr> {
        match self {
            Self::Ipv4 { addr, port } => Some(SocketAddr::V4(SocketAddrV4::new(*addr, *port))),
            Self::Ipv6 { addr, port } => {
                Some(SocketAddr::V6(SocketAddrV6::new(*addr, *port, 0, 0)))
            }
            Self::Domain { .. } => None,
        }
    }

    pub fn kind(&self) -> AddressKind {
        match self {
            Self::Ipv4 { .. } => AddressKind::Ipv4,
            Self::Domain { .. } => AddressKind::Domain,
            Self::Ipv6 { .. } => AddressKind::Ipv6,
        }
    }

    pub fn host(&self) -> String {
        match self {
            Self::Ipv4 { addr, .. } => addr.to_string(),
            Self::Domain { hostname, .. } => hostname.clone(),
            Self::Ipv6 { addr, .. } => addr.to_string(),
        }
    }

    pub fn port(&self) -> u16 {
        match self {
            Self::Ipv4 { port, .. } | Self::Domain { port, .. } | Self::Ipv6 { port, .. } => *port,
        }
    }

    pub fn authority(&self) -> String {
        match self {
            Self::Ipv6 { addr, port } => format!("[{addr}]:{port}"),
            _ => format!("{}:{}", self.host(), self.port()),
        }
    }
}

fn split_host_port(input: &str) -> Result<(&str, u16), OutboundError> {
    let (host, port) = if let Some(rest) = input.strip_prefix('[') {
        let Some((host, tail)) = rest.split_once(']') else {
            return Err(OutboundError::BadSocks5Address(input.to_owned()));
        };
        let Some(port) = tail.strip_prefix(':') else {
            return Err(OutboundError::BadSocks5Address(input.to_owned()));
        };
        (host, port)
    } else {
        let Some((host, port)) = input.rsplit_once(':') else {
            return Err(OutboundError::BadSocks5Address(input.to_owned()));
        };
        if host.contains(':') {
            return Err(OutboundError::BadSocks5Address(input.to_owned()));
        }
        (host, port)
    };
    let port = port
        .parse::<u16>()
        .map_err(|_| OutboundError::BadSocks5Address(format!("invalid port: {port}")))?;
    Ok((host, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_all_address_kinds() {
        for input in ["127.0.0.1:80", "example.com:443", "[::1]:53"] {
            let address = Socks5Address::parse(input).unwrap();
            let encoded = address.encode().unwrap();
            let (decoded, consumed) = Socks5Address::decode(&encoded).unwrap();
            assert_eq!(decoded, address);
            assert_eq!(consumed, encoded.len());
        }
    }
}
