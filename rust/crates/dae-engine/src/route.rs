use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;

use crate::EngineError;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteAwareTarget {
    pub domain: String,
    pub dest: SocketAddr,
}

impl RouteAwareTarget {
    pub fn dest_is_unspecified(&self) -> bool {
        self.dest.ip().is_unspecified()
    }
}

pub fn route_aware_dial_target(
    host: impl AsRef<str>,
    raw_port: impl AsRef<str>,
) -> Result<RouteAwareTarget, EngineError> {
    let host = host.as_ref();
    let raw_port = raw_port.as_ref();
    if host.trim().is_empty() {
        return Err(EngineError::InvalidTarget("empty host".to_owned()));
    }
    let port = parse_go_uint16(raw_port)?;
    if let Ok(addr) = IpAddr::from_str(host) {
        return Ok(RouteAwareTarget {
            domain: String::new(),
            dest: SocketAddr::new(addr, port),
        });
    }
    Ok(RouteAwareTarget {
        domain: host.to_owned(),
        dest: SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), port),
    })
}

fn parse_go_uint16(raw: &str) -> Result<u16, EngineError> {
    match raw.parse::<u32>() {
        Ok(value) if value <= u16::MAX as u32 => Ok(value as u16),
        Ok(_) => Err(EngineError::InvalidTarget(format!(
            "strconv.ParseUint: parsing \"{raw}\": value out of range"
        ))),
        Err(_) => Err(EngineError::InvalidTarget(format!(
            "strconv.ParseUint: parsing \"{raw}\": invalid syntax"
        ))),
    }
}
