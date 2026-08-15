use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;

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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteAwareTargetError(String);

impl fmt::Display for RouteAwareTargetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for RouteAwareTargetError {}

pub fn route_aware_dial_target(
    host: impl AsRef<str>,
    raw_port: impl AsRef<str>,
) -> Result<RouteAwareTarget, RouteAwareTargetError> {
    let host = host.as_ref();
    let raw_port = raw_port.as_ref();
    if host.trim().is_empty() {
        return Err(RouteAwareTargetError("empty host".to_owned()));
    }
    let port = parse_uint16_decimal(raw_port)?;
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

fn parse_uint16_decimal(raw: &str) -> Result<u16, RouteAwareTargetError> {
    match raw.parse::<u32>() {
        Ok(value) if value <= u16::MAX as u32 => Ok(value as u16),
        Ok(_) => Err(RouteAwareTargetError(format!(
            "strconv.ParseUint: parsing \"{raw}\": value out of range"
        ))),
        Err(_) => Err(RouteAwareTargetError(format!(
            "strconv.ParseUint: parsing \"{raw}\": invalid syntax"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_aware_target_matches_golden_fixture() {
        let fixture = dae_golden::load_json("engine/route_aware/target.json").unwrap();
        for case in fixture["cases"].as_array().unwrap() {
            let got = route_aware_dial_target(
                case["host"].as_str().unwrap(),
                case["port"].as_str().unwrap(),
            );
            if case["ok"].as_bool().unwrap() {
                let got = got.unwrap();
                assert_eq!(got.domain, case["domain"].as_str().unwrap());
                assert_eq!(got.dest.to_string(), case["dest"].as_str().unwrap());
                assert_eq!(
                    got.dest_is_unspecified(),
                    case["dest_is_unspecified"].as_bool().unwrap()
                );
            } else {
                assert_eq!(
                    got.unwrap_err().to_string(),
                    case["error"].as_str().unwrap()
                );
            }
        }
    }
}
