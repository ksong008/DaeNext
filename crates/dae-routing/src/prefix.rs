use std::net::{IpAddr, Ipv6Addr};
use std::str::FromStr;
use std::sync::Arc;

use crate::RoutingError;

mod index;
use self::index::IpPrefixLookup;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IpPrefix {
    addr: IpAddr,
    bits: u8,
}

#[derive(Clone, Debug)]
pub struct SharedIpPrefixSet {
    prefixes: Arc<[IpPrefix]>,
    lookup: IpPrefixLookup,
}

impl SharedIpPrefixSet {
    pub fn new(prefixes: impl IntoIterator<Item = IpPrefix>) -> Self {
        let prefixes: Arc<[IpPrefix]> = Arc::from(prefixes.into_iter().collect::<Vec<_>>());
        Self {
            lookup: IpPrefixLookup::for_prefixes(&prefixes),
            prefixes,
        }
    }

    pub fn as_slice(&self) -> &[IpPrefix] {
        &self.prefixes
    }

    pub fn iter(&self) -> std::slice::Iter<'_, IpPrefix> {
        self.as_slice().iter()
    }

    pub fn contains(&self, addr: IpAddr) -> bool {
        self.lookup.contains(&self.prefixes, addr)
    }

    pub fn ptr_eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.prefixes, &other.prefixes)
    }
}

impl PartialEq for SharedIpPrefixSet {
    fn eq(&self, other: &Self) -> bool {
        self.prefixes == other.prefixes
    }
}

impl Eq for SharedIpPrefixSet {}

impl IpPrefix {
    pub fn new(addr: IpAddr, bits: u8) -> Result<Self, RoutingError> {
        let max = if addr.is_ipv4() { 32 } else { 128 };
        if bits > max {
            return Err(RoutingError::InvalidPrefixBits {
                input: format!("{addr}/{bits}"),
                bits,
            });
        }
        Ok(Self { addr, bits })
    }

    pub fn parse(input: &str) -> Result<Self, RoutingError> {
        let Some((addr, bits)) = input.split_once('/') else {
            let addr = IpAddr::from_str(input)
                .map_err(|_| RoutingError::InvalidPrefix(input.to_owned()))?;
            let bits = if addr.is_ipv4() { 32 } else { 128 };
            return Ok(Self { addr, bits });
        };

        let addr =
            IpAddr::from_str(addr).map_err(|_| RoutingError::InvalidPrefix(input.to_owned()))?;
        let bits = bits
            .parse::<u8>()
            .map_err(|_| RoutingError::InvalidPrefix(input.to_owned()))?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        if bits > max {
            return Err(RoutingError::InvalidPrefixBits {
                input: input.to_owned(),
                bits,
            });
        }
        Ok(Self { addr, bits })
    }

    pub const fn bits(&self) -> u8 {
        self.bits
    }

    pub const fn addr(&self) -> IpAddr {
        self.addr
    }

    pub fn contains(&self, addr: IpAddr) -> bool {
        match (self.addr, addr) {
            (IpAddr::V4(prefix), IpAddr::V4(addr)) => prefix_contains(
                u32::from(prefix) as u128,
                u32::from(addr) as u128,
                self.bits,
                32,
            ),
            (IpAddr::V6(prefix), IpAddr::V6(addr)) => {
                prefix_contains(ipv6_to_u128(prefix), ipv6_to_u128(addr), self.bits, 128)
            }
            _ => false,
        }
    }
}

impl FromStr for IpPrefix {
    type Err = RoutingError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl std::fmt::Display for IpPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr, self.bits)
    }
}

pub fn parse_prefixes_to_strings(inputs: &[impl AsRef<str>]) -> Result<Vec<String>, RoutingError> {
    inputs
        .iter()
        .map(|input| IpPrefix::parse(input.as_ref()).map(|prefix| prefix.to_string()))
        .collect()
}

fn prefix_contains(prefix: u128, addr: u128, bits: u8, width: u8) -> bool {
    if bits == 0 {
        return true;
    }
    let shift = width - bits;
    (prefix >> shift) == (addr >> shift)
}

fn ipv6_to_u128(addr: Ipv6Addr) -> u128 {
    u128::from_be_bytes(addr.octets())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn bare_ip_is_converted_to_host_prefix() {
        let fixture = dae_golden::load_json("routing/prefix/bare_ip_to_host_prefix.json").unwrap();
        let case = &fixture["cases"][0];
        let inputs: Vec<_> = case["inputs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect();
        let want: Vec<_> = case["want"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap().to_owned())
            .collect();

        assert_eq!(parse_prefixes_to_strings(&inputs).unwrap(), want);
    }

    #[test]
    fn prefix_contains_matches_ip_version() {
        let prefix = IpPrefix::parse("203.0.113.0/24").unwrap();

        assert!(prefix.contains(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 42))));
        assert!(!prefix.contains(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 42))));
        assert!(!prefix.contains(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    #[test]
    fn shared_prefix_set_keeps_a_compact_clone_handle() {
        assert!(std::mem::size_of::<SharedIpPrefixSet>() <= 3 * std::mem::size_of::<usize>());
    }

    #[test]
    fn rebuilt_prefix_sets_do_not_mutate_previous_shared_generations() {
        let old = SharedIpPrefixSet::new(
            (0..64)
                .map(|index| {
                    IpPrefix::new(IpAddr::V4(Ipv4Addr::new(198, 51, index, 42)), 32).unwrap()
                })
                .collect::<Vec<_>>(),
        );
        let inherited = old.clone();
        let replacement = SharedIpPrefixSet::new([
            IpPrefix::parse("203.0.113.0/24").unwrap(),
            IpPrefix::parse("2001:db8::/32").unwrap(),
        ]);

        assert!(old.ptr_eq(&inherited));
        assert!(!old.ptr_eq(&replacement));
        assert!(old.contains("198.51.63.42".parse().unwrap()));
        assert!(!old.contains("203.0.113.42".parse().unwrap()));
        assert!(replacement.contains("203.0.113.42".parse().unwrap()));
    }
}
