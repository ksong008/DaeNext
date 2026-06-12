use super::*;
pub struct Query {
    pub source: Option<IpAddr>,
    pub dest: IpAddr,
    pub source_port: Option<u16>,
    pub dest_port: u16,
    pub ip_version: Option<u8>,
    pub l4proto: Option<u8>,
    pub domain: String,
    pub process_name: Option<String>,
    pub dscp: Option<u8>,
    pub mac: Option<[u8; 6]>,
}

impl Default for Query {
    fn default() -> Self {
        Self {
            source: None,
            dest: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            source_port: None,
            dest_port: 0,
            ip_version: None,
            l4proto: None,
            domain: String::new(),
            process_name: None,
            dscp: None,
            mac: None,
        }
    }
}

impl Query {
    pub fn tcp(dest: IpAddr, dest_port: u16, domain: impl Into<String>) -> Self {
        Self {
            dest,
            dest_port,
            l4proto: Some(L4_TCP),
            domain: domain.into(),
            ..Self::default()
        }
    }

    pub fn udp(dest: IpAddr, dest_port: u16, domain: impl Into<String>) -> Self {
        Self {
            dest,
            dest_port,
            l4proto: Some(L4_UDP),
            domain: domain.into(),
            ..Self::default()
        }
    }

    pub(super) fn effective_ip_version(&self) -> u8 {
        self.ip_version.unwrap_or_else(|| {
            if self.dest.is_ipv4() {
                IP_VERSION_4
            } else {
                IP_VERSION_6
            }
        })
    }

    pub(super) fn process_name_bytes(&self) -> Option<[u8; 16]> {
        let process_name = self.process_name.as_ref()?;
        if process_name.is_empty() {
            return None;
        }
        let mut raw = [0_u8; 16];
        let bytes = process_name.as_bytes();
        let copy_len = bytes.len().min(raw.len());
        raw[..copy_len].copy_from_slice(&bytes[..copy_len]);
        Some(raw)
    }

    pub(super) fn mac_addr(&self) -> Option<IpAddr> {
        let mac = self.mac?;
        let mut octets = [0_u8; 16];
        octets[10..].copy_from_slice(&mac);
        Some(IpAddr::V6(Ipv6Addr::from(octets)))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MatchOutcome {
    pub outbound: OutboundIndex,
    pub mark: u32,
    pub must: bool,
}

#[derive(Clone, Debug)]
pub struct RoutingMatcher {
    pub(super) lpm_sets: BTreeMap<u32, SharedIpPrefixSet>,
    pub(super) domain_matcher: DomainMatcher,
    pub(super) matches: Vec<MatchSet>,
}

#[derive(Clone, Debug)]
pub struct RoutingDomainSet {
    pub bit: usize,
    pub key: DomainKey,
    pub patterns: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct RoutingSharedDomainSet {
    pub bit: usize,
    pub patterns: SharedDomainSet,
}

#[derive(Clone, Debug)]
pub struct RoutingLpmSet {
    pub index: u32,
    pub prefixes: Vec<IpPrefix>,
}

#[derive(Clone, Debug)]
pub struct RoutingSharedLpmSet {
    pub index: u32,
    pub prefixes: SharedIpPrefixSet,
}

#[derive(Clone, Debug)]
pub struct RoutingMatchSet {
    pub kind: RoutingMatchKind,
    pub outbound: OutboundIndex,
    pub not: bool,
    pub mark: u32,
    pub must: bool,
}

#[derive(Clone, Debug)]
pub enum RoutingMatchKind {
    DomainSet,
    IpSet { lpm_index: u32 },
    SourceIpSet { lpm_index: u32 },
    Port { start: u16, end: u16 },
    SourcePort { start: u16, end: u16 },
    L4Proto { value: u8 },
    IpVersion { value: u8 },
    Mac { lpm_index: u32 },
    ProcessName { value: [u8; 16] },
    Dscp { value: u8 },
    Fallback,
}

#[derive(Clone, Debug)]
pub(super) struct MatchSet {
    pub(super) match_type: MatchType,
    pub(super) outbound: OutboundIndex,
    pub(super) not: bool,
    pub(super) mark: u32,
    pub(super) must: bool,
    pub(super) lpm_index: Option<u32>,
    pub(super) port_start: Option<u16>,
    pub(super) port_end: Option<u16>,
    pub(super) value_u8: Option<u8>,
    pub(super) process_name: Option<[u8; 16]>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum MatchType {
    DomainSet,
    IpSet,
    SourceIpSet,
    Port,
    SourcePort,
    L4Proto,
    IpVersion,
    Mac,
    ProcessName,
    Dscp,
    Fallback,
}
