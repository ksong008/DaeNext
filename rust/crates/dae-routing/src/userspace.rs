use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use dae_core_types::OutboundIndex;
use serde_json::Value;

use crate::RoutingError;
use crate::domain::{DomainKey, DomainMatcher};
use crate::prefix::IpPrefix;

const L4_TCP: u8 = 1;
const L4_UDP: u8 = 2;
const IP_VERSION_4: u8 = 1;
const IP_VERSION_6: u8 = 2;

#[derive(Clone, Debug)]
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

    fn effective_ip_version(&self) -> u8 {
        self.ip_version.unwrap_or_else(|| {
            if self.dest.is_ipv4() {
                IP_VERSION_4
            } else {
                IP_VERSION_6
            }
        })
    }

    fn process_name_bytes(&self) -> Option<[u8; 16]> {
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

    fn mac_addr(&self) -> Option<IpAddr> {
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
    lpm_sets: BTreeMap<u32, Vec<IpPrefix>>,
    domain_matcher: DomainMatcher,
    matches: Vec<MatchSet>,
}

#[derive(Clone, Debug)]
struct MatchSet {
    match_type: MatchType,
    outbound: OutboundIndex,
    not: bool,
    mark: u32,
    must: bool,
    lpm_index: Option<u32>,
    port_start: Option<u16>,
    port_end: Option<u16>,
    value_u8: Option<u8>,
    process_name: Option<[u8; 16]>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MatchType {
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

impl RoutingMatcher {
    pub fn from_fixture_value(value: &Value) -> Result<Self, RoutingError> {
        let mut max_domain_bit = 0_usize;
        let mut domain_sets = Vec::new();
        for set in value
            .get("domain_sets")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let bit = required_u64(set, "bit")? as usize;
            let key = DomainKey::try_from(required_str(set, "key")?)?;
            let patterns = required_array(set, "patterns")?
                .iter()
                .map(|value| {
                    value.as_str().map(str::to_owned).ok_or_else(|| {
                        RoutingError::InvalidFixture("domain pattern must be string".to_owned())
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            max_domain_bit = max_domain_bit.max(bit + 1);
            domain_sets.push((bit, key, patterns));
        }

        let matches_json = required_array(value, "matches")?;
        let mut matches = Vec::with_capacity(matches_json.len());
        for item in matches_json {
            matches.push(MatchSet::from_fixture_value(item)?);
        }

        let mut domain_matcher = DomainMatcher::new(max_domain_bit.max(matches.len()).max(1));
        for (bit, key, patterns) in domain_sets {
            domain_matcher.add_set(bit, patterns, key)?;
        }

        let mut lpm_sets = BTreeMap::new();
        for set in value
            .get("lpm_sets")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let index = required_u64(set, "index")? as u32;
            let prefixes = required_array(set, "prefixes")?
                .iter()
                .map(|value| {
                    let prefix = value.as_str().ok_or_else(|| {
                        RoutingError::InvalidFixture("prefix must be string".to_owned())
                    })?;
                    IpPrefix::parse(prefix)
                })
                .collect::<Result<Vec<_>, _>>()?;
            lpm_sets.insert(index, prefixes);
        }

        Ok(Self {
            lpm_sets,
            domain_matcher,
            matches,
        })
    }

    pub fn match_query(&self, query: &Query) -> Result<OutboundIndex, RoutingError> {
        self.match_query_detail(query)
            .map(|outcome| outcome.outbound)
    }

    pub fn match_query_detail(&self, query: &Query) -> Result<MatchOutcome, RoutingError> {
        let domain_bitmap = if query.domain.is_empty() {
            Vec::new()
        } else {
            self.domain_matcher.match_domain_bitmap(&query.domain)
        };

        let mut good_subrule = false;
        let mut bad_rule = false;
        let mut must_rules_hit = false;
        for (index, match_set) in self.matches.iter().enumerate() {
            if !bad_rule
                && !good_subrule
                && match_set.matches(index, query, &domain_bitmap, &self.lpm_sets)
            {
                good_subrule = true;
            }

            let outbound = match_set.outbound;
            if outbound != OutboundIndex::LOGICAL_OR {
                if good_subrule == match_set.not {
                    bad_rule = true;
                }
                good_subrule = false;
            }

            if outbound.value() & OutboundIndex::LOGICAL_MASK.value()
                != OutboundIndex::LOGICAL_MASK.value()
            {
                if !bad_rule {
                    if outbound == OutboundIndex::MUST_RULES {
                        must_rules_hit = true;
                        continue;
                    }
                    return Ok(MatchOutcome {
                        outbound,
                        mark: match_set.mark,
                        must: match_set.must || must_rules_hit,
                    });
                }
                bad_rule = false;
            }
        }

        Err(RoutingError::InvalidFixture("no match set hit".to_owned()))
    }
}

impl MatchSet {
    fn from_fixture_value(value: &Value) -> Result<Self, RoutingError> {
        let match_type = MatchType::try_from(required_str(value, "type")?)?;
        Ok(Self {
            match_type,
            outbound: outbound_from_fixture(required_str(value, "outbound")?)?,
            not: value.get("not").and_then(Value::as_bool).unwrap_or(false),
            mark: value.get("mark").and_then(Value::as_u64).unwrap_or(0) as u32,
            must: value.get("must").and_then(Value::as_bool).unwrap_or(false),
            lpm_index: value
                .get("lpm_index")
                .and_then(Value::as_u64)
                .map(|value| value as u32),
            port_start: value
                .get("port_start")
                .and_then(Value::as_u64)
                .map(|value| value as u16),
            port_end: value
                .get("port_end")
                .and_then(Value::as_u64)
                .map(|value| value as u16),
            value_u8: optional_match_u8_value(value)?,
            process_name: value
                .get("process_name")
                .and_then(Value::as_str)
                .map(process_name_bytes),
        })
    }

    fn matches(
        &self,
        index: usize,
        query: &Query,
        domain_bitmap: &[u32],
        lpm_sets: &BTreeMap<u32, Vec<IpPrefix>>,
    ) -> bool {
        match self.match_type {
            MatchType::DomainSet => bitmap_has(domain_bitmap, index),
            MatchType::IpSet => self
                .lpm_index
                .and_then(|index| lpm_sets.get(&index))
                .map(|prefixes| prefixes.iter().any(|prefix| prefix.contains(query.dest)))
                .unwrap_or(false),
            MatchType::SourceIpSet => self
                .lpm_index
                .and_then(|index| lpm_sets.get(&index))
                .zip(query.source)
                .map(|(prefixes, source)| prefixes.iter().any(|prefix| prefix.contains(source)))
                .unwrap_or(false),
            MatchType::Mac => self
                .lpm_index
                .and_then(|index| lpm_sets.get(&index))
                .zip(query.mac_addr())
                .map(|(prefixes, mac)| prefixes.iter().any(|prefix| prefix.contains(mac)))
                .unwrap_or(false),
            MatchType::Port => {
                let start = self.port_start.unwrap_or(0);
                let end = self.port_end.unwrap_or(start);
                (start..=end).contains(&query.dest_port)
            }
            MatchType::SourcePort => {
                let Some(source_port) = query.source_port else {
                    return false;
                };
                let start = self.port_start.unwrap_or(0);
                let end = self.port_end.unwrap_or(start);
                (start..=end).contains(&source_port)
            }
            MatchType::L4Proto => query
                .l4proto
                .zip(self.value_u8)
                .map(|(got, want)| (got & want) != 0)
                .unwrap_or(false),
            MatchType::IpVersion => self
                .value_u8
                .map(|want| (query.effective_ip_version() & want) != 0)
                .unwrap_or(false),
            MatchType::ProcessName => self
                .process_name
                .zip(query.process_name_bytes())
                .map(|(want, got)| got[0] != 0 && want == got)
                .unwrap_or(false),
            MatchType::Dscp => query
                .dscp
                .zip(self.value_u8)
                .map(|(got, want)| got == want)
                .unwrap_or(false),
            MatchType::Fallback => true,
        }
    }
}

impl TryFrom<&str> for MatchType {
    type Error = RoutingError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "domain_set" => Ok(Self::DomainSet),
            "ip_set" => Ok(Self::IpSet),
            "source_ip_set" => Ok(Self::SourceIpSet),
            "port" => Ok(Self::Port),
            "source_port" => Ok(Self::SourcePort),
            "l4proto" => Ok(Self::L4Proto),
            "ipversion" => Ok(Self::IpVersion),
            "mac" => Ok(Self::Mac),
            "process_name" => Ok(Self::ProcessName),
            "dscp" => Ok(Self::Dscp),
            "fallback" => Ok(Self::Fallback),
            _ => Err(RoutingError::UnknownMatchType(value.to_owned())),
        }
    }
}

fn outbound_from_fixture(value: &str) -> Result<OutboundIndex, RoutingError> {
    match value {
        "direct" => Ok(OutboundIndex::DIRECT),
        "block" => Ok(OutboundIndex::BLOCK),
        "must_rules" => Ok(OutboundIndex::MUST_RULES),
        "logical_or" => Ok(OutboundIndex::LOGICAL_OR),
        "logical_and" => Ok(OutboundIndex::LOGICAL_AND),
        "<OR>" => Ok(OutboundIndex::LOGICAL_OR),
        "<AND>" => Ok(OutboundIndex::LOGICAL_AND),
        value if value.starts_with("index:") => value[6..]
            .parse::<u8>()
            .map(OutboundIndex)
            .map_err(|_| RoutingError::UnknownOutbound(value.to_owned())),
        value if value.starts_with("user:") => value[5..]
            .parse::<u8>()
            .map(OutboundIndex)
            .map_err(|_| RoutingError::UnknownOutbound(value.to_owned())),
        _ => Err(RoutingError::UnknownOutbound(value.to_owned())),
    }
}

fn optional_match_u8_value(value: &Value) -> Result<Option<u8>, RoutingError> {
    if let Some(value) = value.get("value").and_then(Value::as_u64) {
        return Ok(Some(value as u8));
    }
    if let Some(value) = value.get("l4proto").and_then(Value::as_str) {
        return parse_l4proto(value).map(Some);
    }
    if let Some(value) = value.get("ipversion").and_then(Value::as_str) {
        return parse_ip_version(value).map(Some);
    }
    if let Some(value) = value.get("dscp").and_then(Value::as_u64) {
        return Ok(Some(value as u8));
    }
    Ok(None)
}

fn parse_l4proto(value: &str) -> Result<u8, RoutingError> {
    let mut out = 0_u8;
    for item in value.split('|') {
        match item {
            "tcp" => out |= L4_TCP,
            "udp" => out |= L4_UDP,
            _ => {
                return Err(RoutingError::InvalidFixture(format!(
                    "invalid l4proto: {value}"
                )));
            }
        }
    }
    Ok(out)
}

fn parse_ip_version(value: &str) -> Result<u8, RoutingError> {
    let mut out = 0_u8;
    for item in value.split('|') {
        match item {
            "4" => out |= IP_VERSION_4,
            "6" => out |= IP_VERSION_6,
            _ => {
                return Err(RoutingError::InvalidFixture(format!(
                    "invalid ipversion: {value}"
                )));
            }
        }
    }
    Ok(out)
}

fn process_name_bytes(value: &str) -> [u8; 16] {
    let mut out = [0_u8; 16];
    let raw = value.as_bytes();
    let copy_len = raw.len().min(out.len());
    out[..copy_len].copy_from_slice(&raw[..copy_len]);
    out
}

fn bitmap_has(bitmap: &[u32], bit: usize) -> bool {
    bitmap
        .get(bit / 32)
        .map(|word| ((word >> (bit % 32)) & 1) != 0)
        .unwrap_or(false)
}

fn required_str<'a>(value: &'a Value, key: &str) -> Result<&'a str, RoutingError> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| RoutingError::InvalidFixture(format!("{key} must be string")))
}

fn required_u64(value: &Value, key: &str) -> Result<u64, RoutingError> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| RoutingError::InvalidFixture(format!("{key} must be number")))
}

fn required_array<'a>(value: &'a Value, key: &str) -> Result<&'a Vec<Value>, RoutingError> {
    value
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| RoutingError::InvalidFixture(format!("{key} must be array")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn userspace_matcher_matches_golden_fixture() {
        let fixture = dae_golden::load_json("routing/userspace/basic_matcher.json").unwrap();

        for case in fixture["cases"].as_array().unwrap() {
            let matcher = RoutingMatcher::from_fixture_value(&case["matcher"]).unwrap();
            for query in case["queries"].as_array().unwrap() {
                let parsed = Query {
                    dest: IpAddr::from_str(query["dest"].as_str().unwrap()).unwrap(),
                    dest_port: query["dest_port"].as_u64().unwrap() as u16,
                    domain: query["domain"].as_str().unwrap().to_owned(),
                    ..Query::default()
                };
                let outbound = matcher.match_query(&parsed).unwrap();

                assert_eq!(outbound.to_string(), query["want"].as_str().unwrap());
            }
        }
    }

    #[test]
    fn userspace_matcher_covers_full_go_function_matrix() {
        let matcher = RoutingMatcher::from_fixture_value(&serde_json::json!({
            "domain_sets": [
                {"bit": 9, "key": "suffix", "patterns": ["example.com"]}
            ],
            "lpm_sets": [
                {"index": 0, "prefixes": ["203.0.113.0/24"]},
                {"index": 1, "prefixes": ["198.51.100.0/24"]},
                {"index": 2, "prefixes": ["::aabb:ccdd:ee00/128"]}
            ],
            "matches": [
                {"type": "source_ip_set", "lpm_index": 1, "outbound": "logical_or"},
                {"type": "source_port", "port_start": 40000, "port_end": 50000, "outbound": "logical_and"},
                {"type": "ip_set", "lpm_index": 0, "outbound": "logical_and"},
                {"type": "port", "port_start": 443, "port_end": 443, "outbound": "logical_and"},
                {"type": "l4proto", "l4proto": "tcp", "outbound": "logical_and"},
                {"type": "ipversion", "ipversion": "4", "outbound": "logical_and"},
                {"type": "mac", "lpm_index": 2, "outbound": "logical_and"},
                {"type": "process_name", "process_name": "curl", "outbound": "logical_and"},
                {"type": "dscp", "dscp": 46, "outbound": "must_rules"},
                {"type": "domain_set", "outbound": "direct", "mark": 1234},
                {"type": "fallback", "outbound": "block"}
            ]
        }))
        .unwrap();
        let outcome = matcher
            .match_query_detail(&Query {
                source: Some(IpAddr::from_str("198.51.100.42").unwrap()),
                dest: IpAddr::from_str("203.0.113.42").unwrap(),
                source_port: Some(45000),
                dest_port: 443,
                l4proto: Some(L4_TCP),
                domain: "www.example.com".to_owned(),
                process_name: Some("curl".to_owned()),
                dscp: Some(46),
                mac: Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x00]),
                ..Query::default()
            })
            .unwrap();

        assert_eq!(outcome.outbound, OutboundIndex::DIRECT);
        assert_eq!(outcome.mark, 1234);
        assert!(outcome.must);

        let fallback = matcher
            .match_query(&Query {
                source: Some(IpAddr::from_str("198.51.100.42").unwrap()),
                dest: IpAddr::from_str("203.0.113.42").unwrap(),
                source_port: Some(45000),
                dest_port: 443,
                l4proto: Some(L4_UDP),
                domain: "www.invalid.test".to_owned(),
                process_name: Some("curl".to_owned()),
                dscp: Some(46),
                mac: Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x00]),
                ..Query::default()
            })
            .unwrap();
        assert_eq!(fallback, OutboundIndex::BLOCK);
    }
}
