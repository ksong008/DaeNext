use std::collections::BTreeMap;
use std::net::IpAddr;

use dae_core_types::OutboundIndex;
use serde_json::Value;

use crate::RoutingError;
use crate::domain::{DomainKey, DomainMatcher};
use crate::prefix::IpPrefix;

#[derive(Clone, Debug)]
pub struct Query {
    pub dest: IpAddr,
    pub dest_port: u16,
    pub domain: String,
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
    lpm_index: Option<u32>,
    port_start: Option<u16>,
    port_end: Option<u16>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MatchType {
    DomainSet,
    IpSet,
    Port,
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
        let domain_bitmap = if query.domain.is_empty() {
            Vec::new()
        } else {
            self.domain_matcher.match_domain_bitmap(&query.domain)
        };

        let mut good_subrule = false;
        let mut bad_rule = false;
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
                    return Ok(outbound);
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
            MatchType::Port => {
                let start = self.port_start.unwrap_or(0);
                let end = self.port_end.unwrap_or(start);
                (start..=end).contains(&query.dest_port)
            }
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
            "port" => Ok(Self::Port),
            "fallback" => Ok(Self::Fallback),
            _ => Err(RoutingError::UnknownMatchType(value.to_owned())),
        }
    }
}

fn outbound_from_fixture(value: &str) -> Result<OutboundIndex, RoutingError> {
    match value {
        "direct" => Ok(OutboundIndex::DIRECT),
        "block" => Ok(OutboundIndex::BLOCK),
        "logical_or" => Ok(OutboundIndex::LOGICAL_OR),
        "logical_and" => Ok(OutboundIndex::LOGICAL_AND),
        _ => Err(RoutingError::UnknownOutbound(value.to_owned())),
    }
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
                };
                let outbound = matcher.match_query(&parsed).unwrap();

                assert_eq!(outbound.to_string(), query["want"].as_str().unwrap());
            }
        }
    }
}
