use std::net::IpAddr;

pub use dae_core_types::{DnsRequestOutboundIndex, DnsResponseOutboundIndex};
use dae_routing::{DomainKey, DomainMatcher, IpPrefix, SharedDomainSet};
use serde_json::Value;

use crate::error::DnsError;

const MATCH_TYPE_DOMAIN_SET: &str = "domain_set";
const MATCH_TYPE_IP_SET: &str = "ip_set";
const MATCH_TYPE_QTYPE: &str = "qtype";
const MATCH_TYPE_UPSTREAM: &str = "upstream";
const MATCH_TYPE_FALLBACK: &str = "fallback";

#[derive(Clone, Debug)]
pub struct RequestMatcher {
    domain_matcher: DomainMatcher,
    matches: Vec<RequestMatchSet>,
}

#[derive(Clone, Debug)]
pub struct DnsDomainSet {
    pub bit: usize,
    pub patterns: SharedDomainSet,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DnsRequestMatchSpec {
    pub kind: DnsRequestMatchKind,
    pub value: u16,
    pub not: bool,
    pub upstream: DnsRequestOutboundIndex,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsRequestMatchKind {
    DomainSet,
    QType,
    Fallback,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DnsResponseMatchSpec {
    pub kind: DnsResponseMatchKind,
    pub value: u16,
    pub not: bool,
    pub upstream: DnsResponseOutboundIndex,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsResponseMatchKind {
    DomainSet,
    IpSet,
    QType,
    Upstream,
    Fallback,
}

#[derive(Clone, Debug)]
struct RequestMatchSet {
    match_type: DnsMatchType,
    value: u16,
    not: bool,
    upstream: DnsRequestOutboundIndex,
}

#[derive(Clone, Debug)]
pub struct ResponseMatcher {
    domain_matcher: DomainMatcher,
    lpm_sets: Vec<Vec<IpPrefix>>,
    matches: Vec<ResponseMatchSet>,
}

#[derive(Clone, Debug)]
struct ResponseMatchSet {
    match_type: DnsMatchType,
    value: u16,
    not: bool,
    upstream: DnsResponseOutboundIndex,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DnsMatchType {
    DomainSet,
    IpSet,
    QType,
    Upstream,
    Fallback,
}

impl RequestMatcher {
    pub fn from_shared_typed_sets(
        domain_sets: Vec<DnsDomainSet>,
        matches: Vec<DnsRequestMatchSpec>,
    ) -> Result<Self, DnsError> {
        if matches
            .last()
            .map(|set| set.kind != DnsRequestMatchKind::Fallback)
            .unwrap_or(true)
        {
            return Err(DnsError::Resolve(
                "fallback rule MUST be the last".to_owned(),
            ));
        }
        let max_domain_bit = domain_sets.iter().map(|set| set.bit + 1).max().unwrap_or(0);
        let mut domain_matcher = DomainMatcher::new(max_domain_bit.max(matches.len()).max(1));
        for set in domain_sets {
            domain_matcher.add_shared_set(set.bit, set.patterns);
        }
        let matches = matches
            .into_iter()
            .map(|set| RequestMatchSet {
                match_type: match set.kind {
                    DnsRequestMatchKind::DomainSet => DnsMatchType::DomainSet,
                    DnsRequestMatchKind::QType => DnsMatchType::QType,
                    DnsRequestMatchKind::Fallback => DnsMatchType::Fallback,
                },
                value: set.value,
                not: set.not,
                upstream: set.upstream,
            })
            .collect();
        Ok(Self {
            domain_matcher,
            matches,
        })
    }

    pub fn from_fixture_value(value: &Value) -> Result<Self, DnsError> {
        let matches = required_array(value, "matches")?
            .iter()
            .map(RequestMatchSet::from_fixture_value)
            .collect::<Result<Vec<_>, _>>()?;
        let domain_matcher = build_domain_matcher(value, matches.len())?;
        if matches
            .last()
            .map(|set| set.match_type != DnsMatchType::Fallback)
            .unwrap_or(true)
        {
            return Err(DnsError::Resolve(
                "fallback rule MUST be the last".to_owned(),
            ));
        }
        Ok(Self {
            domain_matcher,
            matches,
        })
    }

    pub fn match_request(
        &self,
        qname: &str,
        qtype: u16,
    ) -> Result<DnsRequestOutboundIndex, DnsError> {
        let domain_bitmap = if qname.is_empty() {
            Vec::new()
        } else {
            self.domain_matcher.match_domain_bitmap(qname)
        };

        let mut good_subrule = false;
        let mut bad_rule = false;
        for (index, match_set) in self.matches.iter().enumerate() {
            if !bad_rule && !good_subrule && match_set.matches(index, qtype, &domain_bitmap) {
                good_subrule = true;
            }

            let upstream = match_set.upstream;
            if upstream != DnsRequestOutboundIndex::LOGICAL_OR {
                if good_subrule == match_set.not {
                    bad_rule = true;
                }
                good_subrule = false;
            }

            if upstream.value() & DnsRequestOutboundIndex::LOGICAL_MASK.value()
                != DnsRequestOutboundIndex::LOGICAL_MASK.value()
            {
                if !bad_rule {
                    return Ok(upstream);
                }
                bad_rule = false;
            }
        }
        Err(DnsError::Resolve("no match set hit".to_owned()))
    }
}

impl RequestMatchSet {
    fn from_fixture_value(value: &Value) -> Result<Self, DnsError> {
        Ok(Self {
            match_type: dns_match_type(required_str(value, "type")?)?,
            value: optional_fixture_u16(value, "value")?.unwrap_or(0),
            not: value.get("not").and_then(Value::as_bool).unwrap_or(false),
            upstream: request_outbound_from_fixture(required_str(value, "upstream")?)?,
        })
    }

    fn matches(&self, index: usize, qtype: u16, domain_bitmap: &[u32]) -> bool {
        match self.match_type {
            DnsMatchType::DomainSet => bitmap_has(domain_bitmap, index),
            DnsMatchType::QType => qtype == self.value,
            DnsMatchType::Fallback => true,
            DnsMatchType::IpSet | DnsMatchType::Upstream => false,
        }
    }
}

impl ResponseMatcher {
    pub fn from_shared_typed_sets(
        domain_sets: Vec<DnsDomainSet>,
        lpm_sets: Vec<Vec<IpPrefix>>,
        matches: Vec<DnsResponseMatchSpec>,
    ) -> Result<Self, DnsError> {
        if matches
            .last()
            .map(|set| set.kind != DnsResponseMatchKind::Fallback)
            .unwrap_or(true)
        {
            return Err(DnsError::Resolve(
                "fallback rule MUST be the last".to_owned(),
            ));
        }
        let max_domain_bit = domain_sets.iter().map(|set| set.bit + 1).max().unwrap_or(0);
        let mut domain_matcher = DomainMatcher::new(max_domain_bit.max(matches.len()).max(1));
        for set in domain_sets {
            domain_matcher.add_shared_set(set.bit, set.patterns);
        }
        let matches = matches
            .into_iter()
            .map(|set| ResponseMatchSet {
                match_type: match set.kind {
                    DnsResponseMatchKind::DomainSet => DnsMatchType::DomainSet,
                    DnsResponseMatchKind::IpSet => DnsMatchType::IpSet,
                    DnsResponseMatchKind::QType => DnsMatchType::QType,
                    DnsResponseMatchKind::Upstream => DnsMatchType::Upstream,
                    DnsResponseMatchKind::Fallback => DnsMatchType::Fallback,
                },
                value: set.value,
                not: set.not,
                upstream: set.upstream,
            })
            .collect();
        Ok(Self {
            domain_matcher,
            lpm_sets,
            matches,
        })
    }

    pub fn from_fixture_value(value: &Value) -> Result<Self, DnsError> {
        let matches = required_array(value, "matches")?
            .iter()
            .map(ResponseMatchSet::from_fixture_value)
            .collect::<Result<Vec<_>, _>>()?;
        let domain_matcher = build_domain_matcher(value, matches.len())?;
        let lpm_sets = value
            .get("lpm_sets")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .map(|set| {
                required_array(set, "prefixes")?
                    .iter()
                    .map(|value| {
                        let prefix = value
                            .as_str()
                            .ok_or_else(|| DnsError::Resolve("prefix must be string".to_owned()))?;
                        IpPrefix::parse(prefix).map_err(|err| DnsError::Resolve(err.to_string()))
                    })
                    .collect::<Result<Vec<_>, _>>()
            })
            .collect::<Result<Vec<_>, _>>()?;
        if matches
            .last()
            .map(|set| set.match_type != DnsMatchType::Fallback)
            .unwrap_or(true)
        {
            return Err(DnsError::Resolve(
                "fallback rule MUST be the last".to_owned(),
            ));
        }
        Ok(Self {
            domain_matcher,
            lpm_sets,
            matches,
        })
    }

    pub fn match_response(
        &self,
        qname: &str,
        qtype: u16,
        ips: &[IpAddr],
        upstream: DnsRequestOutboundIndex,
    ) -> Result<DnsResponseOutboundIndex, DnsError> {
        if qname.is_empty() {
            return Err(DnsError::Resolve("qName cannot be empty".to_owned()));
        }
        let domain_bitmap = self.domain_matcher.match_domain_bitmap(qname);
        let mut good_subrule = false;
        let mut bad_rule = false;
        for (index, match_set) in self.matches.iter().enumerate() {
            if !bad_rule
                && !good_subrule
                && match_set.matches(index, qtype, ips, upstream, &domain_bitmap, &self.lpm_sets)
            {
                good_subrule = true;
            }

            let upstream = match_set.upstream;
            if upstream != DnsResponseOutboundIndex::LOGICAL_OR {
                if good_subrule == match_set.not {
                    bad_rule = true;
                }
                good_subrule = false;
            }

            if upstream.value() & DnsResponseOutboundIndex::LOGICAL_MASK.value()
                != DnsResponseOutboundIndex::LOGICAL_MASK.value()
            {
                if !bad_rule {
                    return Ok(upstream);
                }
                bad_rule = false;
            }
        }
        Err(DnsError::Resolve("no match set hit".to_owned()))
    }
}

impl ResponseMatchSet {
    fn from_fixture_value(value: &Value) -> Result<Self, DnsError> {
        let match_type = dns_match_type(required_str(value, "type")?)?;
        let value_u16 = value
            .get("value")
            .and_then(Value::as_u64)
            .or_else(|| value.get("lpm_index").and_then(Value::as_u64))
            .or_else(|| value.get("qtype").and_then(Value::as_u64))
            .map(|value| checked_fixture_integer(value, "match value"))
            .transpose()?
            .unwrap_or(0);
        Ok(Self {
            match_type,
            value: value_u16,
            not: value.get("not").and_then(Value::as_bool).unwrap_or(false),
            upstream: response_outbound_from_fixture(required_str(value, "upstream")?)?,
        })
    }

    fn matches(
        &self,
        index: usize,
        qtype: u16,
        ips: &[IpAddr],
        upstream: DnsRequestOutboundIndex,
        domain_bitmap: &[u32],
        lpm_sets: &[Vec<IpPrefix>],
    ) -> bool {
        match self.match_type {
            DnsMatchType::DomainSet => bitmap_has(domain_bitmap, index),
            DnsMatchType::IpSet => lpm_sets
                .get(self.value as usize)
                .map(|prefixes| {
                    ips.iter()
                        .any(|ip| prefixes.iter().any(|prefix| prefix.contains(*ip)))
                })
                .unwrap_or(false),
            DnsMatchType::QType => qtype == self.value,
            DnsMatchType::Upstream => upstream.value() as u16 == self.value,
            DnsMatchType::Fallback => true,
        }
    }
}

fn build_domain_matcher(value: &Value, match_count: usize) -> Result<DomainMatcher, DnsError> {
    let mut max_domain_bit = 0_usize;
    let mut domain_sets = Vec::new();
    for set in value
        .get("domain_sets")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let bit = usize::try_from(required_u64(set, "bit")?)
            .map_err(|_| DnsError::Resolve("domain bit is out of range".to_owned()))?;
        let key = DomainKey::try_from(required_str(set, "key")?)
            .map_err(|err| DnsError::Resolve(err.to_string()))?;
        let patterns = required_array(set, "patterns")?
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| DnsError::Resolve("domain pattern must be string".to_owned()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        max_domain_bit = max_domain_bit.max(bit + 1);
        domain_sets.push((bit, key, patterns));
    }
    let mut matcher = DomainMatcher::new(max_domain_bit.max(match_count).max(1));
    for (bit, key, patterns) in domain_sets {
        matcher
            .add_set(bit, patterns, key)
            .map_err(|err| DnsError::Resolve(err.to_string()))?;
    }
    Ok(matcher)
}

fn dns_match_type(value: &str) -> Result<DnsMatchType, DnsError> {
    match value {
        MATCH_TYPE_DOMAIN_SET => Ok(DnsMatchType::DomainSet),
        MATCH_TYPE_IP_SET => Ok(DnsMatchType::IpSet),
        MATCH_TYPE_QTYPE => Ok(DnsMatchType::QType),
        MATCH_TYPE_UPSTREAM => Ok(DnsMatchType::Upstream),
        MATCH_TYPE_FALLBACK => Ok(DnsMatchType::Fallback),
        _ => Err(DnsError::Resolve(format!(
            "unknown dns match type: {value}"
        ))),
    }
}

fn request_outbound_from_fixture(value: &str) -> Result<DnsRequestOutboundIndex, DnsError> {
    match value {
        "reject" => Ok(DnsRequestOutboundIndex::REJECT),
        "asis" => Ok(DnsRequestOutboundIndex::ASIS),
        "logical_or" | "<OR>" => Ok(DnsRequestOutboundIndex::LOGICAL_OR),
        "logical_and" | "<AND>" => Ok(DnsRequestOutboundIndex::LOGICAL_AND),
        value if value.starts_with("index:") => parse_request_user_defined(&value[6..], value),
        value if value.starts_with("upstream:") => parse_request_user_defined(&value[9..], value),
        _ => Err(DnsError::Resolve(format!(
            "unknown request outbound: {value}"
        ))),
    }
}

fn response_outbound_from_fixture(value: &str) -> Result<DnsResponseOutboundIndex, DnsError> {
    match value {
        "accept" => Ok(DnsResponseOutboundIndex::ACCEPT),
        "reject" => Ok(DnsResponseOutboundIndex::REJECT),
        "logical_or" | "<OR>" => Ok(DnsResponseOutboundIndex::LOGICAL_OR),
        "logical_and" | "<AND>" => Ok(DnsResponseOutboundIndex::LOGICAL_AND),
        value if value.starts_with("index:") => parse_response_user_defined(&value[6..], value),
        value if value.starts_with("upstream:") => parse_response_user_defined(&value[9..], value),
        _ => Err(DnsError::Resolve(format!(
            "unknown response outbound: {value}"
        ))),
    }
}

fn parse_request_user_defined(
    raw_index: &str,
    original: &str,
) -> Result<DnsRequestOutboundIndex, DnsError> {
    raw_index
        .parse::<usize>()
        .ok()
        .and_then(|index| DnsRequestOutboundIndex::try_from(index).ok())
        .ok_or_else(|| DnsError::Resolve(format!("unknown request outbound: {original}")))
}

fn parse_response_user_defined(
    raw_index: &str,
    original: &str,
) -> Result<DnsResponseOutboundIndex, DnsError> {
    raw_index
        .parse::<usize>()
        .ok()
        .and_then(|index| DnsResponseOutboundIndex::try_from(index).ok())
        .ok_or_else(|| DnsError::Resolve(format!("unknown response outbound: {original}")))
}

fn bitmap_has(bitmap: &[u32], bit: usize) -> bool {
    bitmap
        .get(bit / 32)
        .map(|word| ((word >> (bit % 32)) & 1) != 0)
        .unwrap_or(false)
}

fn required_str<'a>(value: &'a Value, key: &str) -> Result<&'a str, DnsError> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| DnsError::Resolve(format!("{key} must be string")))
}

fn required_u64(value: &Value, key: &str) -> Result<u64, DnsError> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| DnsError::Resolve(format!("{key} must be number")))
}

fn optional_fixture_u16(value: &Value, key: &str) -> Result<Option<u16>, DnsError> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .map(|raw| checked_fixture_integer(raw, key))
        .transpose()
}

fn checked_fixture_integer<T>(value: u64, key: &str) -> Result<T, DnsError>
where
    T: TryFrom<u64>,
{
    T::try_from(value)
        .map_err(|_| DnsError::Resolve(format!("{key} value {value} is out of range")))
}

fn required_array<'a>(value: &'a Value, key: &str) -> Result<&'a Vec<Value>, DnsError> {
    value
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| DnsError::Resolve(format!("{key} must be array")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixture_user_defined_outbounds_reject_reserved_indices() {
        assert_eq!(
            request_outbound_from_fixture("index:251").unwrap(),
            DnsRequestOutboundIndex::USER_DEFINED_MAX
        );
        assert!(request_outbound_from_fixture("index:252").is_err());
        assert_eq!(
            response_outbound_from_fixture("upstream:251").unwrap(),
            DnsResponseOutboundIndex::USER_DEFINED_MAX
        );
        assert!(response_outbound_from_fixture("upstream:252").is_err());
        assert!(request_outbound_from_fixture("index:65536").is_err());
    }

    #[test]
    fn request_matcher_covers_qname_qtype_not_and_fallback() {
        let matcher = RequestMatcher::from_fixture_value(&serde_json::json!({
            "domain_sets": [
                {"bit": 0, "key": "suffix", "patterns": ["example.com"]}
            ],
            "matches": [
                {"type": "domain_set", "upstream": "logical_and"},
                {"type": "qtype", "value": 1, "upstream": "upstream:2"},
                {"type": "qtype", "value": 28, "not": true, "upstream": "reject"},
                {"type": "fallback", "upstream": "asis"}
            ]
        }))
        .unwrap();

        assert_eq!(
            matcher.match_request("www.example.com", 1).unwrap().value(),
            2
        );
        assert_eq!(
            matcher.match_request("www.example.com", 28).unwrap(),
            DnsRequestOutboundIndex::ASIS
        );
        assert_eq!(
            matcher.match_request("www.invalid.test", 16).unwrap(),
            DnsRequestOutboundIndex::REJECT
        );
    }

    #[test]
    fn response_matcher_covers_qname_qtype_ip_upstream_and_fallback() {
        let matcher = ResponseMatcher::from_fixture_value(&serde_json::json!({
            "domain_sets": [
                {"bit": 0, "key": "suffix", "patterns": ["example.com"]}
            ],
            "lpm_sets": [
                {"prefixes": ["203.0.113.0/24"]}
            ],
            "matches": [
                {"type": "domain_set", "upstream": "logical_and"},
                {"type": "qtype", "qtype": 1, "upstream": "logical_and"},
                {"type": "ip_set", "lpm_index": 0, "upstream": "logical_and"},
                {"type": "upstream", "value": 2, "upstream": "accept"},
                {"type": "fallback", "upstream": "reject"}
            ]
        }))
        .unwrap();

        assert_eq!(
            matcher
                .match_response(
                    "www.example.com",
                    1,
                    &["203.0.113.42".parse().unwrap()],
                    DnsRequestOutboundIndex(2),
                )
                .unwrap(),
            DnsResponseOutboundIndex::ACCEPT
        );
        assert_eq!(
            matcher
                .match_response(
                    "www.example.com",
                    1,
                    &["198.51.100.42".parse().unwrap()],
                    DnsRequestOutboundIndex(2),
                )
                .unwrap(),
            DnsResponseOutboundIndex::REJECT
        );
    }

    #[test]
    fn response_matcher_typed_sets_cover_qname_qtype_ip_upstream_and_fallback() {
        let patterns = SharedDomainSet::new(vec!["example.com".to_owned()], DomainKey::Suffix)
            .expect("domain set");
        let matcher = ResponseMatcher::from_shared_typed_sets(
            vec![DnsDomainSet { bit: 0, patterns }],
            vec![vec![IpPrefix::parse("203.0.113.0/24").unwrap()]],
            vec![
                DnsResponseMatchSpec {
                    kind: DnsResponseMatchKind::DomainSet,
                    value: 0,
                    not: false,
                    upstream: DnsResponseOutboundIndex::LOGICAL_AND,
                },
                DnsResponseMatchSpec {
                    kind: DnsResponseMatchKind::QType,
                    value: 1,
                    not: false,
                    upstream: DnsResponseOutboundIndex::LOGICAL_AND,
                },
                DnsResponseMatchSpec {
                    kind: DnsResponseMatchKind::IpSet,
                    value: 0,
                    not: false,
                    upstream: DnsResponseOutboundIndex::LOGICAL_AND,
                },
                DnsResponseMatchSpec {
                    kind: DnsResponseMatchKind::Upstream,
                    value: 2,
                    not: false,
                    upstream: DnsResponseOutboundIndex::ACCEPT,
                },
                DnsResponseMatchSpec {
                    kind: DnsResponseMatchKind::Fallback,
                    value: 0,
                    not: false,
                    upstream: DnsResponseOutboundIndex::REJECT,
                },
            ],
        )
        .unwrap();

        assert_eq!(
            matcher
                .match_response(
                    "www.example.com",
                    1,
                    &["203.0.113.42".parse().unwrap()],
                    DnsRequestOutboundIndex(2),
                )
                .unwrap(),
            DnsResponseOutboundIndex::ACCEPT
        );
        assert_eq!(
            matcher
                .match_response(
                    "www.example.com",
                    1,
                    &["198.51.100.42".parse().unwrap()],
                    DnsRequestOutboundIndex(2),
                )
                .unwrap(),
            DnsResponseOutboundIndex::REJECT
        );
    }
}
