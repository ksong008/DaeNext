use std::fmt;
use std::mem::size_of;
use std::net::{IpAddr, Ipv6Addr};

use dae_core_types::OutboundIndex;
use dae_ebpf_support::{
    BpfLpmKey, BpfMatchSet, LpmMapBuildSpec, LpmMapEntry, MAX_MATCH_SET_LEN, RoutingMapEntry,
};
use dae_routing::IpPrefix;

pub const MAX_LPM_ARRAY_ENTRIES: usize = MAX_MATCH_SET_LEN + 8;
pub const DEFAULT_LPM_MAX_ENTRIES: u32 = 2_048_000;
pub const BPF_F_NO_PREALLOC: u32 = 1;

const MATCH_TYPE_DOMAIN_SET: u8 = 0;
const MATCH_TYPE_IP_SET: u8 = 1;
const MATCH_TYPE_SOURCE_IP_SET: u8 = 2;
const MATCH_TYPE_PORT: u8 = 3;
const MATCH_TYPE_SOURCE_PORT: u8 = 4;
const MATCH_TYPE_L4_PROTO: u8 = 5;
const MATCH_TYPE_IP_VERSION: u8 = 6;
const MATCH_TYPE_MAC: u8 = 7;
const MATCH_TYPE_PROCESS_NAME: u8 = 8;
const MATCH_TYPE_DSCP: u8 = 9;
const MATCH_TYPE_FALLBACK: u8 = 10;
const LPM_HIT_VALUE: u32 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LpmMapTemplate {
    pub flags: u32,
    pub max_entries: u32,
    pub key_size: u32,
    pub value_size: u32,
}

impl LpmMapTemplate {
    pub const fn dae_unused_lpm_type() -> Self {
        Self {
            flags: BPF_F_NO_PREALLOC,
            max_entries: DEFAULT_LPM_MAX_ENTRIES,
            key_size: size_of::<BpfLpmKey>() as u32,
            value_size: size_of::<u32>() as u32,
        }
    }

    pub fn validate(self) -> Result<(), RoutingNativePlanError> {
        if self.key_size != size_of::<BpfLpmKey>() as u32 {
            return Err(RoutingNativePlanError::InvalidLpmTemplate {
                field: "key_size",
                got: self.key_size,
                want: size_of::<BpfLpmKey>() as u32,
            });
        }
        if self.value_size != size_of::<u32>() as u32 {
            return Err(RoutingNativePlanError::InvalidLpmTemplate {
                field: "value_size",
                got: self.value_size,
                want: size_of::<u32>() as u32,
            });
        }
        if self.max_entries == 0 {
            return Err(RoutingNativePlanError::InvalidLpmTemplate {
                field: "max_entries",
                got: 0,
                want: 1,
            });
        }
        Ok(())
    }
}

impl Default for LpmMapTemplate {
    fn default() -> Self {
        Self::dae_unused_lpm_type()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RoutingNativeMatch {
    DomainSet,
    IpSet(Vec<IpPrefix>),
    SourceIpSet(Vec<IpPrefix>),
    Port(Vec<(u16, u16)>),
    SourcePort(Vec<(u16, u16)>),
    L4Proto(u8),
    IpVersion(u8),
    Mac(Vec<[u8; 6]>),
    ProcessName(Vec<[u8; 16]>),
    Dscp(Vec<u8>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoutingNativeRule {
    pub matcher: RoutingNativeMatch,
    pub outbound: OutboundIndex,
    pub not: bool,
    pub mark: u32,
    pub must: bool,
}

impl RoutingNativeRule {
    pub fn new(matcher: RoutingNativeMatch, outbound: OutboundIndex) -> Self {
        Self {
            matcher,
            outbound,
            not: false,
            mark: 0,
            must: false,
        }
    }

    pub fn with_flags(mut self, not: bool, mark: u32, must: bool) -> Self {
        self.not = not;
        self.mark = mark;
        self.must = must;
        self
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RoutingNativeFallback {
    pub outbound: OutboundIndex,
    pub mark: u32,
    pub must: bool,
}

impl RoutingNativeFallback {
    pub const fn new(outbound: OutboundIndex) -> Self {
        Self {
            outbound,
            mark: 0,
            must: false,
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RoutingNativeBuildPlan {
    pub routing_entries: Vec<RoutingMapEntry>,
    pub lpm_maps: Vec<LpmMapBuildSpec>,
}

impl RoutingNativeBuildPlan {
    pub fn validate(&self) -> Result<(), RoutingNativePlanError> {
        if self.routing_entries.is_empty() {
            return Err(RoutingNativePlanError::MissingFallback);
        }
        if self.routing_entries.len() > MAX_MATCH_SET_LEN {
            return Err(RoutingNativePlanError::RoutingMapOverflow {
                got: self.routing_entries.len(),
                max: MAX_MATCH_SET_LEN,
            });
        }
        if self.lpm_maps.len() > MAX_LPM_ARRAY_ENTRIES {
            return Err(RoutingNativePlanError::LpmArrayOverflow {
                got: self.lpm_maps.len(),
                max: MAX_LPM_ARRAY_ENTRIES,
            });
        }
        for (position, entry) in self.routing_entries.iter().enumerate() {
            if entry.index as usize != position {
                return Err(RoutingNativePlanError::NonContiguousRoutingIndex {
                    position,
                    index: entry.index,
                });
            }
        }
        let Some(last) = self.routing_entries.last() else {
            return Err(RoutingNativePlanError::MissingFallback);
        };
        if last.value.kind != MATCH_TYPE_FALLBACK {
            return Err(RoutingNativePlanError::FallbackNotLast);
        }
        for spec in &self.lpm_maps {
            if spec.index as usize >= MAX_LPM_ARRAY_ENTRIES {
                return Err(RoutingNativePlanError::LpmArrayOverflow {
                    got: spec.index as usize + 1,
                    max: MAX_LPM_ARRAY_ENTRIES,
                });
            }
        }
        Ok(())
    }

    pub fn checksum(&self) -> u64 {
        let mut out = self.routing_entries.len() as u64 ^ ((self.lpm_maps.len() as u64) << 32);
        for entry in &self.routing_entries {
            out ^= entry.index as u64;
            out = out.rotate_left(5) ^ u64::from(entry.value.kind);
            out = out.rotate_left(5) ^ u64::from(entry.value.outbound);
            out = out.rotate_left(5) ^ u64::from(entry.value.not);
            out = out.rotate_left(5) ^ u64::from(entry.value.must);
            out = out.rotate_left(5) ^ u64::from(entry.value.mark);
            for chunk in entry.value.value.chunks_exact(4) {
                out = out.rotate_left(5)
                    ^ u64::from(u32::from_ne_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
            }
        }
        for spec in &self.lpm_maps {
            out = out.rotate_left(7) ^ u64::from(spec.index);
            out = out.rotate_left(7) ^ u64::from(spec.flags);
            out = out.rotate_left(7) ^ u64::from(spec.max_entries);
            for entry in &spec.entries {
                out = out.rotate_left(7) ^ u64::from(entry.key.prefix_len);
                out = out.rotate_left(7) ^ u64::from(entry.value);
                for word in entry.key.data {
                    out = out.rotate_left(7) ^ u64::from(word);
                }
            }
        }
        out
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RoutingNativePlanError {
    EmptyExpandedSet(&'static str),
    InvalidLpmTemplate {
        field: &'static str,
        got: u32,
        want: u32,
    },
    LpmArrayOverflow {
        got: usize,
        max: usize,
    },
    RoutingMapOverflow {
        got: usize,
        max: usize,
    },
    NonContiguousRoutingIndex {
        position: usize,
        index: u32,
    },
    MissingFallback,
    FallbackNotLast,
}

impl fmt::Display for RoutingNativePlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyExpandedSet(name) => write!(f, "empty routing native expanded set: {name}"),
            Self::InvalidLpmTemplate { field, got, want } => {
                write!(f, "invalid LPM template {field}: got {got}, want {want}")
            }
            Self::LpmArrayOverflow { got, max } => {
                write!(f, "routing native LPM array overflow: {got} > {max}")
            }
            Self::RoutingMapOverflow { got, max } => {
                write!(f, "routing native map overflow: {got} > {max}")
            }
            Self::NonContiguousRoutingIndex { position, index } => {
                write!(
                    f,
                    "non-contiguous routing native index at {position}: got {index}"
                )
            }
            Self::MissingFallback => f.write_str("routing native plan is missing fallback"),
            Self::FallbackNotLast => f.write_str("routing native fallback rule must be last"),
        }
    }
}

impl std::error::Error for RoutingNativePlanError {}

pub fn build_routing_native_plan(
    rules: &[RoutingNativeRule],
    fallback: RoutingNativeFallback,
    lpm_template: LpmMapTemplate,
) -> Result<RoutingNativeBuildPlan, RoutingNativePlanError> {
    lpm_template.validate()?;

    let mut plan = RoutingNativeBuildPlan {
        routing_entries: Vec::with_capacity(expanded_routing_entry_count(rules) + 1),
        lpm_maps: Vec::with_capacity(lpm_rule_count(rules)),
    };

    for rule in rules {
        append_rule(&mut plan, rule, lpm_template)?;
    }
    append_match_set(
        &mut plan.routing_entries,
        BpfMatchSet {
            kind: MATCH_TYPE_FALLBACK,
            outbound: fallback.outbound.value(),
            mark: fallback.mark,
            must: u8::from(fallback.must),
            ..BpfMatchSet::default()
        },
    )?;
    plan.validate()?;
    Ok(plan)
}

fn expanded_routing_entry_count(rules: &[RoutingNativeRule]) -> usize {
    rules
        .iter()
        .map(|rule| match &rule.matcher {
            RoutingNativeMatch::Port(ranges) | RoutingNativeMatch::SourcePort(ranges) => {
                ranges.len()
            }
            RoutingNativeMatch::ProcessName(names) => names.len(),
            RoutingNativeMatch::Dscp(values) => values.len(),
            _ => 1,
        })
        .sum()
}

fn lpm_rule_count(rules: &[RoutingNativeRule]) -> usize {
    rules
        .iter()
        .filter(|rule| {
            matches!(
                &rule.matcher,
                RoutingNativeMatch::IpSet(_)
                    | RoutingNativeMatch::SourceIpSet(_)
                    | RoutingNativeMatch::Mac(_)
            )
        })
        .count()
}

pub fn ip_prefix_to_bpf_lpm_key(prefix: &IpPrefix) -> BpfLpmKey {
    match prefix.addr() {
        IpAddr::V4(addr) => {
            let mapped = addr.to_ipv6_mapped();
            BpfLpmKey {
                prefix_len: u32::from(prefix.bits()) + 96,
                data: ipv6_to_native_words(mapped),
            }
        }
        IpAddr::V6(addr) => BpfLpmKey {
            prefix_len: u32::from(prefix.bits()),
            data: ipv6_to_native_words(addr),
        },
    }
}

fn append_rule(
    plan: &mut RoutingNativeBuildPlan,
    rule: &RoutingNativeRule,
    lpm_template: LpmMapTemplate,
) -> Result<(), RoutingNativePlanError> {
    match &rule.matcher {
        RoutingNativeMatch::DomainSet => append_match_set(
            &mut plan.routing_entries,
            base_match_set(MATCH_TYPE_DOMAIN_SET, rule),
        ),
        RoutingNativeMatch::IpSet(prefixes) => {
            append_lpm_rule(plan, MATCH_TYPE_IP_SET, prefixes, rule, lpm_template)
        }
        RoutingNativeMatch::SourceIpSet(prefixes) => {
            append_lpm_rule(plan, MATCH_TYPE_SOURCE_IP_SET, prefixes, rule, lpm_template)
        }
        RoutingNativeMatch::Mac(mac_addrs) => {
            if mac_addrs.is_empty() {
                return Err(RoutingNativePlanError::EmptyExpandedSet("mac"));
            }
            let lpm_index = plan.lpm_maps.len() as u32;
            let entries = mac_addrs
                .iter()
                .map(|mac| LpmMapEntry {
                    key: mac_to_bpf_lpm_key(*mac),
                    value: LPM_HIT_VALUE,
                })
                .collect::<Vec<_>>();
            plan.lpm_maps
                .push(lpm_spec(lpm_index, lpm_template, entries));
            let mut set = base_match_set(MATCH_TYPE_MAC, rule);
            set.value[..4].copy_from_slice(&lpm_index.to_le_bytes());
            append_match_set(&mut plan.routing_entries, set)
        }
        RoutingNativeMatch::Port(ranges) => {
            append_range_rules(&mut plan.routing_entries, MATCH_TYPE_PORT, ranges, rule)
        }
        RoutingNativeMatch::SourcePort(ranges) => append_range_rules(
            &mut plan.routing_entries,
            MATCH_TYPE_SOURCE_PORT,
            ranges,
            rule,
        ),
        RoutingNativeMatch::L4Proto(mask) => {
            let mut set = base_match_set(MATCH_TYPE_L4_PROTO, rule);
            set.value[0] = *mask;
            append_match_set(&mut plan.routing_entries, set)
        }
        RoutingNativeMatch::IpVersion(mask) => {
            let mut set = base_match_set(MATCH_TYPE_IP_VERSION, rule);
            set.value[0] = *mask;
            append_match_set(&mut plan.routing_entries, set)
        }
        RoutingNativeMatch::ProcessName(names) => {
            if names.is_empty() {
                return Err(RoutingNativePlanError::EmptyExpandedSet("pname"));
            }
            for (index, name) in names.iter().enumerate() {
                let mut set = base_match_set(MATCH_TYPE_PROCESS_NAME, rule);
                if index + 1 != names.len() {
                    set.outbound = OutboundIndex::LOGICAL_OR.value();
                }
                set.value.copy_from_slice(name);
                append_match_set(&mut plan.routing_entries, set)?;
            }
            Ok(())
        }
        RoutingNativeMatch::Dscp(values) => {
            if values.is_empty() {
                return Err(RoutingNativePlanError::EmptyExpandedSet("dscp"));
            }
            for (index, value) in values.iter().enumerate() {
                let mut set = base_match_set(MATCH_TYPE_DSCP, rule);
                if index + 1 != values.len() {
                    set.outbound = OutboundIndex::LOGICAL_OR.value();
                }
                set.value[0] = *value;
                append_match_set(&mut plan.routing_entries, set)?;
            }
            Ok(())
        }
    }
}

fn append_lpm_rule(
    plan: &mut RoutingNativeBuildPlan,
    kind: u8,
    prefixes: &[IpPrefix],
    rule: &RoutingNativeRule,
    lpm_template: LpmMapTemplate,
) -> Result<(), RoutingNativePlanError> {
    if prefixes.is_empty() {
        return Err(RoutingNativePlanError::EmptyExpandedSet("lpm"));
    }
    let lpm_index = plan.lpm_maps.len() as u32;
    let entries = prefixes
        .iter()
        .map(|prefix| LpmMapEntry {
            key: ip_prefix_to_bpf_lpm_key(prefix),
            value: LPM_HIT_VALUE,
        })
        .collect::<Vec<_>>();
    plan.lpm_maps
        .push(lpm_spec(lpm_index, lpm_template, entries));
    let mut set = base_match_set(kind, rule);
    set.value[..4].copy_from_slice(&lpm_index.to_le_bytes());
    append_match_set(&mut plan.routing_entries, set)
}

fn append_range_rules(
    entries: &mut Vec<RoutingMapEntry>,
    kind: u8,
    ranges: &[(u16, u16)],
    rule: &RoutingNativeRule,
) -> Result<(), RoutingNativePlanError> {
    if ranges.is_empty() {
        return Err(RoutingNativePlanError::EmptyExpandedSet("port"));
    }
    for (index, (start, end)) in ranges.iter().copied().enumerate() {
        let mut set = base_match_set(kind, rule);
        if index + 1 != ranges.len() {
            set.outbound = OutboundIndex::LOGICAL_OR.value();
        }
        set.value[..2].copy_from_slice(&start.to_le_bytes());
        set.value[2..4].copy_from_slice(&end.to_le_bytes());
        append_match_set(entries, set)?;
    }
    Ok(())
}

fn append_match_set(
    entries: &mut Vec<RoutingMapEntry>,
    value: BpfMatchSet,
) -> Result<(), RoutingNativePlanError> {
    if entries.len() >= MAX_MATCH_SET_LEN {
        return Err(RoutingNativePlanError::RoutingMapOverflow {
            got: entries.len() + 1,
            max: MAX_MATCH_SET_LEN,
        });
    }
    entries.push(RoutingMapEntry {
        index: entries.len() as u32,
        value,
    });
    Ok(())
}

fn base_match_set(kind: u8, rule: &RoutingNativeRule) -> BpfMatchSet {
    BpfMatchSet {
        kind,
        not: u8::from(rule.not),
        outbound: rule.outbound.value(),
        must: u8::from(rule.must),
        mark: rule.mark,
        ..BpfMatchSet::default()
    }
}

fn lpm_spec(index: u32, template: LpmMapTemplate, entries: Vec<LpmMapEntry>) -> LpmMapBuildSpec {
    LpmMapBuildSpec {
        index,
        flags: template.flags,
        max_entries: template.max_entries,
        key_size: template.key_size,
        value_size: template.value_size,
        entries,
    }
}

fn mac_to_bpf_lpm_key(mac: [u8; 6]) -> BpfLpmKey {
    let mut octets = [0_u8; 16];
    octets[10..].copy_from_slice(&mac);
    BpfLpmKey {
        prefix_len: 128,
        data: ipv6_to_native_words(Ipv6Addr::from(octets)),
    }
}

fn ipv6_to_native_words(addr: Ipv6Addr) -> [u32; 4] {
    let octets = addr.octets();
    [
        u32::from_ne_bytes([octets[0], octets[1], octets[2], octets[3]]),
        u32::from_ne_bytes([octets[4], octets[5], octets[6], octets[7]]),
        u32::from_ne_bytes([octets[8], octets[9], octets[10], octets[11]]),
        u32::from_ne_bytes([octets[12], octets[13], octets[14], octets[15]]),
    ]
}
