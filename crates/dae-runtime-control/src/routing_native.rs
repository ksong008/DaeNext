use std::fmt;
use std::mem::size_of;
use std::net::IpAddr;

use dae_core_types::OutboundIndex;
use dae_ebpf_support::{
    BpfLpmKey, BpfMatchSet, LpmMapBuildSpec, LpmMapEntry, MATCH_TYPE_DOMAIN_SET, MATCH_TYPE_DSCP,
    MATCH_TYPE_FALLBACK, MATCH_TYPE_IP_SET, MATCH_TYPE_IP_VERSION, MATCH_TYPE_L4_PROTO,
    MATCH_TYPE_MAC, MATCH_TYPE_PORT, MATCH_TYPE_PROCESS_NAME, MATCH_TYPE_SOURCE_IP_SET,
    MATCH_TYPE_SOURCE_PORT, MAX_MATCH_SET_LEN, RoutingMapEntry,
};
use dae_routing::IpPrefix;

pub const MAX_LPM_ARRAY_ENTRIES: usize = MAX_MATCH_SET_LEN + 8;
pub const DEFAULT_LPM_MAX_ENTRIES: u32 = 2_048_000;
pub const BPF_F_NO_PREALLOC: u32 = 1;

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
            if spec.key_size != size_of::<BpfLpmKey>() as u32 {
                return Err(RoutingNativePlanError::InvalidLpmSpec {
                    index: spec.index,
                    field: "key_size",
                    got: u64::from(spec.key_size),
                    want: size_of::<BpfLpmKey>() as u64,
                });
            }
            if spec.value_size != size_of::<u32>() as u32 {
                return Err(RoutingNativePlanError::InvalidLpmSpec {
                    index: spec.index,
                    field: "value_size",
                    got: u64::from(spec.value_size),
                    want: size_of::<u32>() as u64,
                });
            }
            if spec.max_entries == 0 {
                return Err(RoutingNativePlanError::InvalidLpmSpec {
                    index: spec.index,
                    field: "max_entries",
                    got: 0,
                    want: 1,
                });
            }
            if spec.entries.len() > spec.max_entries as usize {
                return Err(RoutingNativePlanError::InvalidLpmSpec {
                    index: spec.index,
                    field: "entries",
                    got: spec.entries.len() as u64,
                    want: u64::from(spec.max_entries),
                });
            }
            if let Some(entry) = spec
                .entries
                .iter()
                .find(|entry| entry.key.prefix_len > dae_ebpf_support::BPF_LPM_FULL_PREFIX_BITS)
            {
                return Err(RoutingNativePlanError::InvalidLpmSpec {
                    index: spec.index,
                    field: "prefix_len",
                    got: u64::from(entry.key.prefix_len),
                    want: u64::from(dae_ebpf_support::BPF_LPM_FULL_PREFIX_BITS),
                });
            }
        }
        Ok(())
    }

    /// Deterministic change-detection digest over the whole plan (BLAKE3).
    ///
    /// Replaces the previous rotate-XOR weak hash: rotate-XOR has poor
    /// information diffusion and can collide across different plans, which
    /// would make `RoutingMapOwner` skip rewriting the kernel maps while the
    /// caller believes the new rules are live (security-relevant change
    /// detection, H13).  BLAKE3 is a collision-resistant cryptographic hash
    /// (already a workspace dependency), byte-wise and order-sensitive, and
    /// deterministic across processes.  Every field is mixed in: length
    /// prefixes, routing entry index/kind/outbound/not/must/mark plus the
    /// full `value` bytes, and each LPM spec's index/flags/max_entries plus
    /// its entries' prefix_len/value/data bytes.
    ///
    /// Note: this digest drives *change detection* for kernel map rewrites;
    /// it is not an authenticity mechanism (the plan is trusted input).
    pub fn checksum(&self) -> blake3::Hash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&(self.routing_entries.len() as u64).to_le_bytes());
        hasher.update(&(self.lpm_maps.len() as u64).to_le_bytes());
        for entry in &self.routing_entries {
            hasher.update(&entry.index.to_le_bytes());
            hasher.update(&[entry.value.kind]);
            hasher.update(&[entry.value.outbound]);
            hasher.update(&[entry.value.not]);
            hasher.update(&[entry.value.must]);
            hasher.update(&entry.value.mark.to_le_bytes());
            hasher.update(&entry.value.value);
        }
        for spec in &self.lpm_maps {
            hasher.update(&spec.index.to_le_bytes());
            hasher.update(&spec.flags.to_le_bytes());
            hasher.update(&spec.max_entries.to_le_bytes());
            hasher.update(&spec.key_size.to_le_bytes());
            hasher.update(&spec.value_size.to_le_bytes());
            for entry in &spec.entries {
                hasher.update(&entry.key.prefix_len.to_le_bytes());
                hasher.update(&entry.value.to_le_bytes());
                for word in entry.key.data {
                    hasher.update(&word.to_le_bytes());
                }
            }
        }
        hasher.finalize()
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
    InvalidLpmSpec {
        index: u32,
        field: &'static str,
        got: u64,
        want: u64,
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
            Self::InvalidLpmSpec {
                index,
                field,
                got,
                want,
            } => write!(
                f,
                "invalid LPM spec {index} {field}: got {got}, want {want}"
            ),
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
        IpAddr::V4(addr) => BpfLpmKey::from_ipv4_mapped(prefix.bits(), addr.octets()),
        IpAddr::V6(addr) => BpfLpmKey::from_ipv6(prefix.bits(), addr.octets()),
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
    BpfLpmKey::from_mac(mac)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn routing_entry(
        index: u32,
        kind: u8,
        outbound: u8,
        not: u8,
        must: u8,
        mark: u32,
        value: [u8; 16],
    ) -> RoutingMapEntry {
        RoutingMapEntry {
            index,
            value: BpfMatchSet {
                kind,
                outbound,
                not,
                must,
                mark,
                value,
            },
        }
    }

    fn lpm_entry(prefix_len: u32, value: u32, data: [u32; 4]) -> LpmMapEntry {
        LpmMapEntry {
            key: BpfLpmKey { prefix_len, data },
            value,
        }
    }

    #[test]
    fn blake3_checksum_matches_known_vector() {
        // BLAKE3 of the empty input — the standard test vector, verified
        // independently (af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262).
        assert_eq!(
            blake3::hash(b"").to_hex().as_str(),
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        );
        // And the checksum of an empty plan must be deterministic.
        let empty = RoutingNativeBuildPlan {
            routing_entries: vec![routing_entry(0, 3, 1, 0, 0, 0, [0; 16])],
            lpm_maps: vec![],
        };
        assert_eq!(empty.checksum(), empty.checksum());
    }

    #[test]
    fn checksum_differs_when_rule_order_swapped() {
        let plan_a = RoutingNativeBuildPlan {
            routing_entries: vec![
                routing_entry(0, 3, 1, 0, 0, 0, [1; 16]),
                routing_entry(1, 5, 2, 0, 0, 0, [2; 16]),
                routing_entry(2, 10, 3, 0, 0, 0, [3; 16]),
            ],
            lpm_maps: vec![],
        };
        let plan_b = RoutingNativeBuildPlan {
            routing_entries: vec![
                routing_entry(0, 5, 2, 0, 0, 0, [2; 16]),
                routing_entry(1, 3, 1, 0, 0, 0, [1; 16]),
                routing_entry(2, 10, 3, 0, 0, 0, [3; 16]),
            ],
            lpm_maps: vec![],
        };
        assert_ne!(plan_a.checksum(), plan_b.checksum());
    }

    #[test]
    fn checksum_differs_on_single_byte_change() {
        let base = RoutingNativeBuildPlan {
            routing_entries: vec![routing_entry(0, 3, 1, 0, 0, 0, [1; 16])],
            lpm_maps: vec![],
        };
        let mut changed_value = [1_u8; 16];
        changed_value[7] = 2;
        let changed = RoutingNativeBuildPlan {
            routing_entries: vec![routing_entry(0, 3, 1, 0, 0, 0, changed_value)],
            lpm_maps: vec![],
        };
        assert_ne!(base.checksum(), changed.checksum());

        // A single byte changed inside an LPM entry's key data word.
        let lpm_base = RoutingNativeBuildPlan {
            routing_entries: vec![routing_entry(0, 1, 1, 0, 0, 0, [0; 16])],
            lpm_maps: vec![LpmMapBuildSpec {
                index: 0,
                flags: 1,
                max_entries: 1024,
                key_size: 20,
                value_size: 4,
                entries: vec![lpm_entry(128, 1, [0x01020304, 0, 0, 0])],
            }],
        };
        let mut lpm_changed = lpm_base.clone();
        lpm_changed.lpm_maps[0].entries[0].key.data[0] = 0x01020305;
        assert_ne!(lpm_base.checksum(), lpm_changed.checksum());
    }

    #[test]
    fn checksum_changes_when_value_bytes_reordered() {
        // BLAKE3 is byte-order sensitive: swapping two 4-byte chunks inside
        // `value` must change the checksum (a collision class the old
        // rotate-XOR hash's commutative XOR steps could not reliably catch).
        let mut value_a = [0_u8; 16];
        value_a[..4].copy_from_slice(&1_u32.to_le_bytes());
        value_a[4..8].copy_from_slice(&2_u32.to_le_bytes());
        let mut value_b = [0_u8; 16];
        value_b[..4].copy_from_slice(&2_u32.to_le_bytes());
        value_b[4..8].copy_from_slice(&1_u32.to_le_bytes());
        let plan_a = RoutingNativeBuildPlan {
            routing_entries: vec![routing_entry(0, 3, 1, 0, 0, 0, value_a)],
            lpm_maps: vec![],
        };
        let plan_b = RoutingNativeBuildPlan {
            routing_entries: vec![routing_entry(0, 3, 1, 0, 0, 0, value_b)],
            lpm_maps: vec![],
        };
        assert_ne!(plan_a.checksum(), plan_b.checksum());
    }

    #[test]
    fn plan_validation_rejects_invalid_lpm_entry_contract() {
        let mut plan = RoutingNativeBuildPlan {
            routing_entries: vec![routing_entry(0, MATCH_TYPE_FALLBACK, 1, 0, 0, 0, [0; 16])],
            lpm_maps: vec![LpmMapBuildSpec {
                index: 0,
                flags: 1,
                max_entries: 1,
                key_size: size_of::<BpfLpmKey>() as u32,
                value_size: size_of::<u32>() as u32,
                entries: vec![lpm_entry(129, 1, [0; 4])],
            }],
        };
        let error = plan.validate().unwrap_err();
        assert!(matches!(
            error,
            RoutingNativePlanError::InvalidLpmSpec {
                field: "prefix_len",
                ..
            }
        ));

        plan.lpm_maps[0].entries[0] = lpm_entry(128, 1, [0; 4]);
        plan.lpm_maps[0].entries.push(lpm_entry(128, 1, [0; 4]));
        let error = plan.validate().unwrap_err();
        assert!(matches!(
            error,
            RoutingNativePlanError::InvalidLpmSpec {
                field: "entries",
                ..
            }
        ));
    }

    #[test]
    fn map_owner_rewrites_when_checksum_differs() {
        // H13 regression: a plan whose rules differ (here: swapped rule order)
        // must not be skipped by RoutingMapOwner even though the kernel map ids
        // are unchanged, otherwise the new rules never reach the kernel map
        // while the caller believes they are active.
        use crate::routing_owned::RoutingMapOwner;

        let plan_a = RoutingNativeBuildPlan {
            routing_entries: vec![
                routing_entry(0, 3, 1, 0, 0, 0, [1; 16]),
                routing_entry(1, 5, 2, 0, 0, 0, [2; 16]),
                routing_entry(2, 10, 3, 0, 0, 0, [3; 16]),
            ],
            lpm_maps: vec![],
        };
        let plan_b = RoutingNativeBuildPlan {
            routing_entries: vec![
                routing_entry(0, 5, 2, 0, 0, 0, [2; 16]),
                routing_entry(1, 3, 1, 0, 0, 0, [1; 16]),
                routing_entry(2, 10, 3, 0, 0, 0, [3; 16]),
            ],
            lpm_maps: vec![],
        };

        let mut owner = RoutingMapOwner::default();
        let first = owner
            .apply_snapshot_with(11, 22, plan_a, |_r, _l, _p| Ok(()))
            .unwrap();
        assert!(!first.skipped);
        let second = owner
            .apply_snapshot_with(11, 22, plan_b, |_r, _l, _p| Ok(()))
            .unwrap();
        assert!(
            !second.skipped,
            "plan with different rules must be applied, not skipped"
        );
        assert_ne!(first.checksum, second.checksum);
    }
}
