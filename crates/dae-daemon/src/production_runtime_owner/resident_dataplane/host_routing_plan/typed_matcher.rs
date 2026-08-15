use super::*;

type UserspaceMatcherTypedSets = (
    Vec<RoutingSharedDomainSet>,
    Vec<RoutingSharedLpmSet>,
    Vec<RoutingMatchSet>,
);

pub(crate) fn domain_set_json(set: &ResidentDomainSet) -> Value {
    json!({
        "rule_index": set.rule_index,
        "key": domain_key_name(set.values.key()),
        "value_count": set.values.patterns().len(),
        "sample_values": set.values.patterns().iter().take(8).collect::<Vec<_>>(),
        "values_truncated": set.values.patterns().len() > 8,
    })
}

fn domain_key_name(key: DomainKey) -> &'static str {
    match key {
        DomainKey::Full => "full",
        DomainKey::Keyword => "keyword",
        DomainKey::Suffix => "suffix",
        DomainKey::Regex => "regex",
    }
}

pub(crate) fn userspace_matcher_typed_sets(
    plan: &ResidentRoutingPlan,
) -> Result<UserspaceMatcherTypedSets, String> {
    let domain_sets = plan
        .domain_sets
        .iter()
        .map(|set| {
            Ok(RoutingSharedDomainSet {
                bit: set.rule_index,
                patterns: set.values.clone(),
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let lpm_sets = plan
        .lpm_sets
        .iter()
        .enumerate()
        .map(|(index, prefixes)| {
            let prefixes = prefixes.iter().cloned().collect::<Vec<_>>();
            Ok(RoutingSharedLpmSet {
                index: index as u32,
                prefixes: SharedIpPrefixSet::new(prefixes),
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let matches = plan
        .matches
        .iter()
        .map(match_set_typed)
        .collect::<Result<Vec<_>, String>>()?;
    Ok((domain_sets, lpm_sets, matches))
}

pub(crate) fn match_set_typed(set: &MatchSetBytes) -> Result<RoutingMatchSet, String> {
    let kind = match set.bytes[17] {
        MATCH_TYPE_DOMAIN_SET => RoutingMatchKind::DomainSet,
        MATCH_TYPE_IP_SET => RoutingMatchKind::IpSet {
            lpm_index: u32::from_le_bytes([set.bytes[0], set.bytes[1], set.bytes[2], set.bytes[3]]),
        },
        MATCH_TYPE_SOURCE_IP_SET => RoutingMatchKind::SourceIpSet {
            lpm_index: u32::from_le_bytes([set.bytes[0], set.bytes[1], set.bytes[2], set.bytes[3]]),
        },
        MATCH_TYPE_PORT => RoutingMatchKind::Port {
            start: u16::from_le_bytes([set.bytes[0], set.bytes[1]]),
            end: u16::from_le_bytes([set.bytes[2], set.bytes[3]]),
        },
        MATCH_TYPE_SOURCE_PORT => RoutingMatchKind::SourcePort {
            start: u16::from_le_bytes([set.bytes[0], set.bytes[1]]),
            end: u16::from_le_bytes([set.bytes[2], set.bytes[3]]),
        },
        MATCH_TYPE_L4_PROTO => RoutingMatchKind::L4Proto {
            value: set.bytes[0],
        },
        MATCH_TYPE_IP_VERSION => RoutingMatchKind::IpVersion {
            value: set.bytes[0],
        },
        MATCH_TYPE_MAC => RoutingMatchKind::Mac {
            lpm_index: u32::from_le_bytes([set.bytes[0], set.bytes[1], set.bytes[2], set.bytes[3]]),
        },
        MATCH_TYPE_PROCESS_NAME => {
            let mut value = [0_u8; 16];
            value.copy_from_slice(&set.bytes[..16]);
            RoutingMatchKind::ProcessName { value }
        }
        MATCH_TYPE_DSCP => RoutingMatchKind::Dscp {
            value: set.bytes[0],
        },
        MATCH_TYPE_FALLBACK => RoutingMatchKind::Fallback,
        other => return Err(format!("unknown resident routing match type: {other}")),
    };
    Ok(RoutingMatchSet {
        kind,
        outbound: OutboundIndex(set.outbound),
        not: set.bytes[16] != 0,
        mark: set.mark,
        must: set.must,
    })
}
