use super::*;
impl RoutingMatchSet {
    pub(super) fn from_fixture_value(value: &Value) -> Result<Self, RoutingError> {
        let match_type = MatchType::try_from(required_str(value, "type")?)?;
        Ok(Self {
            kind: routing_match_kind_from_fixture(match_type, value)?,
            outbound: outbound_from_fixture(required_str(value, "outbound")?)?,
            not: value.get("not").and_then(Value::as_bool).unwrap_or(false),
            mark: value.get("mark").and_then(Value::as_u64).unwrap_or(0) as u32,
            must: value.get("must").and_then(Value::as_bool).unwrap_or(false),
        })
    }
}

impl MatchSet {
    pub(super) fn from_typed_set(set: RoutingMatchSet) -> Self {
        let RoutingMatchSet {
            kind,
            outbound,
            not,
            mark,
            must,
        } = set;
        let mut out = Self {
            match_type: MatchType::Fallback,
            outbound,
            not,
            mark,
            must,
            lpm_index: None,
            port_start: None,
            port_end: None,
            value_u8: None,
            process_name: None,
        };
        match kind {
            RoutingMatchKind::DomainSet => out.match_type = MatchType::DomainSet,
            RoutingMatchKind::IpSet { lpm_index } => {
                out.match_type = MatchType::IpSet;
                out.lpm_index = Some(lpm_index);
            }
            RoutingMatchKind::SourceIpSet { lpm_index } => {
                out.match_type = MatchType::SourceIpSet;
                out.lpm_index = Some(lpm_index);
            }
            RoutingMatchKind::Port { start, end } => {
                out.match_type = MatchType::Port;
                out.port_start = Some(start);
                out.port_end = Some(end);
            }
            RoutingMatchKind::SourcePort { start, end } => {
                out.match_type = MatchType::SourcePort;
                out.port_start = Some(start);
                out.port_end = Some(end);
            }
            RoutingMatchKind::L4Proto { value } => {
                out.match_type = MatchType::L4Proto;
                out.value_u8 = Some(value);
            }
            RoutingMatchKind::IpVersion { value } => {
                out.match_type = MatchType::IpVersion;
                out.value_u8 = Some(value);
            }
            RoutingMatchKind::Mac { lpm_index } => {
                out.match_type = MatchType::Mac;
                out.lpm_index = Some(lpm_index);
            }
            RoutingMatchKind::ProcessName { value } => {
                out.match_type = MatchType::ProcessName;
                out.process_name = Some(value);
            }
            RoutingMatchKind::Dscp { value } => {
                out.match_type = MatchType::Dscp;
                out.value_u8 = Some(value);
            }
            RoutingMatchKind::Fallback => out.match_type = MatchType::Fallback,
        }
        out
    }

    pub(super) fn matches(
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
