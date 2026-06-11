use super::*;
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

pub(super) fn outbound_from_fixture(value: &str) -> Result<OutboundIndex, RoutingError> {
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

pub(super) fn routing_match_kind_from_fixture(
    match_type: MatchType,
    value: &Value,
) -> Result<RoutingMatchKind, RoutingError> {
    Ok(match match_type {
        MatchType::DomainSet => RoutingMatchKind::DomainSet,
        MatchType::IpSet => RoutingMatchKind::IpSet {
            lpm_index: required_u64(value, "lpm_index")? as u32,
        },
        MatchType::SourceIpSet => RoutingMatchKind::SourceIpSet {
            lpm_index: required_u64(value, "lpm_index")? as u32,
        },
        MatchType::Port => {
            let start = value.get("port_start").and_then(Value::as_u64).unwrap_or(0) as u16;
            let end = value
                .get("port_end")
                .and_then(Value::as_u64)
                .unwrap_or(start as u64) as u16;
            RoutingMatchKind::Port { start, end }
        }
        MatchType::SourcePort => {
            let start = value.get("port_start").and_then(Value::as_u64).unwrap_or(0) as u16;
            let end = value
                .get("port_end")
                .and_then(Value::as_u64)
                .unwrap_or(start as u64) as u16;
            RoutingMatchKind::SourcePort { start, end }
        }
        MatchType::L4Proto => RoutingMatchKind::L4Proto {
            value: optional_match_u8_value(value)?.ok_or_else(|| {
                RoutingError::InvalidFixture("l4proto match value is missing".to_owned())
            })?,
        },
        MatchType::IpVersion => RoutingMatchKind::IpVersion {
            value: optional_match_u8_value(value)?.ok_or_else(|| {
                RoutingError::InvalidFixture("ipversion match value is missing".to_owned())
            })?,
        },
        MatchType::Mac => RoutingMatchKind::Mac {
            lpm_index: required_u64(value, "lpm_index")? as u32,
        },
        MatchType::ProcessName => RoutingMatchKind::ProcessName {
            value: value
                .get("process_name")
                .and_then(Value::as_str)
                .map(process_name_bytes)
                .ok_or_else(|| {
                    RoutingError::InvalidFixture("process_name match value is missing".to_owned())
                })?,
        },
        MatchType::Dscp => RoutingMatchKind::Dscp {
            value: optional_match_u8_value(value)?.ok_or_else(|| {
                RoutingError::InvalidFixture("dscp match value is missing".to_owned())
            })?,
        },
        MatchType::Fallback => RoutingMatchKind::Fallback,
    })
}

pub(super) fn optional_match_u8_value(value: &Value) -> Result<Option<u8>, RoutingError> {
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

pub(super) fn parse_l4proto(value: &str) -> Result<u8, RoutingError> {
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

pub(super) fn parse_ip_version(value: &str) -> Result<u8, RoutingError> {
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

pub(super) fn process_name_bytes(value: &str) -> [u8; 16] {
    let mut out = [0_u8; 16];
    let raw = value.as_bytes();
    let copy_len = raw.len().min(out.len());
    out[..copy_len].copy_from_slice(&raw[..copy_len]);
    out
}

pub(super) fn bitmap_has(bitmap: &[u32], bit: usize) -> bool {
    bitmap
        .get(bit / 32)
        .map(|word| ((word >> (bit % 32)) & 1) != 0)
        .unwrap_or(false)
}

pub(super) fn required_str<'a>(value: &'a Value, key: &str) -> Result<&'a str, RoutingError> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| RoutingError::InvalidFixture(format!("{key} must be string")))
}

pub(super) fn required_u64(value: &Value, key: &str) -> Result<u64, RoutingError> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| RoutingError::InvalidFixture(format!("{key} must be number")))
}

pub(super) fn required_array<'a>(
    value: &'a Value,
    key: &str,
) -> Result<&'a Vec<Value>, RoutingError> {
    value
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| RoutingError::InvalidFixture(format!("{key} must be array")))
}
