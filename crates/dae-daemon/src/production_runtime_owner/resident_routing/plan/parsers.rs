use super::*;
pub(super) fn parse_l4_proto(values: &[String]) -> Result<u8, String> {
    let mut value = 0_u8;
    for item in values {
        match item.as_str() {
            "tcp" => value |= L4_TCP,
            "udp" => value |= L4_UDP,
            other => return Err(format!("unsupported l4proto: {other}")),
        }
    }
    if value == 0 {
        return Err("empty l4proto".to_owned());
    }
    Ok(value)
}

pub(super) fn parse_ip_version(values: &[String]) -> Result<u8, String> {
    let mut value = 0_u8;
    for item in values {
        match item.as_str() {
            "4" => value |= IP_VERSION_4,
            "6" => value |= IP_VERSION_6,
            other => return Err(format!("unsupported ipversion: {other}")),
        }
    }
    if value == 0 {
        return Err("empty ipversion".to_owned());
    }
    Ok(value)
}

pub(super) fn parse_port_range(value: &str) -> Result<(u16, u16), String> {
    if let Some((start, end)) = value.split_once('-') {
        let start = start
            .parse::<u16>()
            .map_err(|err| format!("invalid port range start {value}: {err}"))?;
        let end = end
            .parse::<u16>()
            .map_err(|err| format!("invalid port range end {value}: {err}"))?;
        if start > end {
            return Err(format!("invalid descending port range: {value}"));
        }
        return Ok((start, end));
    }
    let port = value
        .parse::<u16>()
        .map_err(|err| format!("invalid port {value}: {err}"))?;
    Ok((port, port))
}

pub(super) fn parse_ip_prefix_group(
    param_key: &str,
    values: &[String],
) -> Result<Vec<IpPrefix>, String> {
    match param_key {
        "" => values.iter().map(|value| parse_ip_prefix(value)).collect(),
        other => Err(format!("unsupported resident ip parameter key: {other}")),
    }
}

pub(super) fn parse_ip_prefix(value: &str) -> Result<IpPrefix, String> {
    let value = value.trim_matches('\'').trim_matches('"');
    if let Some((addr, bits)) = value.split_once('/') {
        let addr = IpAddr::from_str(addr).map_err(|err| format!("invalid ip {value}: {err}"))?;
        let bits = bits
            .parse::<u8>()
            .map_err(|err| format!("invalid prefix bits {value}: {err}"))?;
        let max_bits = if addr.is_ipv4() { 32 } else { 128 };
        if bits > max_bits {
            return Err(format!("invalid prefix bits {bits} for {addr}"));
        }
        return Ok(IpPrefix { addr, bits });
    }
    let addr = IpAddr::from_str(value).map_err(|err| format!("invalid ip {value}: {err}"))?;
    let bits = if addr.is_ipv4() { 32 } else { 128 };
    Ok(IpPrefix { addr, bits })
}

pub(super) fn parse_mac_prefix(value: &str) -> Result<IpPrefix, String> {
    let parts = value.split(':').collect::<Vec<_>>();
    if parts.len() != 6 {
        return Err(format!("invalid mac address: {value}"));
    }
    let mut octets = [0_u8; 16];
    for (index, part) in parts.iter().enumerate() {
        octets[index + 10] = u8::from_str_radix(part, 16)
            .map_err(|err| format!("invalid mac address {value}: {err}"))?;
    }
    Ok(IpPrefix {
        addr: IpAddr::V6(Ipv6Addr::from(octets)),
        bits: 128,
    })
}

pub(super) fn parse_u32_auto(value: &str) -> Result<u32, std::num::ParseIntError> {
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        u32::from_str_radix(hex, 16)
    } else {
        value.parse::<u32>()
    }
}

pub(super) fn parse_dscp(value: &str) -> Result<u8, String> {
    let parsed = parse_u64_base0(value).map_err(|err| format!("invalid dscp {value}: {err}"))?;
    if parsed > 63 {
        return Err(format!("invalid dscp {value}: value {parsed} exceeds 63"));
    }
    Ok(parsed as u8)
}

fn parse_u64_base0(value: &str) -> Result<u64, std::num::ParseIntError> {
    if let Some(rest) = value.strip_prefix('+') {
        return parse_u64_base0(rest);
    }
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        return u64::from_str_radix(hex, 16);
    }
    if let Some(octal) = value
        .strip_prefix("0o")
        .or_else(|| value.strip_prefix("0O"))
    {
        return u64::from_str_radix(octal, 8);
    }
    if let Some(binary) = value
        .strip_prefix("0b")
        .or_else(|| value.strip_prefix("0B"))
    {
        return u64::from_str_radix(binary, 2);
    }
    if value.len() > 1
        && value.starts_with('0')
        && value.as_bytes().get(1).is_some_and(u8::is_ascii_digit)
    {
        return u64::from_str_radix(value, 8);
    }
    value.parse::<u64>()
}
