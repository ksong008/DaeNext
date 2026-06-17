use super::*;
pub(crate) fn parse_map_count_request(value: &str) -> Result<MapStatsCountRequest, String> {
    let (name, id) = value
        .split_once(':')
        .ok_or_else(|| format!("bad map-stats count --map {value:?}; want name:id"))?;
    if name.trim().is_empty() {
        return Err(format!("bad map-stats count --map {value:?}; empty name"));
    }
    let id = id
        .parse::<u32>()
        .map_err(|err| format!("bad map id in --map {value:?}: {err}"))?;
    Ok(MapStatsCountRequest {
        name: name.to_owned(),
        id,
    })
}

pub(crate) fn next_value<'a>(
    iter: &mut impl Iterator<Item = &'a String>,
    name: &str,
) -> Result<&'a str, String> {
    iter.next()
        .map(String::as_str)
        .ok_or_else(|| format!("missing {name}"))
}

pub(crate) fn parse_next<'a, T: std::str::FromStr>(
    iter: &mut impl Iterator<Item = &'a String>,
    name: &str,
) -> Result<T, String>
where
    T::Err: std::fmt::Display,
{
    next_value(iter, name)?
        .parse()
        .map_err(|err| format!("bad {name}: {err}"))
}

pub(crate) fn parse_next_path<'a>(
    iter: &mut impl Iterator<Item = &'a String>,
    name: &str,
) -> Result<PathBuf, String> {
    Ok(PathBuf::from(next_value(iter, name)?))
}

pub(crate) fn parse_value<T: std::str::FromStr>(arg: &str) -> Result<T, String>
where
    T::Err: std::fmt::Display,
{
    split_value(arg)?
        .parse()
        .map_err(|err| format!("bad {arg}: {err}"))
}

pub(crate) fn parse_path_value(arg: &str) -> Result<PathBuf, String> {
    Ok(PathBuf::from(split_value(arg)?))
}

pub(crate) fn split_value(arg: &str) -> Result<&str, String> {
    arg.split_once('=')
        .map(|(_, value)| value)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("missing value for {arg}"))
}

pub(crate) fn parse_bool(value: &str) -> Result<bool, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(format!("bad bool value: {value}")),
    }
}

pub(crate) fn parse_tc_attach_direction(
    value: &str,
) -> Result<dae_ebpf_support::TcAttachDirection, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "ingress" => Ok(dae_ebpf_support::TcAttachDirection::Ingress),
        "egress" => Ok(dae_ebpf_support::TcAttachDirection::Egress),
        _ => Err(format!("bad tc attach direction: {value}")),
    }
}

pub(crate) fn parse_attach_backend(value: &str) -> Result<dae_ebpf_support::AttachBackend, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "" | "auto" => Ok(dae_ebpf_support::AttachBackend::Auto),
        "tcx" => Ok(dae_ebpf_support::AttachBackend::Tcx),
        "tc" | "tc-netlink" | "tc_netlink" => Ok(dae_ebpf_support::AttachBackend::TcNetlink),
        _ => Err(format!("bad tc attach backend: {value}")),
    }
}

pub(crate) fn parse_mac(value: &str) -> Result<[u8; 6], String> {
    let mut mac = [0_u8; 6];
    let parts = value.split(':').collect::<Vec<_>>();
    if parts.len() != mac.len() {
        return Err(format!("bad mac address: {value}"));
    }
    for (index, part) in parts.iter().enumerate() {
        if part.len() != 2 {
            return Err(format!("bad mac address: {value}"));
        }
        mac[index] =
            u8::from_str_radix(part, 16).map_err(|err| format!("bad mac address: {err}"))?;
    }
    Ok(mac)
}
