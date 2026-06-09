use super::*;
pub(super) fn group_check_tolerance_ms(config: &Config, group: &Group) -> i64 {
    let nanos = if group.check_tolerance.as_nanos() != 0 {
        group.check_tolerance.as_nanos()
    } else {
        config.global.check_tolerance.as_nanos()
    };
    duration_nanos_to_millis(nanos)
}

pub(super) fn group_check_interval(config: &Config, group: &Group) -> Duration {
    let nanos = if group.check_interval.as_nanos() != 0 {
        group.check_interval.as_nanos()
    } else {
        config.global.check_interval.as_nanos()
    };
    duration_nanos_to_duration(nanos)
}

pub(super) fn duration_nanos_to_duration(nanos: i64) -> Duration {
    if nanos <= 0 {
        return Duration::ZERO;
    }
    Duration::from_nanos(nanos as u64)
}

pub(super) fn group_tcp_check_plan(
    config: &Config,
    group: &Group,
) -> Result<ResidentTcpCheckPlan, String> {
    let urls = group
        .tcp_check_url
        .as_ref()
        .filter(|urls| !urls.is_empty())
        .unwrap_or(&config.global.tcp_check_url);
    let raw = urls
        .first()
        .filter(|raw| !raw.is_empty())
        .map(String::as_str)
        .unwrap_or("http://cp.cloudflare.com");
    let url = Url::parse(raw).map_err(|err| {
        format!(
            "resident dataplane group {} tcp_check_url {raw}: {err}",
            group.name
        )
    })?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(format!(
            "resident dataplane group {} tcp_check_url supports http or https check targets, got scheme {}",
            group.name,
            url.scheme()
        ));
    }
    let host = url.host_str().ok_or_else(|| {
        format!(
            "resident dataplane group {} tcp_check_url {raw} has no host",
            group.name
        )
    })?;
    let port = url.port_or_known_default().unwrap_or(80);
    let mut path = url.path().to_owned();
    if path.is_empty() {
        path = "/".to_owned();
    }
    if let Some(query) = url.query()
        && !query.is_empty()
    {
        path.push('?');
        path.push_str(query);
    }
    let method = if !group.tcp_check_http_method.is_empty() {
        group.tcp_check_http_method.clone()
    } else if !config.global.tcp_check_http_method.is_empty() {
        config.global.tcp_check_http_method.clone()
    } else {
        "HEAD".to_owned()
    };
    let explicit_addresses = if urls.len() > 1 { &urls[1..] } else { &[] };
    Ok(ResidentTcpCheckPlan {
        scheme: url.scheme().to_owned(),
        target: tcp_check_target(host, port, explicit_addresses),
        host: host.to_owned(),
        path,
        method,
    })
}

pub(super) fn group_udp_check_plan(
    config: &Config,
    group: &Group,
) -> Result<ResidentUdpCheckPlan, String> {
    let values = group
        .udp_check_dns
        .as_ref()
        .filter(|values| !values.is_empty())
        .unwrap_or(&config.global.udp_check_dns);
    let raw = values
        .first()
        .filter(|raw| !raw.is_empty())
        .map(String::as_str)
        .unwrap_or("dns.google:53");
    let (host, port) = split_check_host_port(raw).map_err(|err| {
        format!(
            "resident dataplane group {} udp_check_dns {raw}: {err}",
            group.name
        )
    })?;
    let explicit_addresses = if values.len() > 1 { &values[1..] } else { &[] };
    let target = udp_check_target(&host, port, explicit_addresses).map_err(|err| {
        format!(
            "resident dataplane group {} udp_check_dns {raw}: {err}",
            group.name
        )
    })?;
    Ok(ResidentUdpCheckPlan {
        target,
        host,
        lookup_host: "connectivitycheck.gstatic.com.".to_owned(),
    })
}

pub(super) fn split_check_host_port(raw: &str) -> Result<(String, u16), String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err("empty host:port".to_owned());
    }
    if let Some(rest) = raw.strip_prefix('[') {
        let Some((host, after_host)) = rest.split_once(']') else {
            return Err("missing closing bracket for IPv6 host".to_owned());
        };
        let port = after_host
            .strip_prefix(':')
            .ok_or_else(|| "missing port after IPv6 host".to_owned())?;
        return Ok((host.to_owned(), parse_check_port(port)?));
    }
    let Some((host, port)) = raw.rsplit_once(':') else {
        return Err("expected host:port".to_owned());
    };
    if host.is_empty() {
        return Err("empty host".to_owned());
    }
    Ok((host.to_owned(), parse_check_port(port)?))
}

pub(super) fn parse_check_port(raw: &str) -> Result<u16, String> {
    raw.parse::<u16>()
        .map_err(|err| format!("invalid port {raw}: {err}"))
}

pub(super) fn tcp_check_target(host: &str, port: u16, explicit_addresses: &[String]) -> String {
    for raw in explicit_addresses {
        let raw = raw.trim();
        if raw.parse::<Ipv4Addr>().is_ok() {
            return format!("{raw}:{port}");
        }
    }
    format!("{host}:{port}")
}

pub(super) fn udp_check_target(
    host: &str,
    port: u16,
    explicit_addresses: &[String],
) -> Result<ResidentUdpCheckTarget, String> {
    for raw in explicit_addresses {
        let raw = raw.trim();
        if raw.is_empty() {
            continue;
        }
        if let Ok(ip) = raw.parse::<Ipv4Addr>() {
            return Ok(ResidentUdpCheckTarget::literal(SocketAddrV4::new(ip, port)));
        }
    }
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        return Ok(ResidentUdpCheckTarget::literal(SocketAddrV4::new(ip, port)));
    }
    let authority = format!("{host}:{port}");
    Ok(ResidentUdpCheckTarget::new(authority, None))
}

pub(super) fn duration_nanos_to_millis(nanos: i64) -> i64 {
    if nanos <= 0 {
        return 0;
    }
    (nanos + 999_999) / 1_000_000
}

pub(super) fn resident_selector_network_type(network: &str) -> Result<NetworkType, String> {
    match network {
        "tcp4" => Ok(NetworkType::TCP4),
        "udp4" => Ok(NetworkType::DNS_UDP4),
        other => Err(format!("unsupported resident selector network: {other}")),
    }
}
