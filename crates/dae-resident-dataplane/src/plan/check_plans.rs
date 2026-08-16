use super::*;

const RESIDENT_TCP_CHECK_FALLBACK_URL: &str = "http://cp.cloudflare.com";
const RESIDENT_UDP_CHECK_FALLBACK_DNS: &str = "dns.google:53";
const RESIDENT_DNS_CHECK_DEFAULT_PORT: u16 = dae_dns::ACTIVE_DNS_DEFAULT_TARGET_PORT;
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
        .unwrap_or(RESIDENT_TCP_CHECK_FALLBACK_URL);
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
    let targets = tcp_check_targets(host, port, explicit_addresses);
    let target = targets
        .first()
        .map(|target| target.target.clone())
        .expect("resident TCP check target list is never empty");
    let fallback_resolver = health_check_fallback_resolver(config, &group.name)?;
    let resolver = ResidentHealthTargetResolver::new(
        host.to_owned(),
        port,
        targets
            .iter()
            .filter_map(|target| target.target.parse::<SocketAddr>().ok())
            .collect(),
        fallback_resolver,
        effective_so_mark_from_dae(config.global.so_mark_from_dae),
        group_check_interval(config, group),
    );
    Ok(ResidentTcpCheckPlan {
        scheme: url.scheme().to_owned(),
        target,
        targets,
        host: host.to_owned(),
        path,
        method,
        resolver,
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
        .unwrap_or(RESIDENT_UDP_CHECK_FALLBACK_DNS);
    let (host, port) = split_check_host_port(raw).map_err(|err| {
        format!(
            "resident dataplane group {} udp_check_dns {raw}: {err}",
            group.name
        )
    })?;
    let explicit_addresses = if values.len() > 1 { &values[1..] } else { &[] };
    let fallback_resolver = health_check_fallback_resolver(config, &group.name)?;
    let targets = udp_check_targets(&host, port, explicit_addresses).map_err(|err| {
        format!(
            "resident dataplane group {} udp_check_dns {raw}: {err}",
            group.name
        )
    })?;
    let target = targets
        .first()
        .cloned()
        .expect("resident UDP check target list is never empty");
    let resolver = ResidentHealthTargetResolver::new(
        host.clone(),
        port,
        targets
            .iter()
            .filter_map(ResidentUdpCheckTarget::literal_addr)
            .collect(),
        fallback_resolver,
        effective_so_mark_from_dae(config.global.so_mark_from_dae),
        group_check_interval(config, group),
    );
    Ok(ResidentUdpCheckPlan {
        target,
        targets,
        host,
        lookup_host: "connectivitycheck.gstatic.com.".to_owned(),
        resolver,
    })
}

fn health_check_fallback_resolver(config: &Config, group_name: &str) -> Result<SocketAddr, String> {
    config
        .global
        .fallback_resolver
        .parse::<SocketAddr>()
        .map_err(|err| {
            format!(
                "resident dataplane group {group_name} invalid global.fallback_resolver {:?}: {err}",
                config.global.fallback_resolver
            )
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
        let port = match after_host.strip_prefix(':') {
            Some(port) => port.to_owned(),
            None if after_host.is_empty() => RESIDENT_DNS_CHECK_DEFAULT_PORT.to_string(),
            None => return Err("unexpected text after bracketed host".to_owned()),
        };
        return Ok((host.to_owned(), parse_check_port(&port)?));
    }
    if raw.parse::<IpAddr>().is_ok() {
        return Ok((raw.to_owned(), RESIDENT_DNS_CHECK_DEFAULT_PORT));
    }
    let (host, port) = if raw.matches(':').count() > 1 {
        return Err("expected IPv4, domain, host:port, or bracketed IPv6 host".to_owned());
    } else if let Some((host, port)) = raw.rsplit_once(':') {
        (host.to_owned(), port.to_owned())
    } else {
        (raw.to_owned(), RESIDENT_DNS_CHECK_DEFAULT_PORT.to_string())
    };
    if host.trim().is_empty() {
        return Err("empty host".to_owned());
    }
    Ok((host, parse_check_port(&port)?))
}

pub(super) fn parse_check_port(raw: &str) -> Result<u16, String> {
    raw.parse::<u16>()
        .map_err(|err| format!("invalid port {raw}: {err}"))
}

pub(super) fn tcp_check_targets(
    host: &str,
    port: u16,
    explicit_addresses: &[String],
) -> Vec<ResidentTcpCheckTarget> {
    let mut targets = Vec::new();
    for raw in explicit_addresses {
        let raw = raw.trim();
        if let Ok(ip) = raw.parse::<IpAddr>() {
            push_tcp_check_target(&mut targets, ip, port);
        }
    }
    if !targets.is_empty() {
        return targets;
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        push_tcp_check_target(&mut targets, ip, port);
        return targets;
    }
    targets.push(ResidentTcpCheckTarget {
        target: authority_from_host_port(host, port),
        network_type: None,
    });
    targets
}

fn push_tcp_check_target(targets: &mut Vec<ResidentTcpCheckTarget>, ip: IpAddr, port: u16) {
    let target = SocketAddr::new(ip, port).to_string();
    if targets.iter().any(|seen| seen.target == target) {
        return;
    }
    targets.push(ResidentTcpCheckTarget {
        target,
        network_type: Some(resident_tcp_check_network_type(ip)),
    });
}

pub(super) fn udp_check_targets(
    host: &str,
    port: u16,
    explicit_addresses: &[String],
) -> Result<Vec<ResidentUdpCheckTarget>, String> {
    let mut targets = Vec::new();
    for raw in explicit_addresses {
        let raw = raw.trim();
        if raw.is_empty() {
            continue;
        }
        if let Ok(ip) = raw.parse::<IpAddr>() {
            push_udp_check_target(&mut targets, SocketAddr::new(ip, port));
        }
    }
    if !targets.is_empty() {
        return Ok(targets);
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        push_udp_check_target(&mut targets, SocketAddr::new(ip, port));
        return Ok(targets);
    }
    let authority = authority_from_host_port(host, port);
    targets.push(ResidentUdpCheckTarget::new(authority, None));
    Ok(targets)
}

fn push_udp_check_target(targets: &mut Vec<ResidentUdpCheckTarget>, addr: SocketAddr) {
    if targets.iter().any(|seen| seen.literal_addr() == Some(addr)) {
        return;
    }
    targets.push(ResidentUdpCheckTarget::literal(addr));
}

fn authority_from_host_port(host: &str, port: u16) -> String {
    if host.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

pub(super) fn duration_nanos_to_millis(nanos: i64) -> i64 {
    if nanos <= 0 {
        return 0;
    }
    nanos / 1_000_000 + i64::from(nanos % 1_000_000 != 0)
}

#[cfg(test)]
mod duration_tests {
    use super::duration_nanos_to_millis;

    #[test]
    fn nanos_to_millis_rounds_up_without_overflow() {
        assert_eq!(duration_nanos_to_millis(1), 1);
        assert_eq!(duration_nanos_to_millis(1_000_000), 1);
        assert_eq!(duration_nanos_to_millis(i64::MAX), i64::MAX / 1_000_000 + 1);
    }
}
