use super::*;
use std::time::Duration;

#[cfg(test)]
use crate::resident_dns_upstream_refresh_interval;

pub(super) fn parse_dns_fallback_resolver(config: &Config) -> Result<SocketAddr, String> {
    config
        .global
        .fallback_resolver
        .parse::<SocketAddr>()
        .map_err(|err| {
            format!(
                "invalid global.fallback_resolver {:?}: {err}",
                config.global.fallback_resolver
            )
        })
}

#[cfg(test)]
pub(in crate::dns) fn parse_dns_upstream(
    index: u8,
    tag: &str,
    link: &str,
    fallback_resolver: SocketAddr,
    resolver_mark: u32,
) -> Result<ResidentDnsUpstream, String> {
    parse_dns_upstream_with_refresh_interval(
        index,
        tag,
        link,
        fallback_resolver,
        resolver_mark,
        resident_dns_upstream_refresh_interval(),
    )
}

pub(super) fn parse_dns_upstream_with_refresh_interval(
    index: u8,
    tag: &str,
    link: &str,
    fallback_resolver: SocketAddr,
    resolver_mark: u32,
    refresh_interval: Duration,
) -> Result<ResidentDnsUpstream, String> {
    let (scheme, rest) = link
        .split_once("://")
        .ok_or_else(|| format!("DNS upstream {tag} has no scheme: {link}"))?;
    let scheme = match scheme {
        "udp" => ResidentDnsUpstreamScheme::Udp,
        "tcp" => ResidentDnsUpstreamScheme::Tcp,
        "tcp+udp" | "udp+tcp" => ResidentDnsUpstreamScheme::TcpUdp,
        "tls" => ResidentDnsUpstreamScheme::Tls,
        "https" => ResidentDnsUpstreamScheme::Https,
        "quic" => ResidentDnsUpstreamScheme::Quic,
        "h3" | "http3" => ResidentDnsUpstreamScheme::Http3,
        other => {
            return Err(format!(
                "resident DNS upstream {tag} uses unsupported scheme {other}; resident DNS upstream shape remains fail-closed until this scheme is admitted"
            ));
        }
    };
    let (authority, path) = split_dns_upstream_authority_and_path(rest, scheme);
    let target = parse_dns_upstream_authority(
        authority,
        scheme.default_port(),
        fallback_resolver,
        resolver_mark,
        refresh_interval,
    )?;
    Ok(ResidentDnsUpstream {
        index,
        tag: tag.to_owned(),
        target,
        scheme,
        path: path.into(),
    })
}

impl ResidentDnsUpstreamScheme {
    const fn default_port(self) -> u16 {
        match self {
            Self::Udp | Self::Tcp | Self::TcpUdp => DNS_DEFAULT_PORT,
            Self::Tls | Self::Quic => DNS_TLS_DEFAULT_PORT,
            Self::Https | Self::Http3 => DNS_HTTPS_DEFAULT_PORT,
        }
    }

    const fn default_path(self) -> &'static str {
        match self {
            Self::Https | Self::Http3 => DNS_DEFAULT_DOH_PATH,
            Self::Udp | Self::Tcp | Self::TcpUdp | Self::Tls | Self::Quic => "",
        }
    }
}

fn split_dns_upstream_authority_and_path(
    rest: &str,
    scheme: ResidentDnsUpstreamScheme,
) -> (&str, String) {
    match rest.find('/') {
        Some(index) => (&rest[..index], rest[index..].to_owned()),
        None => (rest, scheme.default_path().to_owned()),
    }
}

fn parse_dns_upstream_authority(
    authority: &str,
    default_port: u16,
    fallback_resolver: SocketAddr,
    resolver_mark: u32,
    refresh_interval: Duration,
) -> Result<ResidentDnsUpstreamTarget, String> {
    let authority = authority.trim();
    if authority.is_empty() {
        return Err("DNS upstream authority is empty".to_owned());
    }
    let (authority, host, port, literal_addr) =
        dns_upstream_authority_with_default_port(authority, default_port)?;
    Ok(ResidentDnsUpstreamTarget::new(
        authority,
        host,
        port,
        literal_addr,
        fallback_resolver,
        resolver_mark,
        refresh_interval,
    ))
}

fn dns_upstream_authority_with_default_port(
    authority: &str,
    default_port: u16,
) -> Result<(String, String, u16, Option<SocketAddr>), String> {
    if let Ok(addr) = authority.parse::<SocketAddr>() {
        return Ok((
            addr.to_string(),
            addr.ip().to_string(),
            addr.port(),
            Some(addr),
        ));
    }
    if let Ok(ip) = authority.parse::<IpAddr>() {
        let addr = SocketAddr::new(ip, default_port);
        return Ok((addr.to_string(), ip.to_string(), default_port, Some(addr)));
    }
    if let Some(rest) = authority.strip_prefix('[') {
        let Some((host, tail)) = rest.split_once(']') else {
            return Err(format!(
                "DNS upstream {authority} has malformed IPv6 authority"
            ));
        };
        let port = match tail.strip_prefix(':') {
            Some(port) => port
                .parse::<u16>()
                .map_err(|err| format!("DNS upstream {authority} has invalid port: {err}"))?,
            None if tail.is_empty() => default_port,
            None => {
                return Err(format!(
                    "DNS upstream {authority} has unexpected text after bracketed host"
                ));
            }
        };
        if let Ok(ip) = host.parse::<IpAddr>() {
            let addr = SocketAddr::new(ip, port);
            return Ok((addr.to_string(), ip.to_string(), port, Some(addr)));
        }
        return Ok((format!("[{host}]:{port}"), host.to_owned(), port, None));
    }
    if authority.matches(':').count() > 1 {
        return Err(format!(
            "DNS upstream {authority} is an IPv6 literal and must be bracketed when a port is supplied"
        ));
    }
    if let Some((host, port)) = authority.rsplit_once(':') {
        let port = port
            .parse::<u16>()
            .map_err(|err| format!("DNS upstream {authority} has invalid port: {err}"))?;
        return Ok((authority.to_owned(), host.to_owned(), port, None));
    }
    Ok((
        format!("{authority}:{default_port}"),
        authority.to_owned(),
        default_port,
        None,
    ))
}

pub(super) fn split_keyable_link(raw: &str) -> (Option<String>, String) {
    let trimmed = raw.trim();
    let Some(scheme_pos) = trimmed.find("://") else {
        return (None, unquote_config_value(trimmed));
    };
    let before_scheme = &trimmed[..scheme_pos];
    if let Some(colon) = before_scheme.rfind(':') {
        let tag = unquote_config_value(&trimmed[..colon]);
        let link = unquote_config_value(&trimmed[colon + 1..]);
        if !tag.is_empty() {
            return (Some(tag), link);
        }
    }
    (None, unquote_config_value(trimmed))
}

fn unquote_config_value(value: &str) -> String {
    let value = value.trim();
    if value.len() >= 2 {
        let bytes = value.as_bytes();
        if (bytes[0] == b'\'' && bytes[value.len() - 1] == b'\'')
            || (bytes[0] == b'"' && bytes[value.len() - 1] == b'"')
        {
            return value[1..value.len() - 1].to_owned();
        }
    }
    value.to_owned()
}
