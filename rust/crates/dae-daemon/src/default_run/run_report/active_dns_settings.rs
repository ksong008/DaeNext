use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, ToSocketAddrs};
use std::path::Path;

use super::*;

const CONFIGURED_DNS_CHECK_DEFAULT_PORT: u16 = dae_dns::ACTIVE_DNS_DEFAULT_TARGET_PORT;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ConfiguredActiveDnsTarget {
    pub(super) target_ip: String,
    pub(super) target_port: u16,
}

pub(super) fn apply_configured_active_dns_target(
    options: &mut ProductionRuntimeOwnerOptions,
    config: &Path,
    resolve_domains: bool,
) -> Result<(), String> {
    if !options.active_dns_target_ip.trim().is_empty() {
        return Ok(());
    }
    match configured_active_dns_target_from_config(config, resolve_domains) {
        Ok(Some(target)) => {
            options.active_dns_target_ip = target.target_ip;
            options.active_dns_target_port = target.target_port;
            Ok(())
        }
        Ok(None) => Ok(()),
        Err(err) if options.execute_active_dns || resolve_domains => Err(err),
        Err(_) => Ok(()),
    }
}

pub(super) fn configured_active_dns_target_from_config(
    config: &Path,
    resolve_domains: bool,
) -> Result<Option<ConfiguredActiveDnsTarget>, String> {
    let config = load_config_file(config)?;
    configured_active_dns_target_from_global(&config.global.udp_check_dns, resolve_domains)
}

pub(super) fn configured_active_dns_target_from_global(
    udp_check_dns: &[String],
    resolve_domains: bool,
) -> Result<Option<ConfiguredActiveDnsTarget>, String> {
    configured_active_dns_target_from_udp_check_dns(udp_check_dns, resolve_domains)
}

fn configured_active_dns_target_from_udp_check_dns(
    values: &[String],
    resolve_domains: bool,
) -> Result<Option<ConfiguredActiveDnsTarget>, String> {
    let entries = configured_active_dns_entries(values);
    let Some((first_index, raw)) = entries
        .iter()
        .enumerate()
        .find_map(|(index, value)| (!value.is_empty()).then_some((index, value.as_str())))
    else {
        return Ok(None);
    };
    let first = match parse_udp_check_entry(raw, CONFIGURED_DNS_CHECK_DEFAULT_PORT) {
        Some(UdpCheckEntry::Ipv4(addr)) => return Ok(Some(active_dns_target_from_addr(addr))),
        Some(UdpCheckEntry::Domain { host, port }) => (host, port),
        None => return Ok(None),
    };
    for explicit in entries.iter().skip(first_index + 1) {
        if let Some(UdpCheckEntry::Ipv4(addr)) = parse_udp_check_entry(explicit, first.1) {
            return Ok(Some(active_dns_target_from_addr(addr)));
        }
    }
    if !resolve_domains {
        return Ok(None);
    }
    resolve_domain_active_dns_target(&first.0, first.1).map(Some)
}

fn configured_active_dns_entries(values: &[String]) -> Vec<String> {
    values
        .iter()
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect()
}

enum UdpCheckEntry {
    Ipv4(SocketAddrV4),
    Domain { host: String, port: u16 },
}

fn parse_udp_check_entry(raw: &str, default_port: u16) -> Option<UdpCheckEntry> {
    let raw = raw.trim();
    if let Some(ip) = ipv4_literal(raw) {
        return Some(UdpCheckEntry::Ipv4(SocketAddrV4::new(ip, default_port)));
    }
    if let Ok(addr) = raw.parse::<SocketAddr>() {
        return match addr {
            SocketAddr::V4(addr) => Some(UdpCheckEntry::Ipv4(addr)),
            SocketAddr::V6(_) => None,
        };
    }
    let (host, port) = split_optional_host_port(raw, default_port)?;
    if let Some(ip) = ipv4_literal(host) {
        return Some(UdpCheckEntry::Ipv4(SocketAddrV4::new(ip, port)));
    }
    Some(UdpCheckEntry::Domain {
        host: host.to_owned(),
        port,
    })
}

fn active_dns_target_from_addr(addr: SocketAddrV4) -> ConfiguredActiveDnsTarget {
    ConfiguredActiveDnsTarget {
        target_ip: addr.ip().to_string(),
        target_port: addr.port(),
    }
}

fn resolve_domain_active_dns_target(
    host: &str,
    port: u16,
) -> Result<ConfiguredActiveDnsTarget, String> {
    let authority = format!("{host}:{port}");
    authority
        .to_socket_addrs()
        .map_err(|err| format!("resolve global.udp_check_dns {authority}: {err}"))?
        .find_map(|addr| match addr {
            SocketAddr::V4(addr) => Some(active_dns_target_from_addr(addr)),
            SocketAddr::V6(_) => None,
        })
        .ok_or_else(|| format!("resolve global.udp_check_dns {authority}: no IPv4 address"))
}

fn split_optional_host_port(raw: &str, default_port: u16) -> Option<(&str, u16)> {
    if let Some(rest) = raw.strip_prefix('[') {
        let (host, after_host) = rest.split_once(']')?;
        let port = after_host.strip_prefix(':')?.parse::<u16>().ok()?;
        return Some((host, port));
    }
    if raw.matches(':').count() > 1 {
        return None;
    }
    match raw.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() => Some((host, port.parse::<u16>().ok()?)),
        Some(_) => None,
        None if !raw.is_empty() => Some((raw, default_port)),
        None => None,
    }
}

fn ipv4_literal(raw: &str) -> Option<Ipv4Addr> {
    raw.trim().parse::<Ipv4Addr>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONFIGURED_DNS_CHECK_PORT: u16 = 8053;

    fn configured_dns_domain() -> String {
        "localhost".to_owned()
    }

    fn configured_dns_domain_with_port() -> String {
        format!("{}:{}", configured_dns_domain(), CONFIGURED_DNS_CHECK_PORT)
    }

    fn configured_dns_address() -> Ipv4Addr {
        Ipv4Addr::LOCALHOST
    }

    fn configured_dns_address_string() -> String {
        configured_dns_address().to_string()
    }

    fn configured_dns_address_with_port() -> String {
        format!("{}:{}", configured_dns_address(), CONFIGURED_DNS_CHECK_PORT)
    }

    #[test]
    fn configured_active_dns_target_prefers_udp_check_explicit_address() {
        let target = configured_active_dns_target_from_global(
            &[
                configured_dns_domain_with_port(),
                configured_dns_address_string(),
            ],
            false,
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            target,
            ConfiguredActiveDnsTarget {
                target_ip: configured_dns_address_string(),
                target_port: CONFIGURED_DNS_CHECK_PORT,
            }
        );
    }

    #[test]
    fn configured_active_dns_target_accepts_combined_udp_check_string() {
        let target = configured_active_dns_target_from_global(
            &[format!(
                "{},{}",
                configured_dns_domain_with_port(),
                configured_dns_address_string()
            )],
            false,
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            target,
            ConfiguredActiveDnsTarget {
                target_ip: configured_dns_address_string(),
                target_port: CONFIGURED_DNS_CHECK_PORT,
            }
        );
    }

    #[test]
    fn configured_active_dns_target_accepts_combined_udp_check_address_port() {
        let target = configured_active_dns_target_from_global(
            &[format!(
                "{},{}",
                configured_dns_domain(),
                configured_dns_address_with_port()
            )],
            false,
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            target,
            ConfiguredActiveDnsTarget {
                target_ip: configured_dns_address_string(),
                target_port: CONFIGURED_DNS_CHECK_PORT,
            }
        );
    }

    #[test]
    fn configured_active_dns_target_uses_udp_check_ipv4_host() {
        let target =
            configured_active_dns_target_from_global(&[configured_dns_address_with_port()], false)
                .unwrap()
                .unwrap();
        assert_eq!(
            target,
            ConfiguredActiveDnsTarget {
                target_ip: configured_dns_address_string(),
                target_port: CONFIGURED_DNS_CHECK_PORT,
            }
        );
    }

    #[test]
    fn configured_active_dns_target_uses_bare_udp_check_ipv4_setting() {
        let target =
            configured_active_dns_target_from_global(&[configured_dns_address_string()], false)
                .unwrap()
                .unwrap();
        assert_eq!(
            target,
            ConfiguredActiveDnsTarget {
                target_ip: configured_dns_address_string(),
                target_port: CONFIGURED_DNS_CHECK_DEFAULT_PORT,
            }
        );
    }

    #[test]
    fn configured_active_dns_target_accepts_domain_only_without_inventing_ip() {
        let target =
            configured_active_dns_target_from_global(&[configured_dns_domain_with_port()], false)
                .unwrap();
        assert_eq!(
            target, None,
            "domain-only config is valid, but no synthetic IP target is invented"
        );
    }

    #[test]
    fn configured_active_dns_target_accepts_bare_domain_only_without_inventing_ip() {
        assert_eq!(
            configured_active_dns_target_from_global(&[configured_dns_domain()], false).unwrap(),
            None
        );
    }

    #[test]
    fn configured_active_dns_target_accepts_empty_config_as_no_target() {
        assert_eq!(
            configured_active_dns_target_from_global(&["".to_owned()], true).unwrap(),
            None
        );
    }
}
