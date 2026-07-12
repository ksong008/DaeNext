use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

use super::{DefaultRouteFingerprint, InterfaceAddressFingerprint, NetworkFamily};

const IPV6_ADDRESS_UNSTABLE_FLAGS: u32 =
    libc::IFA_F_TEMPORARY | libc::IFA_F_DADFAILED | libc::IFA_F_DEPRECATED | libc::IFA_F_TENTATIVE;

pub(super) fn read_optional_proc_file(path: &Path) -> io::Result<String> {
    match fs::read_to_string(path) {
        Ok(content) => Ok(content),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(String::new()),
        Err(err) => Err(err),
    }
}

pub(super) fn parse_ipv4_default_routes(
    input: &str,
) -> Result<Vec<DefaultRouteFingerprint>, String> {
    let mut routes = Vec::new();
    for (line_index, line) in input.lines().enumerate() {
        if line_index == 0 || line.trim().is_empty() {
            continue;
        }
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() < 8 {
            return Err(format!("line {} has fewer than 8 fields", line_index + 1));
        }
        if fields[1] != "00000000" || fields[7] != "00000000" {
            continue;
        }
        let flags = parse_hex_u32(fields[3], "IPv4 route flags")?;
        if !route_is_usable(flags) {
            continue;
        }
        let gateway = ipv4_from_proc_hex(fields[2])?;
        let metric = fields[6]
            .parse::<u32>()
            .map_err(|err| format!("invalid IPv4 route metric {:?}: {err}", fields[6]))?;
        routes.push(DefaultRouteFingerprint {
            family: NetworkFamily::Ipv4,
            interface: fields[0].to_owned(),
            gateway: IpAddr::V4(gateway),
            metric,
        });
    }
    Ok(routes)
}

pub(super) fn parse_ipv6_default_routes(
    input: &str,
) -> Result<Vec<DefaultRouteFingerprint>, String> {
    let mut routes = Vec::new();
    for (line_index, line) in input.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() < 10 {
            return Err(format!("line {} has fewer than 10 fields", line_index + 1));
        }
        if fields[0] != "00000000000000000000000000000000" || fields[1] != "00" {
            continue;
        }
        let flags = parse_hex_u32(fields[8], "IPv6 route flags")?;
        if !route_is_usable(flags) {
            continue;
        }
        let gateway = ipv6_from_proc_hex(fields[4])?;
        let metric = parse_hex_u32(fields[5], "IPv6 route metric")?;
        routes.push(DefaultRouteFingerprint {
            family: NetworkFamily::Ipv6,
            interface: fields[9].to_owned(),
            gateway: IpAddr::V6(gateway),
            metric,
        });
    }
    Ok(routes)
}

pub(super) fn parse_ipv6_interface_addresses(
    input: &str,
    wanted_ifaces: &BTreeSet<String>,
) -> Result<BTreeMap<String, Vec<InterfaceAddressFingerprint>>, String> {
    let mut addresses = BTreeMap::<String, Vec<InterfaceAddressFingerprint>>::new();
    for (line_index, line) in input.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() < 6 {
            return Err(format!("line {} has fewer than 6 fields", line_index + 1));
        }
        let iface = fields[5];
        if !wanted_ifaces.contains(iface) {
            continue;
        }
        let flags = parse_hex_u32(fields[4], "IPv6 address flags")?;
        if flags & IPV6_ADDRESS_UNSTABLE_FLAGS != 0 {
            continue;
        }
        let address = ipv6_from_proc_hex(fields[0])?;
        if address.is_unspecified() || address.is_loopback() {
            continue;
        }
        let prefix_len = u8::from_str_radix(fields[2], 16)
            .map_err(|err| format!("invalid IPv6 prefix length {:?}: {err}", fields[2]))?;
        if prefix_len > 128 {
            return Err(format!(
                "invalid IPv6 prefix length {prefix_len}, want 0..=128"
            ));
        }
        let scope = u8::from_str_radix(fields[3], 16)
            .map_err(|err| format!("invalid IPv6 scope {:?}: {err}", fields[3]))?;
        addresses
            .entry(iface.to_owned())
            .or_default()
            .push(InterfaceAddressFingerprint {
                family: NetworkFamily::Ipv6,
                address: IpAddr::V6(address),
                prefix_len,
                peer: None,
                scope,
            });
    }
    Ok(addresses)
}

fn route_is_usable(flags: u32) -> bool {
    flags & libc::RTF_UP as u32 != 0 && flags & libc::RTF_REJECT as u32 == 0
}

fn ipv4_from_proc_hex(raw: &str) -> Result<Ipv4Addr, String> {
    let value = parse_hex_u32(raw, "IPv4 address")?;
    Ok(Ipv4Addr::from(value.to_le_bytes()))
}

fn ipv6_from_proc_hex(raw: &str) -> Result<Ipv6Addr, String> {
    if raw.len() != 32 {
        return Err(format!("invalid IPv6 hex length {}, want 32", raw.len()));
    }
    let mut bytes = [0_u8; 16];
    for (index, byte) in bytes.iter_mut().enumerate() {
        let start = index * 2;
        *byte = u8::from_str_radix(&raw[start..start + 2], 16)
            .map_err(|err| format!("invalid IPv6 address {raw:?}: {err}"))?;
    }
    Ok(Ipv6Addr::from(bytes))
}

fn parse_hex_u32(raw: &str, label: &str) -> Result<u32, String> {
    u32::from_str_radix(raw, 16).map_err(|err| format!("invalid {label} {raw:?}: {err}"))
}
