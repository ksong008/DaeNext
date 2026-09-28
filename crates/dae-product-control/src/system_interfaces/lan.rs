use std::collections::HashSet;
use std::fs;
use std::net::IpAddr;
use std::path::Path;
use std::process::Command;

use serde_json::{Value, json};

#[derive(Debug)]
struct LanCandidate {
    name: String,
    up: bool,
    addressed: bool,
    default_route: bool,
    eligible: bool,
}

pub(super) fn annotate_lan_recommendations(items: &mut [Value]) {
    let candidates = items
        .iter()
        .map(|item| {
            let name = item["name"].as_str().unwrap_or_default();
            LanCandidate {
                name: name.to_owned(),
                up: item["up"].as_bool().unwrap_or(false),
                addressed: item["addresses"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .any(is_usable_address),
                default_route: item["defaultRoutes"]
                    .as_array()
                    .is_some_and(|routes| !routes.is_empty()),
                eligible: is_lan_device(Path::new("/sys/class/net"), name),
            }
        })
        .collect::<Vec<_>>();
    let openwrt = openwrt_lan_devices();
    let names = recommended_lan_names(&candidates, openwrt.as_deref());
    for item in items {
        let recommended = names.contains(item["name"].as_str().unwrap_or_default());
        item["recommendedLan"] = json!(recommended);
    }
}

fn recommended_lan_names(
    candidates: &[LanCandidate],
    openwrt: Option<&[String]>,
) -> HashSet<String> {
    if let Some(devices) = openwrt {
        // An explicit but unavailable LAN must not turn the WAN into a LAN.
        return candidates
            .iter()
            .filter(|item| item.up && devices.contains(&item.name))
            .map(|item| item.name.clone())
            .collect();
    }
    let eligible = candidates
        .iter()
        .filter(|item| item.eligible)
        .collect::<Vec<_>>();
    if !candidates.iter().any(|item| item.default_route) {
        return HashSet::new();
    }
    let mut names = eligible
        .iter()
        .filter(|item| item.up && item.addressed && !item.default_route)
        .map(|item| item.name.clone())
        .collect::<HashSet<_>>();
    // Preserve the single-interface side-router case. Count down/unaddressed
    // interfaces too, so a router with an unavailable LAN cannot select its WAN.
    if names.is_empty() && eligible.len() == 1 {
        let item = eligible[0];
        if item.up && item.addressed && item.default_route {
            names.insert(item.name.clone());
        }
    }
    names
}

fn is_usable_address(address: &str) -> bool {
    let address = address.split('/').next().unwrap_or_default();
    match address.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => {
            !ip.is_loopback()
                && !ip.is_unspecified()
                && !ip.is_link_local()
                && !ip.is_multicast()
                && !ip.is_broadcast()
        }
        Ok(IpAddr::V6(ip)) => {
            !ip.is_loopback()
                && !ip.is_unspecified()
                && !ip.is_unicast_link_local()
                && !ip.is_multicast()
        }
        Err(_) => false,
    }
}

fn is_lan_device(sysfs: &Path, name: &str) -> bool {
    if name.is_empty()
        || name == "lo"
        || name == "dae0"
        || name == "dae0peer"
        || [
            "docker", "virbr", "veth", "lxc", "lxd", "cni", "flannel", "podman",
        ]
        .iter()
        .any(|prefix| name.starts_with(prefix))
        || name.strip_prefix("br-").is_some_and(|suffix| {
            suffix.len() == 12 && suffix.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
    {
        return false;
    }
    let path = sysfs.join(name);
    if path.join("master").exists() || path.join("tun_flags").exists() {
        return false;
    }
    // Physical NICs, bridges, bonds and VLAN L3 devices are plausible LANs;
    // virtual tunnels and unrelated virtual Ethernet devices are not.
    path.join("device").exists()
        || path.join("bridge").is_dir()
        || path.join("bonding").is_dir()
        || fs::read_to_string(path.join("uevent"))
            .is_ok_and(|text| text.lines().any(|line| line == "DEVTYPE=vlan"))
}

fn openwrt_lan_devices() -> Option<Vec<String>> {
    if !Path::new("/etc/openwrt_release").is_file() {
        return None;
    }
    if let Ok(output) = Command::new("ubus")
        .args(["-t", "2", "call", "network.interface.lan", "status"])
        .output()
        && output.status.success()
        && let Ok(status) = serde_json::from_slice::<Value>(&output.stdout)
    {
        if let Some(device) = status["l3_device"]
            .as_str()
            .or_else(|| status["device"].as_str())
            .filter(|name| !name.is_empty())
        {
            return Some(vec![device.to_owned()]);
        }
        // LAN is configured but not yet available.
        return Some(Vec::new());
    }
    for key in ["network.lan.device", "network.lan.ifname"] {
        if let Ok(output) = Command::new("uci").args(["-q", "get", key]).output()
            && output.status.success()
        {
            // Legacy bridge configurations expose member ports through ifname.
            if key.ends_with(".ifname")
                && let Ok(kind) = Command::new("uci")
                    .args(["-q", "get", "network.lan.type"])
                    .output()
                && String::from_utf8_lossy(&kind.stdout).trim() == "bridge"
            {
                return Some(vec!["br-lan".to_owned()]);
            }
            return Some(
                String::from_utf8_lossy(&output.stdout)
                    .split_whitespace()
                    .map(str::to_owned)
                    .collect(),
            );
        }
    }
    // Unknown OpenWrt topology needs an explicit choice, not a WAN fallback.
    Some(Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nic(name: &str, default_route: bool) -> LanCandidate {
        LanCandidate {
            name: name.to_owned(),
            up: true,
            addressed: true,
            default_route,
            eligible: true,
        }
    }

    #[test]
    fn router_selects_lan_instead_of_default_route_wan() {
        let items = [nic("wan", true), nic("br-lan", false)];
        assert_eq!(
            recommended_lan_names(&items, None),
            HashSet::from(["br-lan".to_owned()])
        );
    }

    #[test]
    fn single_interface_side_router_retains_its_uplink() {
        assert_eq!(
            recommended_lan_names(&[nic("eth0", true)], None),
            HashSet::from(["eth0".to_owned()])
        );
    }

    #[test]
    fn down_or_unaddressed_lan_does_not_fall_back_to_wan() {
        for (up, addressed) in [(false, true), (true, false)] {
            let mut lan = nic("eth1", false);
            lan.up = up;
            lan.addressed = addressed;
            assert!(recommended_lan_names(&[nic("eth0", true), lan], None).is_empty());
        }
    }

    #[test]
    fn multiple_wan_devices_are_not_lan_candidates() {
        assert!(recommended_lan_names(&[nic("eth0", true), nic("eth1", true)], None).is_empty());
    }

    #[test]
    fn missing_route_information_does_not_label_all_nics_as_lan() {
        assert!(recommended_lan_names(&[nic("eth0", false), nic("eth1", false)], None).is_empty());
    }

    #[test]
    fn sysfs_excludes_bridge_members_tunnels_and_container_bridges() {
        let root = std::env::temp_dir().join(format!(
            "daed-lan-topology-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        for path in [
            "eth0/device",
            "eth0/master",
            "br-lan/bridge",
            "eth1/device",
            "docker0/bridge",
            "br-012345abcdef/bridge",
            "tap0/bridge",
            "veth123",
            "wg0",
        ] {
            fs::create_dir_all(root.join(path)).unwrap();
        }
        fs::write(root.join("tap0/tun_flags"), "1").unwrap();
        for name in [
            "eth0",
            "docker0",
            "br-012345abcdef",
            "tap0",
            "veth123",
            "wg0",
            "lo",
            "dae0",
        ] {
            assert!(!is_lan_device(&root, name), "{name}");
        }
        for name in ["br-lan", "eth1"] {
            assert!(is_lan_device(&root, name), "{name}");
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn openwrt_explicit_lan_wins_even_when_it_has_the_default_route() {
        let items = [
            nic("br-lan", true),
            nic("br-guest", false),
            nic("wan", true),
        ];
        assert_eq!(
            recommended_lan_names(&items, Some(&["br-lan".to_owned()])),
            HashSet::from(["br-lan".to_owned()])
        );
        assert!(recommended_lan_names(&items, Some(&["unavailable".to_owned()])).is_empty());
        assert!(recommended_lan_names(&items, Some(&[])).is_empty());
    }

    #[test]
    fn virtual_interfaces_do_not_disrupt_single_nic_detection() {
        let mut virtual_nic = nic("docker0", false);
        virtual_nic.eligible = false;
        assert_eq!(
            recommended_lan_names(&[nic("eth0", true), virtual_nic], None),
            HashSet::from(["eth0".to_owned()])
        );
    }

    #[test]
    fn link_local_and_loopback_addresses_are_not_lan_evidence() {
        for address in [
            "127.0.0.1/8",
            "169.254.1.2/16",
            "::1/128",
            "fe80::1/64",
            "0.0.0.0",
            "224.0.0.1",
            "bad",
        ] {
            assert!(!is_usable_address(address), "{address}");
        }
        for address in [
            "192.168.1.1/24",
            "10.0.0.1/24",
            "2001:db8::1/64",
            "fd00::1/64",
        ] {
            assert!(is_usable_address(address), "{address}");
        }
    }
}
