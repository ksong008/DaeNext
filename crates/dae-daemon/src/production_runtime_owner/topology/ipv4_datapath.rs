use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::super::topology_netlink as netlink;
use super::*;

const TPROXY_MARK: u32 = 0x0800_0000;
const TPROXY_TABLE: u32 = 2023;

pub(crate) fn setup_production_ip_datapath(steps: &mut Vec<Value>, host_mac: [u8; 6]) -> bool {
    let namespace = match netlink::open_namespace(PRODUCTION_NETNS) {
        Ok(namespace) => namespace,
        Err(error) => {
            netlink::step(steps, "open-production-netns-for-routing", || Err(error));
            return false;
        }
    };
    let mut peer_steps = Vec::new();
    let peer_result = netlink::in_namespace(Some(&namespace), || {
        let mut ok = true;
        for (family, unspecified, name) in [
            (libc::AF_INET as u8, IpAddr::from(Ipv4Addr::UNSPECIFIED), ""),
            (
                libc::AF_INET6 as u8,
                IpAddr::from(Ipv6Addr::UNSPECIFIED),
                "ipv6-",
            ),
        ] {
            ok &= apply(
                &mut peer_steps,
                &format!("add-daens-{name}fwmark-rule"),
                || netlink::add_mark_rule(family, TPROXY_MARK, TPROXY_TABLE),
            );
            ok &= apply(
                &mut peer_steps,
                &format!("add-daens-{name}local-route"),
                || netlink::add_route("lo", unspecified, Some(TPROXY_TABLE), false),
            );
        }
        ok &= set_sysctl(
            &mut peer_steps,
            "set-daens-dae0peer-accept-local",
            PRODUCTION_PEER_IFACE,
            "accept_local",
            "1",
        );
        Ok(ok)
    });
    steps.append(&mut peer_steps);
    let Ok(mut ok) = peer_result else {
        netlink::step(steps, "configure-daens-policy-routing", || {
            peer_result.map(|_| Value::Null)
        });
        return false;
    };
    for (name, key, value) in [
        ("set-production-dae0-accept-local", "accept_local", "1"),
        (
            "disable-production-dae0-send-redirects",
            "send_redirects",
            "0",
        ),
        ("disable-production-dae0-rp-filter", "rp_filter", "0"),
    ] {
        ok &= set_sysctl(steps, name, PRODUCTION_HOST_IFACE, key, value);
    }

    let configured = netlink::in_namespace(Some(&namespace), || {
        for (peer, host, name) in [
            (
                IpAddr::from(Ipv4Addr::new(169, 254, 0, 11)),
                IpAddr::from(Ipv4Addr::new(169, 254, 0, 1)),
                "",
            ),
            (
                IpAddr::from(Ipv6Addr::new(0xfd00, 0x0dae, 0x2023, 0, 0, 0, 0, 0x11)),
                IpAddr::from(Ipv6Addr::new(0xfd00, 0x0dae, 0x2023, 0, 0, 0, 0, 1)),
                "ipv6-",
            ),
        ] {
            ok &= apply(
                steps,
                &format!("assign-daens-dae0peer-{name}link-ip"),
                || netlink::add_address(PRODUCTION_PEER_IFACE, peer),
            );
            ok &= apply(
                steps,
                &format!("add-daens-dae0peer-{name}link-route"),
                || netlink::add_route(PRODUCTION_PEER_IFACE, host, None, false),
            );
            ok &= apply(
                steps,
                &format!("add-daens-dae0peer-{name}default-route"),
                || netlink::add_route(PRODUCTION_PEER_IFACE, host, None, true),
            );
            ok &= apply(
                steps,
                &format!("add-daens-dae0peer-{name}host-neighbor"),
                || netlink::replace_permanent_neighbor(PRODUCTION_PEER_IFACE, host, host_mac),
            );
        }
        Ok(())
    });
    if let Err(error) = configured {
        netlink::step(steps, "configure-daens-peer-routes", || Err(error));
        ok = false;
    }
    ok
}

fn apply(
    steps: &mut Vec<Value>,
    name: &str,
    operation: impl FnOnce() -> std::io::Result<()>,
) -> bool {
    netlink::step(steps, name, || operation().map(|()| Value::Null))["status"] == "pass"
}

fn set_sysctl(steps: &mut Vec<Value>, name: &str, iface: &str, key: &str, value: &str) -> bool {
    let path = format!("/proc/sys/net/ipv4/conf/{iface}/{key}");
    let result = netlink::step(steps, name, || {
        std::fs::write(&path, value)?;
        Ok(json!({ "path": path, "value": value }))
    });
    if let Some(step) = steps.last_mut() {
        step["backend"] = json!("procfs");
    }
    result["status"] == "pass"
}
