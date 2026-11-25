use super::super::topology_netlink;
use super::*;
pub(crate) fn setup_production_topology(
    steps: &mut Vec<Value>,
    options: &ProductionRuntimeOwnerOptions,
) -> bool {
    setup_link_pair_with_auto_selection(
        steps,
        "production",
        PRODUCTION_HOST_IFACE,
        PRODUCTION_PEER_IFACE,
        options.netns_link_mode,
        |steps, mode| setup_production_topology_with_link_mode(steps, options, mode),
        |steps| {
            cleanup_partial_link_setup(
                steps,
                "production",
                Some(PRODUCTION_NETNS),
                PRODUCTION_HOST_IFACE,
                PRODUCTION_PEER_IFACE,
            );
        },
    )
}

pub(crate) fn setup_production_topology_with_link_mode(
    steps: &mut Vec<Value>,
    options: &ProductionRuntimeOwnerOptions,
    mode: NetnsLinkMode,
) -> bool {
    if !create_link_pair(
        steps,
        "production",
        PRODUCTION_HOST_IFACE,
        PRODUCTION_PEER_IFACE,
        mode,
    ) {
        return false;
    }
    if topology_netlink::step(steps, "create-production-netns", || {
        topology_netlink::create_namespace(PRODUCTION_NETNS)?;
        Ok(json!({"netns": PRODUCTION_NETNS}))
    })["status"]
        != "pass"
    {
        return false;
    }
    let namespace = match topology_netlink::open_namespace(PRODUCTION_NETNS) {
        Ok(namespace) => namespace,
        Err(error) => {
            topology_netlink::step(steps, "open-production-netns", || Err(error));
            return false;
        }
    };
    let assigned = topology_netlink::step(steps, "assign-production-netns-id-summary", || {
        topology_netlink::assign_namespace_id(&namespace).map(|id| {
            json!({
                "netns": PRODUCTION_NETNS,
                "configured_dae_netns_id": options.dae_netns_id,
                "effective_dae_netns_id": id,
                "strategy": "auto",
            })
        })
    });
    if assigned["status"] != "pass" {
        return false;
    }
    if topology_netlink::step(steps, "move-production-peer-into-netns", || {
        topology_netlink::move_link(PRODUCTION_PEER_IFACE, &namespace)?;
        Ok(json!({"interface": PRODUCTION_PEER_IFACE, "netns": PRODUCTION_NETNS}))
    })["status"]
        != "pass"
    {
        return false;
    }
    for (name, interface, target) in [
        ("bring-production-host-link-up", PRODUCTION_HOST_IFACE, None),
        ("bring-production-netns-loopback-up", "lo", Some(&namespace)),
        (
            "bring-production-peer-link-up",
            PRODUCTION_PEER_IFACE,
            Some(&namespace),
        ),
    ] {
        if topology_netlink::step(steps, name, || {
            topology_netlink::bring_up(interface, target)?;
            Ok(json!({"interface": interface}))
        })["status"]
            != "pass"
        {
            return false;
        }
    }
    true
}

pub(crate) fn effective_dae_netns_id(steps: &[Value], requested_dae_netns_id: u32) -> u32 {
    steps
        .iter()
        .rev()
        .find(|step| {
            step["name"].as_str() == Some("assign-production-netns-id-summary")
                && step["status"].as_str() == Some("pass")
        })
        .and_then(|step| step["detail"]["effective_dae_netns_id"].as_u64())
        .and_then(|id| u32::try_from(id).ok())
        .unwrap_or(requested_dae_netns_id)
}
