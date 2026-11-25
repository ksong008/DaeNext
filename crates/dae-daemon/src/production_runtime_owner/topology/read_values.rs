use super::super::topology_netlink;
use super::*;

pub(crate) type TopologyValues = (Value, Option<u32>, Option<[u8; 6]>, Option<[u8; 6]>, u32);

pub(crate) fn read_topology_values(
    steps: &mut Vec<Value>,
    options: &ProductionRuntimeOwnerOptions,
) -> TopologyValues {
    let dae_netns_id = effective_dae_netns_id(steps, options.dae_netns_id);
    let mut host = None;
    let host_step = topology_netlink::step(steps, "read-production-dae0-link-detail", || {
        let link = topology_netlink::read_link(PRODUCTION_HOST_IFACE, None)?;
        let detail =
            json!({"ifindex": link.index, "address": mac_string(link.mac), "kind": link.kind});
        host = Some(link);
        Ok(detail)
    });
    let mut peer = None;
    let peer_step = topology_netlink::step(steps, "read-production-dae0peer-link-detail", || {
        let namespace = topology_netlink::open_namespace(PRODUCTION_NETNS)?;
        let link = topology_netlink::read_link(PRODUCTION_PEER_IFACE, Some(&namespace))?;
        let detail =
            json!({"ifindex": link.index, "address": mac_string(link.mac), "kind": link.kind});
        peer = Some(link);
        Ok(detail)
    });
    let dae0_ifindex = host.as_ref().map(|link| link.index);
    let dae0_mac = host.as_ref().map(|link| link.mac);
    let dae0peer_mac = peer.as_ref().map(|link| link.mac);
    let value = json!({
        "status": if host.is_some() && peer.is_some() { "pass" } else { "fail" },
        "netns_link_env": netns_link_env_name(),
        "requested_netns_link_mode": options.netns_link_mode.as_str(),
        "production_host_link_kind": host.as_ref().and_then(|link| link.kind.as_deref()),
        "production_peer_link_kind": peer.as_ref().and_then(|link| link.kind.as_deref()),
        "dae0_ifindex": dae0_ifindex,
        "requested_dae_netns_id": options.dae_netns_id,
        "dae_netns_id": dae_netns_id,
        "dae_netns_id_source": "rtnetlink RTM_GETNSID by namespace FD",
        "dae0_mac": dae0_mac.map(mac_string),
        "dae0peer_mac": dae0peer_mac.map(mac_string),
        "dae0_ifindex_error": host_step["stderr"],
        "dae0_mac_error": host_step["stderr"],
        "dae0peer_mac_error": peer_step["stderr"],
        "control_plane_pid": std::process::id(),
        "has_bpf_get_current_task": false,
    });
    (value, dae0_ifindex, dae0_mac, dae0peer_mac, dae_netns_id)
}
