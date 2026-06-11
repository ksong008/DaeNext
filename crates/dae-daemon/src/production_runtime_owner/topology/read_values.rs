use super::*;
pub(crate) fn read_topology_values(
    steps: &mut Vec<Value>,
    options: &ProductionRuntimeOwnerOptions,
) -> (Value, Option<u32>, Option<[u8; 6]>, Option<[u8; 6]>, u32) {
    let dae_netns_id = effective_dae_netns_id(steps, options.dae_netns_id);
    let dae0_link_detail_step = run_observation_step(
        steps,
        "read-production-dae0-link-detail",
        CommandSpec::new("ip", ["-d", "link", "show", "dev", PRODUCTION_HOST_IFACE]),
    );
    let dae0peer_link_detail_step = run_observation_step(
        steps,
        "read-production-dae0peer-link-detail",
        CommandSpec::new(
            "ip",
            [
                "netns",
                "exec",
                PRODUCTION_NETNS,
                "ip",
                "-d",
                "link",
                "show",
                "dev",
                PRODUCTION_PEER_IFACE,
            ],
        ),
    );
    let dae0_ifindex_step = run_observation_step(
        steps,
        "read-production-dae0-ifindex",
        CommandSpec::new(
            "cat",
            [format!("/sys/class/net/{PRODUCTION_HOST_IFACE}/ifindex")],
        ),
    );
    let dae0_mac_step = run_observation_step(
        steps,
        "read-production-dae0-mac",
        CommandSpec::new(
            "cat",
            [format!("/sys/class/net/{PRODUCTION_HOST_IFACE}/address")],
        ),
    );
    let dae0peer_mac_step = run_observation_step(
        steps,
        "read-production-dae0peer-mac",
        CommandSpec::new(
            "ip",
            [
                "netns".to_owned(),
                "exec".to_owned(),
                PRODUCTION_NETNS.to_owned(),
                "cat".to_owned(),
                format!("/sys/class/net/{PRODUCTION_PEER_IFACE}/address"),
            ],
        ),
    );
    let dae0_ifindex = parse_step_u32(&dae0_ifindex_step).ok();
    let dae0_mac = parse_step_mac(&dae0_mac_step).ok();
    let dae0peer_mac = parse_step_mac(&dae0peer_mac_step).ok();
    let dae0_link_kind = parse_link_kind(&dae0_link_detail_step);
    let dae0peer_link_kind = parse_link_kind(&dae0peer_link_detail_step);
    let value = match (dae0_ifindex, dae0_mac, dae0peer_mac) {
        (Some(dae0_ifindex), Some(dae0_mac), Some(dae0peer_mac)) => json!({
            "status": "pass",
            "netns_link_env": netns_link_env_name(),
            "requested_netns_link_mode": options.netns_link_mode.as_str(),
            "production_host_link_kind": dae0_link_kind,
            "production_peer_link_kind": dae0peer_link_kind,
            "dae0_ifindex": dae0_ifindex,
            "requested_dae_netns_id": options.dae_netns_id,
            "dae_netns_id": dae_netns_id,
            "dae_netns_id_source": "ip netns set daens",
            "dae0_mac": mac_string(dae0_mac),
            "dae0peer_mac": mac_string(dae0peer_mac),
            "control_plane_pid": std::process::id(),
            "has_bpf_get_current_task": true,
        }),
        _ => json!({
            "status": "fail",
            "netns_link_env": netns_link_env_name(),
            "requested_netns_link_mode": options.netns_link_mode.as_str(),
            "production_host_link_kind": dae0_link_kind,
            "production_peer_link_kind": dae0peer_link_kind,
            "requested_dae_netns_id": options.dae_netns_id,
            "dae_netns_id": dae_netns_id,
            "dae0_ifindex_error": parse_step_u32(&dae0_ifindex_step).err(),
            "dae0_mac_error": parse_step_mac(&dae0_mac_step).err(),
            "dae0peer_mac_error": parse_step_mac(&dae0peer_mac_step).err(),
        }),
    };
    (value, dae0_ifindex, dae0_mac, dae0peer_mac, dae_netns_id)
}

pub(crate) fn parse_link_kind(step: &Value) -> Option<&'static str> {
    if step["status"].as_str() != Some("pass") {
        return None;
    }
    let stdout = step["stdout"].as_str().unwrap_or_default();
    if stdout.contains(" netkit ") || stdout.contains("\n    netkit ") {
        Some("netkit")
    } else if stdout.contains(" veth ") || stdout.contains("\n    veth ") {
        Some("veth")
    } else {
        None
    }
}
