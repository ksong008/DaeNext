use super::*;

pub(super) fn setup_production_topology(steps: &mut Vec<Value>, opts: &Stage50Options) -> bool {
    let mut ok = true;
    ok &= run_step(
        steps,
        "create-production-veth-pair",
        CommandSpec::new(
            "ip",
            &[
                "link",
                "add",
                PRODUCTION_HOST_IFACE,
                "type",
                "veth",
                "peer",
                "name",
                PRODUCTION_PEER_IFACE,
            ],
        ),
    );
    ok &= run_step(
        steps,
        "create-production-netns",
        CommandSpec::new("ip", &["netns", "add", PRODUCTION_NETNS]),
    );
    ok &= run_step(
        steps,
        "assign-production-netns-id",
        CommandSpec::new(
            "ip",
            &[
                "netns",
                "set",
                PRODUCTION_NETNS,
                &opts.dae_netns_id.to_string(),
            ],
        ),
    );
    ok &= run_step(
        steps,
        "move-production-peer-into-netns",
        CommandSpec::new(
            "ip",
            &[
                "link",
                "set",
                PRODUCTION_PEER_IFACE,
                "netns",
                PRODUCTION_NETNS,
            ],
        ),
    );
    ok &= run_step(
        steps,
        "bring-production-host-link-up",
        CommandSpec::new("ip", &["link", "set", PRODUCTION_HOST_IFACE, "up"]),
    );
    ok &= run_step(
        steps,
        "bring-production-netns-loopback-up",
        CommandSpec::new(
            "ip",
            &[
                "netns",
                "exec",
                PRODUCTION_NETNS,
                "ip",
                "link",
                "set",
                "lo",
                "up",
            ],
        ),
    );
    ok &= run_step(
        steps,
        "bring-production-peer-link-up",
        CommandSpec::new(
            "ip",
            &[
                "netns",
                "exec",
                PRODUCTION_NETNS,
                "ip",
                "link",
                "set",
                PRODUCTION_PEER_IFACE,
                "up",
            ],
        ),
    );
    ok &= run_step(
        steps,
        "add-daens-fwmark-rule",
        CommandSpec::new(
            "ip",
            &[
                "netns",
                "exec",
                PRODUCTION_NETNS,
                "ip",
                "rule",
                "add",
                "fwmark",
                "0x8000000/0x8000000",
                "table",
                "2023",
            ],
        ),
    );
    ok &= run_step(
        steps,
        "add-daens-local-route",
        CommandSpec::new(
            "ip",
            &[
                "netns",
                "exec",
                PRODUCTION_NETNS,
                "ip",
                "route",
                "add",
                "local",
                "default",
                "dev",
                "lo",
                "table",
                "2023",
            ],
        ),
    );
    ok
}

pub(super) fn add_stage53_loopback_target(steps: &mut Vec<Value>, opts: &Stage50Options) -> bool {
    run_step(
        steps,
        "add-stage53-temporary-loopback-upstream-address",
        CommandSpec::new(
            "ip",
            &[
                "addr",
                "add",
                &format!("{}/32", opts.target_ip),
                "dev",
                "lo",
            ],
        ),
    )
}

pub(super) fn delete_stage53_loopback_target(
    cleanup_steps: &mut Vec<Value>,
    opts: &Stage50Options,
) {
    run_cleanup_step(
        cleanup_steps,
        "delete-stage53-temporary-loopback-upstream-address",
        CommandSpec::new(
            "ip",
            &[
                "addr",
                "del",
                &format!("{}/32", opts.target_ip),
                "dev",
                "lo",
            ],
        ),
    );
}

pub(super) fn stage53_loopback_target_present(target_ip: &str) -> bool {
    Command::new("ip")
        .args(["addr", "show", "dev", "lo"])
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .is_some_and(|stdout| stdout.contains(target_ip))
}

pub(super) fn setup_client_topology(steps: &mut Vec<Value>, opts: &Stage50Options) -> bool {
    let mut ok = true;
    ok &= run_step(
        steps,
        "create-client-netns",
        CommandSpec::new("ip", &["netns", "add", CLIENT_NETNS]),
    );
    ok &= run_step(
        steps,
        "create-lan-veth-pair",
        CommandSpec::new(
            "ip",
            &[
                "link",
                "add",
                LAN_HOST_IFACE,
                "type",
                "veth",
                "peer",
                "name",
                LAN_CLIENT_IFACE,
            ],
        ),
    );
    ok &= run_step(
        steps,
        "move-lan-client-into-netns",
        CommandSpec::new(
            "ip",
            &["link", "set", LAN_CLIENT_IFACE, "netns", CLIENT_NETNS],
        ),
    );
    ok &= run_step(
        steps,
        "assign-lan-host-ip",
        CommandSpec::new(
            "ip",
            &[
                "addr",
                "add",
                &format!("{DEFAULT_STAGE50_LAN_GATEWAY_IP}/24"),
                "dev",
                LAN_HOST_IFACE,
            ],
        ),
    );
    ok &= run_step(
        steps,
        "bring-lan-host-link-up",
        CommandSpec::new("ip", &["link", "set", LAN_HOST_IFACE, "up"]),
    );
    ok &= run_step(
        steps,
        "disable-lan-host-send-redirects",
        CommandSpec::new(
            "sysctl",
            &[
                "-w",
                &format!("net.ipv4.conf.{LAN_HOST_IFACE}.send_redirects=0"),
            ],
        ),
    );
    ok &= run_step(
        steps,
        "disable-lan-host-rp-filter",
        CommandSpec::new(
            "sysctl",
            &["-w", &format!("net.ipv4.conf.{LAN_HOST_IFACE}.rp_filter=0")],
        ),
    );
    ok &= run_step(
        steps,
        "bring-client-loopback-up",
        CommandSpec::new(
            "ip",
            &[
                "netns",
                "exec",
                CLIENT_NETNS,
                "ip",
                "link",
                "set",
                "lo",
                "up",
            ],
        ),
    );
    ok &= run_step(
        steps,
        "assign-lan-client-ip",
        CommandSpec::new(
            "ip",
            &[
                "netns",
                "exec",
                CLIENT_NETNS,
                "ip",
                "addr",
                "add",
                &format!("{}/24", opts.client_ip),
                "dev",
                LAN_CLIENT_IFACE,
            ],
        ),
    );
    ok &= run_step(
        steps,
        "bring-lan-client-link-up",
        CommandSpec::new(
            "ip",
            &[
                "netns",
                "exec",
                CLIENT_NETNS,
                "ip",
                "link",
                "set",
                LAN_CLIENT_IFACE,
                "up",
            ],
        ),
    );
    ok &= run_step(
        steps,
        "add-client-default-route-via-lan-gateway",
        CommandSpec::new(
            "ip",
            &[
                "netns",
                "exec",
                CLIENT_NETNS,
                "ip",
                "route",
                "add",
                "default",
                "via",
                DEFAULT_STAGE50_LAN_GATEWAY_IP,
                "dev",
                LAN_CLIENT_IFACE,
            ],
        ),
    );
    ok
}

pub(super) fn read_topology_values(
    steps: &mut Vec<Value>,
    opts: &Stage50Options,
) -> (Value, Option<u32>, Option<[u8; 6]>, Option<[u8; 6]>) {
    let dae0_ifindex_step = run_observation_step(
        steps,
        "read-production-dae0-ifindex",
        CommandSpec::new(
            "cat",
            &[&format!("/sys/class/net/{PRODUCTION_HOST_IFACE}/ifindex")],
        ),
    );
    let dae0_mac_step = run_observation_step(
        steps,
        "read-production-dae0-mac",
        CommandSpec::new(
            "cat",
            &[&format!("/sys/class/net/{PRODUCTION_HOST_IFACE}/address")],
        ),
    );
    let dae0peer_mac_step = run_observation_step(
        steps,
        "read-production-dae0peer-mac",
        CommandSpec::new(
            "ip",
            &[
                "netns",
                "exec",
                PRODUCTION_NETNS,
                "cat",
                &format!("/sys/class/net/{PRODUCTION_PEER_IFACE}/address"),
            ],
        ),
    );
    let dae0_ifindex = parse_step_u32(&dae0_ifindex_step).ok();
    let dae0_mac = parse_step_mac(&dae0_mac_step).ok();
    let dae0peer_mac = parse_step_mac(&dae0peer_mac_step).ok();
    let value = match (dae0_ifindex, dae0_mac, dae0peer_mac) {
        (Some(dae0_ifindex), Some(dae0_mac), Some(dae0peer_mac)) => json!({
            "status": "pass",
            "dae0_ifindex": dae0_ifindex,
            "dae_netns_id": opts.dae_netns_id,
            "dae0_mac": mac_string(dae0_mac),
            "dae0peer_mac": mac_string(dae0peer_mac),
            "control_plane_pid": std::process::id(),
        }),
        _ => json!({
            "status": "fail",
            "dae0_ifindex_step": dae0_ifindex_step,
            "dae0_mac_step": dae0_mac_step,
            "dae0peer_mac_step": dae0peer_mac_step,
        }),
    };
    (value, dae0_ifindex, dae0_mac, dae0peer_mac)
}
