use super::*;

pub(super) fn setup_production_ipv4_datapath(steps: &mut Vec<Value>, dae0_mac: [u8; 6]) -> bool {
    let host_mac = mac_string(dae0_mac);
    let mut ok = true;
    ok &= run_step(
        steps,
        "set-daens-dae0peer-accept-local",
        CommandSpec::new(
            "ip",
            &[
                "netns",
                "exec",
                PRODUCTION_NETNS,
                "sysctl",
                "-w",
                &format!("net.ipv4.conf.{PRODUCTION_PEER_IFACE}.accept_local=1"),
            ],
        ),
    );
    ok &= run_step(
        steps,
        "set-production-dae0-accept-local",
        CommandSpec::new(
            "sysctl",
            &[
                "-w",
                &format!("net.ipv4.conf.{PRODUCTION_HOST_IFACE}.accept_local=1"),
            ],
        ),
    );
    ok &= run_step(
        steps,
        "disable-production-dae0-send-redirects",
        CommandSpec::new(
            "sysctl",
            &[
                "-w",
                &format!("net.ipv4.conf.{PRODUCTION_HOST_IFACE}.send_redirects=0"),
            ],
        ),
    );
    ok &= run_step(
        steps,
        "disable-production-dae0-rp-filter",
        CommandSpec::new(
            "sysctl",
            &[
                "-w",
                &format!("net.ipv4.conf.{PRODUCTION_HOST_IFACE}.rp_filter=0"),
            ],
        ),
    );
    ok &= run_step(
        steps,
        "assign-daens-dae0peer-link-ip",
        CommandSpec::new(
            "ip",
            &[
                "netns",
                "exec",
                PRODUCTION_NETNS,
                "ip",
                "addr",
                "add",
                "169.254.0.11/32",
                "dev",
                PRODUCTION_PEER_IFACE,
            ],
        ),
    );
    ok &= run_step(
        steps,
        "add-daens-dae0peer-link-route",
        CommandSpec::new(
            "ip",
            &[
                "netns",
                "exec",
                PRODUCTION_NETNS,
                "ip",
                "route",
                "add",
                "169.254.0.1",
                "dev",
                PRODUCTION_PEER_IFACE,
            ],
        ),
    );
    ok &= run_step(
        steps,
        "add-daens-dae0peer-default-route",
        CommandSpec::new(
            "ip",
            &[
                "netns",
                "exec",
                PRODUCTION_NETNS,
                "ip",
                "route",
                "add",
                "default",
                "via",
                "169.254.0.1",
                "dev",
                PRODUCTION_PEER_IFACE,
            ],
        ),
    );
    ok &= run_step(
        steps,
        "add-daens-dae0peer-host-neighbor",
        CommandSpec::new(
            "ip",
            &[
                "netns",
                "exec",
                PRODUCTION_NETNS,
                "ip",
                "neigh",
                "replace",
                "169.254.0.1",
                "dev",
                PRODUCTION_PEER_IFACE,
                "lladdr",
                &host_mac,
                "nud",
                "permanent",
            ],
        ),
    );
    ok
}

pub(super) fn write_param_image(
    opts: &Stage50Options,
    dae0_ifindex: u32,
    dae0peer_mac: [u8; 6],
) -> Value {
    let param = build_dae_param(DaeParamInput {
        tproxy_port: opts.tproxy_port,
        control_plane_pid: std::process::id(),
        dae0_ifindex,
        dae_netns_id: opts.dae_netns_id,
        dae0peer_mac,
        has_bpf_get_current_task: true,
    });
    match write_param_aware_object(&opts.source_object, &opts.param_object, param) {
        Ok(report) => json!({
            "status": "pass",
            "path": path_string(&opts.param_object),
            "rewritten_param_matches": report.rewritten_param_matches,
            "previous_param_was_zero": report.previous_param_was_zero,
            "source_len": report.source_len,
            "output_len": report.output_len,
            "param": {
                "tproxy_port": param.tproxy_port,
                "control_plane_pid": param.control_plane_pid,
                "dae0_ifindex": param.dae0_ifindex,
                "dae_netns_id": param.dae_netns_id,
                "dae0peer_mac": mac_string(param.dae0peer_mac),
                "has_bpf_get_current_task": param.has_bpf_get_current_task,
            },
            "location": {
                "symbol": report.location.symbol,
                "section": report.location.section,
                "symbol_size": report.location.symbol_size,
                "file_offset": report.location.file_offset,
            },
        }),
        Err(err) => json!({
            "status": "fail",
            "path": path_string(&opts.param_object),
            "error": err.to_string(),
        }),
    }
}

pub(super) fn attach_peer_program(steps: &mut Vec<Value>, opts: &Stage50Options) -> bool {
    let param_object = path_string(&opts.param_object);
    let mut ok = true;
    ok &= run_step(
        steps,
        "attach-production-peer-clsact-qdisc",
        CommandSpec::new(
            "ip",
            &[
                "netns",
                "exec",
                PRODUCTION_NETNS,
                "tc",
                "qdisc",
                "add",
                "dev",
                PRODUCTION_PEER_IFACE,
                "clsact",
            ],
        ),
    );
    ok &= run_step(
        steps,
        "attach-production-dae0peer-param-aware-ebpf-program",
        CommandSpec::new(
            "ip",
            &[
                "netns",
                "exec",
                PRODUCTION_NETNS,
                "tc",
                "filter",
                "add",
                "dev",
                PRODUCTION_PEER_IFACE,
                "ingress",
                "pref",
                STAGE50_FILTER_PREF,
                "bpf",
                "da",
                "obj",
                &param_object,
                "sec",
                &opts.peer_section,
            ],
        ),
    );
    ok
}

pub(super) fn attach_lan_program(steps: &mut Vec<Value>, opts: &Stage50Options) -> bool {
    let param_object = path_string(&opts.param_object);
    let mut ok = true;
    ok &= run_step(
        steps,
        "attach-lan-host-clsact-qdisc",
        CommandSpec::new("tc", &["qdisc", "add", "dev", LAN_HOST_IFACE, "clsact"]),
    );
    ok &= run_step(
        steps,
        "attach-lan-ingress-param-aware-ebpf-program",
        CommandSpec::new(
            "tc",
            &[
                "filter",
                "add",
                "dev",
                LAN_HOST_IFACE,
                "ingress",
                "pref",
                STAGE50_LAN_FILTER_PREF,
                "bpf",
                "da",
                "obj",
                &param_object,
                "sec",
                &opts.lan_section,
            ],
        ),
    );
    ok
}

pub(super) fn attach_host_program(steps: &mut Vec<Value>, opts: &Stage50Options) -> bool {
    let param_object = path_string(&opts.param_object);
    let mut ok = true;
    ok &= run_step(
        steps,
        "attach-production-host-clsact-qdisc",
        CommandSpec::new(
            "tc",
            &["qdisc", "add", "dev", PRODUCTION_HOST_IFACE, "clsact"],
        ),
    );
    ok &= run_step(
        steps,
        "attach-production-dae0-param-aware-ebpf-program",
        CommandSpec::new(
            "tc",
            &[
                "filter",
                "add",
                "dev",
                PRODUCTION_HOST_IFACE,
                "ingress",
                "pref",
                STAGE50_FILTER_PREF,
                "bpf",
                "da",
                "obj",
                &param_object,
                "sec",
                &opts.host_section,
            ],
        ),
    );
    ok
}

pub(super) fn show_peer_program(steps: &mut Vec<Value>) -> Value {
    run_observation_step(
        steps,
        "show-production-dae0peer-param-aware-ebpf-program-filter",
        CommandSpec::new(
            "ip",
            &[
                "netns",
                "exec",
                PRODUCTION_NETNS,
                "tc",
                "filter",
                "show",
                "dev",
                PRODUCTION_PEER_IFACE,
                "ingress",
            ],
        ),
    )
}

pub(super) fn show_lan_program(steps: &mut Vec<Value>) -> Value {
    run_observation_step(
        steps,
        "show-lan-ingress-param-aware-ebpf-program-filter",
        CommandSpec::new("tc", &["filter", "show", "dev", LAN_HOST_IFACE, "ingress"]),
    )
}

pub(super) fn show_host_program(steps: &mut Vec<Value>) -> Value {
    run_observation_step(
        steps,
        "show-production-dae0-param-aware-ebpf-program-filter",
        CommandSpec::new(
            "tc",
            &["filter", "show", "dev", PRODUCTION_HOST_IFACE, "ingress"],
        ),
    )
}

pub(super) fn show_peer_program_stats(steps: &mut Vec<Value>) -> Value {
    run_observation_step(
        steps,
        "show-production-dae0peer-param-aware-ebpf-program-filter-stats",
        CommandSpec::new(
            "ip",
            &[
                "netns",
                "exec",
                PRODUCTION_NETNS,
                "tc",
                "-s",
                "filter",
                "show",
                "dev",
                PRODUCTION_PEER_IFACE,
                "ingress",
            ],
        ),
    )
}

pub(super) fn show_lan_program_stats(steps: &mut Vec<Value>) -> Value {
    run_observation_step(
        steps,
        "show-lan-ingress-param-aware-ebpf-program-filter-stats",
        CommandSpec::new(
            "tc",
            &["-s", "filter", "show", "dev", LAN_HOST_IFACE, "ingress"],
        ),
    )
}

pub(super) fn show_host_program_stats(steps: &mut Vec<Value>) -> Value {
    run_observation_step(
        steps,
        "show-production-dae0-param-aware-ebpf-program-filter-stats",
        CommandSpec::new(
            "tc",
            &[
                "-s",
                "filter",
                "show",
                "dev",
                PRODUCTION_HOST_IFACE,
                "ingress",
            ],
        ),
    )
}

pub(super) fn live_handoff_json(
    handoff: &dae_ebpf_support::LiveLoadedTproxyListenSocketMap,
) -> Value {
    json!({
        "status": "pass",
        "map": map_json(&handoff.map),
        "new_map_ids": handoff.new_map_ids,
        "keys_updated": handoff.keys_updated,
        "tcp_listener_fd_observed": handoff.tcp_listener_fd >= 0,
        "udp_socket_fd_observed": handoff.udp_socket_fd >= 0,
        "tcp_options": {
            "ip_transparent": handoff.tcp_options.ip_transparent,
            "so_reuseaddr": handoff.tcp_options.so_reuseaddr,
            "ip_recvorigdstaddr": handoff.tcp_options.ip_recvorigdstaddr,
            "ipv6_recvorigdstaddr": handoff.tcp_options.ipv6_recvorigdstaddr,
            "original_dst_capture_ready": handoff.tcp_options.original_dst_capture_ready,
        },
        "udp_options": {
            "ip_transparent": handoff.udp_options.ip_transparent,
            "so_reuseaddr": handoff.udp_options.so_reuseaddr,
            "ip_recvorigdstaddr": handoff.udp_options.ip_recvorigdstaddr,
            "ipv6_recvorigdstaddr": handoff.udp_options.ipv6_recvorigdstaddr,
            "original_dst_capture_ready": handoff.udp_options.original_dst_capture_ready,
        },
    })
}

pub(super) fn update_stage50_routing_map(
    before_map_ids: &[u32],
    so_mark: u32,
) -> Result<(Value, u32), String> {
    let (fd, info, new_map_ids) =
        open_unique_new_map(before_map_ids, ROUTING_MAP_KERNEL_NAME, 4, 24)
            .map_err(|err| err.to_string())?;
    let key = 0_u32.to_ne_bytes();
    let value = fallback_match_set_value(OUTBOUND_STAGE50_PROXY, so_mark);
    update_map_elem_bytes(fd.as_raw_fd(), &key, &value).map_err(|err| err.to_string())?;
    Ok((
        json!({
            "status": "pass",
            "map": map_json(&info),
            "new_map_ids": new_map_ids,
            "key": 0,
            "match_type": "Fallback",
            "match_type_value": MATCH_TYPE_FALLBACK,
            "outbound": OUTBOUND_STAGE50_PROXY,
            "mark": so_mark,
            "must": false,
        }),
        info.id,
    ))
}

pub(super) fn fallback_match_set_value(outbound: u8, mark: u32) -> [u8; 24] {
    let mut value = [0_u8; 24];
    value[17] = MATCH_TYPE_FALLBACK;
    value[18] = outbound;
    value[20..24].copy_from_slice(&mark.to_ne_bytes());
    value
}

pub(super) fn open_unique_new_map(
    before_map_ids: &[u32],
    name: &str,
    key_size: u32,
    value_size: u32,
) -> std::io::Result<(OwnedFd, RuntimeMapInfo, Vec<u32>)> {
    let current = map_ids()?;
    let new_map_ids = current
        .iter()
        .copied()
        .filter(|id| !before_map_ids.contains(id))
        .collect::<Vec<_>>();
    let mut candidates = Vec::new();
    for id in &new_map_ids {
        let fd = open_map_fd(*id)?;
        let info = map_info(fd.as_raw_fd())?;
        if info.name == name && info.key_size == key_size && info.value_size == value_size {
            candidates.push((fd, info));
        }
    }
    if candidates.len() != 1 {
        return Err(std::io::Error::other(format!(
            "expected exactly one new map {name}, found {}",
            candidates.len()
        )));
    }
    let (fd, info) = candidates.remove(0);
    Ok((fd, info, new_map_ids))
}
