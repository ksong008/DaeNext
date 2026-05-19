use super::utils::*;
use super::*;

pub(super) struct Stage49SmokeResult {
    pub(super) passed: bool,
    pub(super) socket_options_verified: bool,
    pub(super) discovered_map_id: Option<u32>,
    pub(super) executed_steps: Vec<Value>,
    pub(super) cleanup_steps: Vec<Value>,
    pub(super) topology_values: Value,
    pub(super) param_image: Value,
    pub(super) peer_attach_show: Value,
    pub(super) host_attach_show: Value,
    pub(super) loaded_map_handoff: Value,
}

pub(super) fn execute_stage49_smoke(
    opts: &Stage49Options,
    before_map_ids: &[u32],
) -> Stage49SmokeResult {
    let mut executed_steps = Vec::new();
    let mut cleanup_steps = Vec::new();
    let mut ok = true;

    ok &= run_step(
        &mut executed_steps,
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
        &mut executed_steps,
        "create-production-netns",
        CommandSpec::new("ip", &["netns", "add", PRODUCTION_NETNS]),
    );
    ok &= run_step(
        &mut executed_steps,
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
        &mut executed_steps,
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
        &mut executed_steps,
        "bring-production-host-link-up",
        CommandSpec::new("ip", &["link", "set", PRODUCTION_HOST_IFACE, "up"]),
    );
    ok &= run_step(
        &mut executed_steps,
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
        &mut executed_steps,
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

    let dae0_ifindex_step = run_observation_step(
        &mut executed_steps,
        "read-production-dae0-ifindex",
        CommandSpec::new(
            "cat",
            &[&format!("/sys/class/net/{PRODUCTION_HOST_IFACE}/ifindex")],
        ),
    );
    let dae0peer_mac_step = run_observation_step(
        &mut executed_steps,
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
    let dae0_ifindex = parse_step_u32(&dae0_ifindex_step);
    let dae0peer_mac = parse_step_mac(&dae0peer_mac_step);
    let topology_values = match (dae0_ifindex, dae0peer_mac) {
        (Ok(dae0_ifindex), Ok(dae0peer_mac)) => json!({
            "status": "pass",
            "dae0_ifindex": dae0_ifindex,
            "dae_netns_id": opts.dae_netns_id,
            "dae_netns_id_source": "ip netns set daens",
            "dae0peer_mac": mac_string(dae0peer_mac),
            "control_plane_pid": std::process::id(),
            "has_bpf_get_current_task": opts.has_bpf_get_current_task,
        }),
        (ifindex, mac) => {
            ok = false;
            json!({
                "status": "fail",
                "dae0_ifindex_error": ifindex.err().map(|err| err.to_string()),
                "dae0peer_mac_error": mac.err().map(|err| err.to_string()),
            })
        }
    };

    let param_image = if ok {
        let dae0_ifindex = topology_values["dae0_ifindex"].as_u64().unwrap() as u32;
        let dae0peer_mac = parse_mac(topology_values["dae0peer_mac"].as_str().unwrap())
            .expect("stage49 topology mac must parse after earlier validation");
        let param = build_dae_param(DaeParamInput {
            tproxy_port: opts.tproxy_port,
            control_plane_pid: std::process::id(),
            dae0_ifindex,
            dae_netns_id: opts.dae_netns_id,
            dae0peer_mac,
            has_bpf_get_current_task: opts.has_bpf_get_current_task,
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
            Err(err) => {
                ok = false;
                json!({
                    "status": "fail",
                    "path": path_string(&opts.param_object),
                    "error": err.to_string(),
                })
            }
        }
    } else {
        json!({
            "status": "skipped",
            "path": path_string(&opts.param_object),
            "reason": "topology runtime PARAM values were not available",
        })
    };
    ok &= param_image["status"].as_str() == Some("pass")
        && param_image["rewritten_param_matches"]
            .as_bool()
            .unwrap_or(false);

    if ok {
        let param_object = path_string(&opts.param_object);
        ok &= run_step(
            &mut executed_steps,
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
            &mut executed_steps,
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
                    STAGE49_FILTER_PREF,
                    "bpf",
                    "da",
                    "obj",
                    &param_object,
                    "sec",
                    &opts.peer_section,
                ],
            ),
        );
    }
    let peer_attach_show = run_observation_step(
        &mut executed_steps,
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
    );

    let (loaded_map_handoff, discovered_map_id, handoff_passed, socket_options_verified) = if ok {
        match run_loaded_tproxy_listen_socket_map_fd_smoke(before_map_ids, opts.tproxy_port) {
            Ok(report) => {
                let options_verified =
                    socket_options_verified(&report.tcp_options, &report.udp_options);
                (
                    json!({
                        "status": "pass",
                        "map": {
                            "id": report.map.id,
                            "name": report.map.name,
                            "map_type": report.map.map_type,
                            "key_size": report.map.key_size,
                            "value_size": report.map.value_size,
                            "max_entries": report.map.max_entries,
                            "flags": report.map.flags,
                        },
                        "new_map_ids": report.new_map_ids,
                        "keys_updated": report.keys_updated,
                        "tcp_listener_fd_observed": report.tcp_listener_fd >= 0,
                        "udp_socket_fd_observed": report.udp_socket_fd >= 0,
                        "tcp_options": {
                            "ip_transparent": report.tcp_options.ip_transparent,
                            "so_reuseaddr": report.tcp_options.so_reuseaddr,
                            "ip_recvorigdstaddr": report.tcp_options.ip_recvorigdstaddr,
                            "ipv6_recvorigdstaddr": report.tcp_options.ipv6_recvorigdstaddr,
                            "original_dst_capture_ready": report.tcp_options.original_dst_capture_ready,
                        },
                        "udp_options": {
                            "ip_transparent": report.udp_options.ip_transparent,
                            "so_reuseaddr": report.udp_options.so_reuseaddr,
                            "ip_recvorigdstaddr": report.udp_options.ip_recvorigdstaddr,
                            "ipv6_recvorigdstaddr": report.udp_options.ipv6_recvorigdstaddr,
                            "original_dst_capture_ready": report.udp_options.original_dst_capture_ready,
                        },
                    }),
                    Some(report.map.id),
                    true,
                    options_verified,
                )
            }
            Err(err) => (
                json!({
                    "status": "fail",
                    "error": err.to_string(),
                }),
                None,
                false,
                false,
            ),
        }
    } else {
        (
            json!({
                "status": "skipped",
                "reason": "PARAM-aware dae0peer attach did not pass",
            }),
            None,
            false,
            false,
        )
    };
    ok &= handoff_passed && socket_options_verified;

    if ok {
        let param_object = path_string(&opts.param_object);
        ok &= run_step(
            &mut executed_steps,
            "attach-production-host-clsact-qdisc",
            CommandSpec::new(
                "tc",
                &["qdisc", "add", "dev", PRODUCTION_HOST_IFACE, "clsact"],
            ),
        );
        ok &= run_step(
            &mut executed_steps,
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
                    STAGE49_FILTER_PREF,
                    "bpf",
                    "da",
                    "obj",
                    &param_object,
                    "sec",
                    &opts.host_section,
                ],
            ),
        );
    }
    let host_attach_show = run_observation_step(
        &mut executed_steps,
        "show-production-dae0-param-aware-ebpf-program-filter",
        CommandSpec::new(
            "tc",
            &["filter", "show", "dev", PRODUCTION_HOST_IFACE, "ingress"],
        ),
    );

    ok &= run_step(
        &mut cleanup_steps,
        "delete-production-dae0-param-aware-ebpf-program-filter",
        CommandSpec::new(
            "tc",
            &[
                "filter",
                "del",
                "dev",
                PRODUCTION_HOST_IFACE,
                "ingress",
                "pref",
                STAGE49_FILTER_PREF,
            ],
        ),
    );
    ok &= run_step(
        &mut cleanup_steps,
        "delete-production-host-clsact-qdisc",
        CommandSpec::new(
            "tc",
            &["qdisc", "del", "dev", PRODUCTION_HOST_IFACE, "clsact"],
        ),
    );
    ok &= run_step(
        &mut cleanup_steps,
        "delete-production-dae0peer-param-aware-ebpf-program-filter",
        CommandSpec::new(
            "ip",
            &[
                "netns",
                "exec",
                PRODUCTION_NETNS,
                "tc",
                "filter",
                "del",
                "dev",
                PRODUCTION_PEER_IFACE,
                "ingress",
                "pref",
                STAGE49_FILTER_PREF,
            ],
        ),
    );
    ok &= run_step(
        &mut cleanup_steps,
        "delete-production-peer-clsact-qdisc",
        CommandSpec::new(
            "ip",
            &[
                "netns",
                "exec",
                PRODUCTION_NETNS,
                "tc",
                "qdisc",
                "del",
                "dev",
                PRODUCTION_PEER_IFACE,
                "clsact",
            ],
        ),
    );
    ok &= run_step(
        &mut cleanup_steps,
        "delete-production-host-link",
        CommandSpec::new("ip", &["link", "del", PRODUCTION_HOST_IFACE]),
    );
    ok &= run_step(
        &mut cleanup_steps,
        "delete-production-netns",
        CommandSpec::new("ip", &["netns", "del", PRODUCTION_NETNS]),
    );

    let peer_output = peer_attach_show["stdout"].as_str().unwrap_or_default();
    let host_output = host_attach_show["stdout"].as_str().unwrap_or_default();
    Stage49SmokeResult {
        passed: ok
            && peer_attach_show["status"].as_str() == Some("pass")
            && peer_output.contains(&opts.peer_section)
            && peer_output.contains("tproxy_dae0peer")
            && host_attach_show["status"].as_str() == Some("pass")
            && host_output.contains(&opts.host_section)
            && host_output.contains("tproxy_dae0_ing")
            && production_resource_leftovers().is_empty(),
        socket_options_verified,
        discovered_map_id,
        executed_steps,
        cleanup_steps,
        topology_values,
        param_image,
        peer_attach_show,
        host_attach_show,
        loaded_map_handoff,
    }
}

fn socket_options_verified(
    tcp: &dae_ebpf_support::TproxySocketOptions,
    udp: &dae_ebpf_support::TproxySocketOptions,
) -> bool {
    tcp.ip_transparent
        && tcp.so_reuseaddr
        && tcp.original_dst_capture_ready
        && udp.ip_transparent
        && udp.so_reuseaddr
        && udp.original_dst_capture_ready
}
