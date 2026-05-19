use super::utils::*;
use super::*;

pub(super) struct Stage38SmokeResult {
    pub(super) passed: bool,
    pub(super) discovered_map_id: Option<u32>,
    pub(super) executed_steps: Vec<Value>,
    pub(super) cleanup_steps: Vec<Value>,
    pub(super) peer_attach_show: Value,
    pub(super) host_attach_show: Value,
    pub(super) loaded_map_handoff: Value,
}

pub(super) fn execute_stage38_smoke(
    opts: &Stage38Options,
    before_map_ids: &[u32],
) -> Stage38SmokeResult {
    let mut executed_steps = Vec::new();
    let mut cleanup_steps = Vec::new();
    let mut ok = true;
    let object_path = path_string(&opts.object_path);

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
        "attach-production-dae0peer-ebpf-program",
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
                STAGE38_FILTER_PREF,
                "bpf",
                "da",
                "obj",
                &object_path,
                "sec",
                &opts.peer_section,
            ],
        ),
    );
    let peer_attach_show = run_observation_step(
        &mut executed_steps,
        "show-production-dae0peer-ebpf-program-filter",
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
    let (loaded_map_handoff, discovered_map_id, handoff_passed) =
        match run_loaded_listen_socket_map_fd_smoke(before_map_ids) {
            Ok(report) => (
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
                }),
                Some(report.map.id),
                true,
            ),
            Err(err) => (
                json!({
                    "status": "fail",
                    "error": err.to_string(),
                }),
                None,
                false,
            ),
        };
    ok &= handoff_passed;
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
        "attach-production-dae0-ebpf-program",
        CommandSpec::new(
            "tc",
            &[
                "filter",
                "add",
                "dev",
                PRODUCTION_HOST_IFACE,
                "ingress",
                "pref",
                STAGE38_FILTER_PREF,
                "bpf",
                "da",
                "obj",
                &object_path,
                "sec",
                &opts.host_section,
            ],
        ),
    );
    let host_attach_show = run_observation_step(
        &mut executed_steps,
        "show-production-dae0-ebpf-program-filter",
        CommandSpec::new(
            "tc",
            &["filter", "show", "dev", PRODUCTION_HOST_IFACE, "ingress"],
        ),
    );
    ok &= run_step(
        &mut cleanup_steps,
        "delete-production-dae0-ebpf-program-filter",
        CommandSpec::new(
            "tc",
            &[
                "filter",
                "del",
                "dev",
                PRODUCTION_HOST_IFACE,
                "ingress",
                "pref",
                STAGE38_FILTER_PREF,
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
        "delete-production-dae0peer-ebpf-program-filter",
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
                STAGE38_FILTER_PREF,
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
    Stage38SmokeResult {
        passed: ok
            && peer_attach_show["status"].as_str() == Some("pass")
            && peer_output.contains(&opts.peer_section)
            && peer_output.contains("tproxy_dae0peer")
            && host_attach_show["status"].as_str() == Some("pass")
            && host_output.contains(&opts.host_section)
            && host_output.contains("tproxy_dae0_ing")
            && production_resource_leftovers().is_empty(),
        discovered_map_id,
        executed_steps,
        cleanup_steps,
        peer_attach_show,
        host_attach_show,
        loaded_map_handoff,
    }
}
