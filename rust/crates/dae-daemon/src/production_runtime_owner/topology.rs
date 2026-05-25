use std::path::Path;

use dae_ebpf_support::{
    DaeParamInput, TcAttachDirection, TcAttachTarget, TcBpfAttachSpec, TcCommandSpec,
    build_dae_param, write_param_aware_object,
};
use serde_json::{Value, json};

use super::command::{
    CommandSpec, command_exists, iface_exists, mac_string, netns_exists, parse_step_mac,
    parse_step_u32, path_string, push_check, run_observation_step, run_step, tproxy_port_available,
};
use super::{
    FILTER_PREF, PRODUCTION_HOST_IFACE, PRODUCTION_NETNS, PRODUCTION_PEER_IFACE,
    ProductionRuntimeOwnerOptions,
};

pub(super) fn setup_production_topology(
    steps: &mut Vec<Value>,
    options: &ProductionRuntimeOwnerOptions,
) -> bool {
    let mut ok = true;
    ok &= run_step(
        steps,
        "create-production-veth-pair",
        CommandSpec::new(
            "ip",
            [
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
        CommandSpec::new("ip", ["netns", "add", PRODUCTION_NETNS]),
    );
    ok &= run_step(
        steps,
        "assign-production-netns-id",
        CommandSpec::new(
            "ip",
            [
                "netns",
                "set",
                PRODUCTION_NETNS,
                &options.dae_netns_id.to_string(),
            ],
        ),
    );
    ok &= run_step(
        steps,
        "move-production-peer-into-netns",
        CommandSpec::new(
            "ip",
            [
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
        CommandSpec::new("ip", ["link", "set", PRODUCTION_HOST_IFACE, "up"]),
    );
    ok &= run_step(
        steps,
        "bring-production-netns-loopback-up",
        CommandSpec::new(
            "ip",
            [
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
            [
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
    ok
}

pub(super) fn read_topology_values(
    steps: &mut Vec<Value>,
    options: &ProductionRuntimeOwnerOptions,
) -> (Value, Option<u32>, Option<[u8; 6]>, Option<[u8; 6]>) {
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
    let value = match (dae0_ifindex, dae0_mac, dae0peer_mac) {
        (Some(dae0_ifindex), Some(dae0_mac), Some(dae0peer_mac)) => json!({
            "status": "pass",
            "dae0_ifindex": dae0_ifindex,
            "dae_netns_id": options.dae_netns_id,
            "dae_netns_id_source": "ip netns set daens",
            "dae0_mac": mac_string(dae0_mac),
            "dae0peer_mac": mac_string(dae0peer_mac),
            "control_plane_pid": std::process::id(),
            "has_bpf_get_current_task": true,
        }),
        _ => json!({
            "status": "fail",
            "dae0_ifindex_error": parse_step_u32(&dae0_ifindex_step).err(),
            "dae0_mac_error": parse_step_mac(&dae0_mac_step).err(),
            "dae0peer_mac_error": parse_step_mac(&dae0peer_mac_step).err(),
        }),
    };
    (value, dae0_ifindex, dae0_mac, dae0peer_mac)
}

pub(super) fn write_param_image(
    options: &ProductionRuntimeOwnerOptions,
    param_object: &Path,
    dae0_ifindex: u32,
    dae0peer_mac: [u8; 6],
) -> Value {
    let param = build_dae_param(DaeParamInput {
        tproxy_port: options.tproxy_port,
        control_plane_pid: std::process::id(),
        dae0_ifindex,
        dae_netns_id: options.dae_netns_id,
        dae0peer_mac,
        has_bpf_get_current_task: true,
    });
    match write_param_aware_object(&options.source_object, param_object, param) {
        Ok(report) => json!({
            "status": "pass",
            "path": path_string(param_object),
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
            "path": path_string(param_object),
            "error": err.to_string(),
        }),
    }
}

pub(super) fn attach_peer_program(
    steps: &mut Vec<Value>,
    options: &ProductionRuntimeOwnerOptions,
    param_object: &Path,
) -> bool {
    let param_object = path_string(param_object);
    let target = production_peer_attach_target();
    let attach = TcBpfAttachSpec::new(
        target.clone(),
        FILTER_PREF,
        param_object,
        options.peer_section.clone(),
    );
    let mut ok = true;
    ok &= run_step(
        steps,
        "attach-production-peer-clsact-qdisc",
        command_spec(target.clsact_qdisc_add_command()),
    );
    ok &= run_step(
        steps,
        "attach-production-dae0peer-param-aware-ebpf-program",
        command_spec(attach.filter_add_command()),
    );
    ok
}

pub(super) fn attach_host_program(
    steps: &mut Vec<Value>,
    options: &ProductionRuntimeOwnerOptions,
    param_object: &Path,
) -> bool {
    let param_object = path_string(param_object);
    let target = production_host_attach_target();
    let attach = TcBpfAttachSpec::new(
        target.clone(),
        FILTER_PREF,
        param_object,
        options.host_section.clone(),
    );
    let mut ok = true;
    ok &= run_step(
        steps,
        "attach-production-host-clsact-qdisc",
        command_spec(target.clsact_qdisc_add_command()),
    );
    ok &= run_step(
        steps,
        "attach-production-dae0-param-aware-ebpf-program",
        command_spec(attach.filter_add_command()),
    );
    ok
}

pub(super) fn show_peer_program(steps: &mut Vec<Value>) -> Value {
    run_observation_step(
        steps,
        "show-production-dae0peer-param-aware-ebpf-program-filter",
        command_spec(production_peer_attach_target().filter_show_command(false)),
    )
}

pub(super) fn show_host_program(steps: &mut Vec<Value>) -> Value {
    run_observation_step(
        steps,
        "show-production-dae0-param-aware-ebpf-program-filter",
        command_spec(production_host_attach_target().filter_show_command(false)),
    )
}

pub(super) fn cleanup_production_topology(steps: &mut Vec<Value>) {
    let cleanup = [
        (
            "delete-production-dae0-param-aware-ebpf-program-filter",
            command_spec(production_host_attach_target().filter_del_command(FILTER_PREF)),
        ),
        (
            "delete-production-host-clsact-qdisc",
            command_spec(production_host_attach_target().clsact_qdisc_del_command()),
        ),
        (
            "delete-production-dae0peer-param-aware-ebpf-program-filter",
            command_spec(production_peer_attach_target().filter_del_command(FILTER_PREF)),
        ),
        (
            "delete-production-peer-clsact-qdisc",
            command_spec(production_peer_attach_target().clsact_qdisc_del_command()),
        ),
        (
            "delete-production-host-link",
            CommandSpec::new("ip", ["link", "del", PRODUCTION_HOST_IFACE]),
        ),
        (
            "delete-production-netns",
            CommandSpec::new("ip", ["netns", "del", PRODUCTION_NETNS]),
        ),
    ];
    for (name, spec) in cleanup {
        let _ = run_step(steps, name, spec);
    }
}

fn production_host_attach_target() -> TcAttachTarget {
    TcAttachTarget::host(PRODUCTION_HOST_IFACE, TcAttachDirection::Ingress)
}

fn production_peer_attach_target() -> TcAttachTarget {
    TcAttachTarget::netns(
        PRODUCTION_NETNS,
        PRODUCTION_PEER_IFACE,
        TcAttachDirection::Ingress,
    )
}

fn command_spec(command: TcCommandSpec) -> CommandSpec {
    CommandSpec::new(command.program, command.args)
}

pub(super) fn preflight_checks(options: &ProductionRuntimeOwnerOptions) -> Vec<Value> {
    let mut checks = Vec::new();
    push_check(
        &mut checks,
        "root-gate-acknowledged",
        !options.execute || options.ack_root_gate,
        json!({"execute": options.execute, "ack_root_gate": options.ack_root_gate}),
        "production runtime owner root-gated smoke requires --ack-root-gate",
    );
    for tool in ["ip", "tc"] {
        push_check(
            &mut checks,
            match tool {
                "ip" => "tool-ip-available",
                _ => "tool-tc-available",
            },
            command_exists(tool),
            json!({"tool": tool}),
            "required host tool is missing",
        );
    }
    push_check(
        &mut checks,
        "source-object-present",
        !options.execute || options.source_object.exists(),
        json!({"path": path_string(&options.source_object)}),
        "production runtime owner source eBPF object is missing",
    );
    push_check(
        &mut checks,
        "production-names-free",
        !options.execute
            || (!iface_exists(PRODUCTION_HOST_IFACE)
                && !iface_exists(PRODUCTION_PEER_IFACE)
                && !netns_exists(PRODUCTION_NETNS)),
        json!({
            "host_iface": PRODUCTION_HOST_IFACE,
            "peer_iface": PRODUCTION_PEER_IFACE,
            "netns": PRODUCTION_NETNS,
        }),
        "production runtime owner names are already in use",
    );
    push_check(
        &mut checks,
        "tproxy-port-free",
        !options.execute || tproxy_port_available(options.tproxy_port),
        json!({"tproxy_port": options.tproxy_port}),
        "production runtime owner tproxy port is already in use",
    );
    checks
}
