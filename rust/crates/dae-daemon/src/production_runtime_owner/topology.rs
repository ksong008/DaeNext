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
use super::native_ebpf::{NativeEbpfAttachRole, NativeEbpfRuntimeState};
use super::netns_link::{
    NetnsLinkMode, cleanup_partial_link_setup, create_link_pair, netns_link_env_name,
    setup_link_pair_with_auto_fallback,
};
use super::{
    FILTER_PREF, PRODUCTION_HOST_IFACE, PRODUCTION_NETNS, PRODUCTION_PEER_IFACE,
    ProductionRuntimeOwnerOptions,
};

pub(super) fn setup_production_topology(
    steps: &mut Vec<Value>,
    options: &ProductionRuntimeOwnerOptions,
) -> bool {
    setup_link_pair_with_auto_fallback(
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

fn setup_production_topology_with_link_mode(
    steps: &mut Vec<Value>,
    options: &ProductionRuntimeOwnerOptions,
    mode: NetnsLinkMode,
) -> bool {
    let mut ok = true;
    ok &= create_link_pair(
        steps,
        "production",
        PRODUCTION_HOST_IFACE,
        PRODUCTION_PEER_IFACE,
        mode,
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

pub(super) fn setup_production_ipv4_datapath(steps: &mut Vec<Value>, dae0_mac: [u8; 6]) -> bool {
    let host_mac = mac_string(dae0_mac);
    let mut ok = true;
    ok &= run_step(
        steps,
        "add-daens-fwmark-rule",
        CommandSpec::new(
            "ip",
            [
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
            [
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
    ok &= run_step(
        steps,
        "set-daens-dae0peer-accept-local",
        CommandSpec::new(
            "ip",
            [
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
            [
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
            [
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
            [
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
            [
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
            [
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
            [
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
            [
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

pub(super) fn read_topology_values(
    steps: &mut Vec<Value>,
    options: &ProductionRuntimeOwnerOptions,
) -> (Value, Option<u32>, Option<[u8; 6]>, Option<[u8; 6]>) {
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
            "dae_netns_id": options.dae_netns_id,
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
            "dae0_ifindex_error": parse_step_u32(&dae0_ifindex_step).err(),
            "dae0_mac_error": parse_step_mac(&dae0_mac_step).err(),
            "dae0peer_mac_error": parse_step_mac(&dae0peer_mac_step).err(),
        }),
    };
    (value, dae0_ifindex, dae0_mac, dae0peer_mac)
}

fn parse_link_kind(step: &Value) -> Option<&'static str> {
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
    native_param_object: &Path,
    native_runtime: &mut NativeEbpfRuntimeState,
) -> bool {
    let param_object = path_string(param_object);
    let target = production_peer_attach_target();
    let attach = TcBpfAttachSpec::new(
        target.clone(),
        FILTER_PREF,
        param_object,
        options.peer_section.clone(),
    );
    if native_runtime.attach_program(
        steps,
        options,
        native_param_object,
        NativeEbpfAttachRole::PeerIngress,
    ) == Some(true)
    {
        return true;
    }
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
    native_param_object: &Path,
    native_runtime: &mut NativeEbpfRuntimeState,
) -> bool {
    let param_object = path_string(param_object);
    let target = production_host_attach_target();
    let attach = TcBpfAttachSpec::new(
        target.clone(),
        FILTER_PREF,
        param_object,
        options.host_section.clone(),
    );
    if native_runtime.attach_program(
        steps,
        options,
        native_param_object,
        NativeEbpfAttachRole::HostIngress,
    ) == Some(true)
    {
        return true;
    }
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

pub(super) fn cleanup_production_topology(
    steps: &mut Vec<Value>,
    native_peer_attached: bool,
    native_host_attached: bool,
) {
    if native_host_attached {
        steps.push(json!({
            "name": "delete-production-dae0-param-aware-ebpf-program-filter",
            "status": "skipped",
            "reason": "native Aya link lifetime detached the host ingress filter before tc command fallback cleanup",
        }));
    } else {
        let _ = run_step(
            steps,
            "delete-production-dae0-param-aware-ebpf-program-filter",
            command_spec(production_host_attach_target().filter_del_command(FILTER_PREF)),
        );
    }
    let cleanup_host = [(
        "delete-production-host-clsact-qdisc",
        command_spec(production_host_attach_target().clsact_qdisc_del_command()),
    )];
    for (name, spec) in cleanup_host {
        let _ = run_step(steps, name, spec);
    }
    if native_peer_attached {
        steps.push(json!({
            "name": "delete-production-dae0peer-param-aware-ebpf-program-filter",
            "status": "skipped",
            "reason": "native Aya link lifetime detached the peer ingress filter before tc command fallback cleanup",
        }));
    } else {
        let _ = run_step(
            steps,
            "delete-production-dae0peer-param-aware-ebpf-program-filter",
            command_spec(production_peer_attach_target().filter_del_command(FILTER_PREF)),
        );
    }
    let cleanup_rest = [
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
    for (name, spec) in cleanup_rest {
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
        "native-ebpf-runtime-opt-in-contract",
        true,
        json!({
            "opt_in": options.native_ebpf_opt_in,
            "requested_backend": options.native_ebpf_backend.as_str(),
            "completed_a3_admission": options.native_ebpf_completed_a3_admission,
            "native_loader_compiled": cfg!(feature = "native-ebpf"),
            "default_enable_allowed": false,
            "tc_command_fallback_required": true,
            "go_bpf_fallback_retired": options.native_ebpf_completed_a3_admission,
            "topology_link_mode": {
                "env": netns_link_env_name(),
                "requested": options.netns_link_mode.as_str(),
                "auto_policy": "netkit_l2_scrub_none_then_legacy_netkit_l2_then_veth",
                "tcx_is_attach_backend_only": true,
            },
        }),
        "native eBPF runtime opt-in contract is invalid",
    );
    push_check(
        &mut checks,
        "native-ebpf-object-present",
        !options.execute
            || !options.native_ebpf_opt_in
            || options
                .native_ebpf_object
                .as_ref()
                .is_none_or(|path| path.is_file()),
        json!({
            "opt_in": options.native_ebpf_opt_in,
            "path": options.native_ebpf_object.as_ref().map(|path| path_string(path)),
            "fallback_object": path_string(&options.source_object),
            "required_when_configured": true,
        }),
        "configured native eBPF object is missing",
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
