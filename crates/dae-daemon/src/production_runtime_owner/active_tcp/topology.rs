use std::path::Path;

use dae_ebpf_support::{TcAttachDirection, TcAttachTarget, TcBpfAttachSpec, TcCommandSpec};
use serde_json::Value;

use super::super::command::{CommandSpec, mac_string, path_string, run_observation_step, run_step};
use super::super::native_ebpf::{NativeEbpfAttachRole, NativeEbpfRuntimeState};
use super::super::netns_link::{
    NetnsLinkMode, cleanup_partial_link_setup, create_link_pair,
    setup_link_pair_with_auto_selection,
};
use super::super::{
    PRODUCTION_HOST_IFACE, PRODUCTION_NETNS, PRODUCTION_PEER_IFACE, ProductionRuntimeOwnerOptions,
};
use super::{
    CLIENT_NETNS, DEFAULT_LAN_GATEWAY_IP, DEFAULT_LAN_SECTION, LAN_CLIENT_IFACE, LAN_FILTER_PREF,
    LAN_HOST_IFACE,
};

pub(in crate::production_runtime_owner) fn setup_client_topology(
    steps: &mut Vec<Value>,
    options: &ProductionRuntimeOwnerOptions,
) -> bool {
    let mut ok = setup_link_pair_with_auto_selection(
        steps,
        "active-tcp",
        LAN_HOST_IFACE,
        LAN_CLIENT_IFACE,
        options.netns_link_mode,
        setup_client_link_topology_with_mode,
        |steps| {
            cleanup_partial_link_setup(
                steps,
                "active-tcp",
                Some(CLIENT_NETNS),
                LAN_HOST_IFACE,
                LAN_CLIENT_IFACE,
            );
        },
    );
    ok &= setup_client_ipv4_topology(steps, options);
    ok
}

fn setup_client_link_topology_with_mode(steps: &mut Vec<Value>, mode: NetnsLinkMode) -> bool {
    let mut ok = true;
    ok &= run_step(
        steps,
        "create-client-netns",
        CommandSpec::new("ip", ["netns", "add", CLIENT_NETNS]),
    );
    ok &= create_link_pair(steps, "lan", LAN_HOST_IFACE, LAN_CLIENT_IFACE, mode);
    ok &= run_step(
        steps,
        "move-lan-client-into-netns",
        CommandSpec::new(
            "ip",
            ["link", "set", LAN_CLIENT_IFACE, "netns", CLIENT_NETNS],
        ),
    );
    ok &= run_step(
        steps,
        "bring-lan-host-link-up",
        CommandSpec::new("ip", ["link", "set", LAN_HOST_IFACE, "up"]),
    );
    ok &= run_step(
        steps,
        "bring-client-loopback-up",
        CommandSpec::new(
            "ip",
            [
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
        "bring-lan-client-link-up",
        CommandSpec::new(
            "ip",
            [
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
    ok
}

fn setup_client_ipv4_topology(
    steps: &mut Vec<Value>,
    options: &ProductionRuntimeOwnerOptions,
) -> bool {
    let mut ok = true;
    ok &= run_step(
        steps,
        "assign-lan-host-ip",
        CommandSpec::new(
            "ip",
            [
                "addr",
                "add",
                &format!("{DEFAULT_LAN_GATEWAY_IP}/24"),
                "dev",
                LAN_HOST_IFACE,
            ],
        ),
    );
    ok &= run_step(
        steps,
        "disable-lan-host-send-redirects",
        CommandSpec::new(
            "sysctl",
            [
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
            ["-w", &format!("net.ipv4.conf.{LAN_HOST_IFACE}.rp_filter=0")],
        ),
    );
    ok &= run_step(
        steps,
        "assign-lan-client-ip",
        CommandSpec::new(
            "ip",
            [
                "netns",
                "exec",
                CLIENT_NETNS,
                "ip",
                "addr",
                "add",
                &format!("{}/24", options.active_tcp_client_ip),
                "dev",
                LAN_CLIENT_IFACE,
            ],
        ),
    );
    ok &= run_step(
        steps,
        "add-client-default-route-via-lan-gateway",
        CommandSpec::new(
            "ip",
            [
                "netns",
                "exec",
                CLIENT_NETNS,
                "ip",
                "route",
                "add",
                "default",
                "via",
                DEFAULT_LAN_GATEWAY_IP,
                "dev",
                LAN_CLIENT_IFACE,
            ],
        ),
    );
    ok
}

pub(in crate::production_runtime_owner) fn setup_production_ipv4_datapath(
    steps: &mut Vec<Value>,
    dae0_mac: [u8; 6],
) -> bool {
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

pub(in crate::production_runtime_owner) fn attach_lan_program(
    steps: &mut Vec<Value>,
    options: &ProductionRuntimeOwnerOptions,
    param_object: &Path,
    native_param_object: &Path,
    native_runtime: &mut NativeEbpfRuntimeState,
) -> bool {
    let param_object = path_string(param_object);
    let target = lan_attach_target();
    let attach = TcBpfAttachSpec::new(
        target.clone(),
        LAN_FILTER_PREF,
        param_object,
        DEFAULT_LAN_SECTION,
    );
    if native_runtime.attach_program(
        steps,
        options,
        native_param_object,
        NativeEbpfAttachRole::LanIngress,
    ) == Some(true)
    {
        return true;
    }
    let mut ok = true;
    ok &= run_step(
        steps,
        "attach-lan-host-clsact-qdisc",
        command_spec(target.clsact_qdisc_add_command()),
    );
    ok &= run_step(
        steps,
        "attach-lan-ingress-param-aware-ebpf-program",
        command_spec(attach.filter_add_command()),
    );
    ok
}

pub(in crate::production_runtime_owner) fn show_lan_program(steps: &mut Vec<Value>) -> Value {
    run_observation_step(
        steps,
        "show-lan-ingress-param-aware-ebpf-program-filter",
        command_spec(lan_attach_target().filter_show_command(false)),
    )
}

pub(in crate::production_runtime_owner) fn show_peer_program_stats(
    steps: &mut Vec<Value>,
) -> Value {
    run_observation_step(
        steps,
        "show-production-dae0peer-param-aware-ebpf-program-filter-stats",
        command_spec(production_peer_attach_target().filter_show_command(true)),
    )
}

pub(in crate::production_runtime_owner) fn show_lan_program_stats(steps: &mut Vec<Value>) -> Value {
    run_observation_step(
        steps,
        "show-lan-ingress-param-aware-ebpf-program-filter-stats",
        command_spec(lan_attach_target().filter_show_command(true)),
    )
}

pub(in crate::production_runtime_owner) fn show_host_program_stats(
    steps: &mut Vec<Value>,
) -> Value {
    run_observation_step(
        steps,
        "show-production-dae0-param-aware-ebpf-program-filter-stats",
        command_spec(production_host_attach_target().filter_show_command(true)),
    )
}

fn lan_attach_target() -> TcAttachTarget {
    TcAttachTarget::host(LAN_HOST_IFACE, TcAttachDirection::Ingress)
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
