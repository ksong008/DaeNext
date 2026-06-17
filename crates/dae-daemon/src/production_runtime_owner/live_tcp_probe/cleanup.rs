use dae_ebpf_support::{TcAttachDirection, TcAttachTarget, TcCommandSpec};
use serde_json::{Value, json};

use super::super::command::{CommandSpec, run_step};
use super::{CLIENT_NETNS, LAN_FILTER_PREF, LAN_HOST_IFACE};

pub(in crate::production_runtime_owner) fn cleanup_active_tcp_resources(
    cleanup_steps: &mut Vec<Value>,
    native_lan_attached: bool,
) {
    if native_lan_attached {
        cleanup_steps.push(json!({
            "name": "delete-lan-ingress-param-aware-ebpf-program-filter",
            "status": "skipped",
            "reason": "native Aya link lifetime detached the LAN ingress filter before tc command cleanup",
        }));
    } else {
        let _ = run_step(
            cleanup_steps,
            "delete-lan-ingress-param-aware-ebpf-program-filter",
            command_spec(lan_attach_target().filter_del_command(LAN_FILTER_PREF)),
        );
    }
    for (name, spec) in [
        (
            "delete-lan-host-clsact-qdisc",
            command_spec(lan_attach_target().clsact_qdisc_del_command()),
        ),
        (
            "delete-lan-host-link",
            CommandSpec::new("ip", ["link", "del", LAN_HOST_IFACE]),
        ),
        (
            "delete-client-netns",
            CommandSpec::new("ip", ["netns", "del", CLIENT_NETNS]),
        ),
    ] {
        let _ = run_step(cleanup_steps, name, spec);
    }
}

fn lan_attach_target() -> TcAttachTarget {
    TcAttachTarget::host(LAN_HOST_IFACE, TcAttachDirection::Ingress)
}

fn command_spec(command: TcCommandSpec) -> CommandSpec {
    CommandSpec::new(command.program, command.args)
}
