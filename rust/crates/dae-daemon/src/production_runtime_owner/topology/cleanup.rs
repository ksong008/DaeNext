use super::*;
pub(crate) fn cleanup_production_topology(
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

pub(crate) fn production_host_attach_target() -> TcAttachTarget {
    TcAttachTarget::host(PRODUCTION_HOST_IFACE, TcAttachDirection::Ingress)
}

pub(crate) fn production_peer_attach_target() -> TcAttachTarget {
    TcAttachTarget::netns(
        PRODUCTION_NETNS,
        PRODUCTION_PEER_IFACE,
        TcAttachDirection::Ingress,
    )
}

pub(crate) fn command_spec(command: TcCommandSpec) -> CommandSpec {
    CommandSpec::new(command.program, command.args)
}
