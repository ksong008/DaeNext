use super::*;
pub(crate) fn cleanup_production_topology(
    steps: &mut Vec<Value>,
    native_peer_attached: bool,
    native_host_attached: bool,
    native_backend: bool,
) {
    if !iface_exists(PRODUCTION_HOST_IFACE) && !netns_exists(PRODUCTION_NETNS) {
        steps.push(json!({"name": "production-topology-already-absent", "status": "skipped"}));
        return;
    }
    if native_backend || native_host_attached {
        steps.push(json!({
            "name": "delete-production-dae0-param-aware-ebpf-program-filter",
            "status": "skipped",
            "reason": "native physical owner handles exact host filter cleanup; see reset-native-ebpf-owner and binding postflight",
        }));
    } else {
        let _ = run_step(
            steps,
            "delete-production-dae0-param-aware-ebpf-program-filter",
            command_spec(production_host_attach_target().filter_del_command(FILTER_PREF)),
        );
    }
    if native_backend || native_peer_attached {
        steps.push(json!({
            "name": "delete-production-dae0peer-param-aware-ebpf-program-filter",
            "status": "skipped",
            "reason": "native physical owner handles exact peer filter cleanup; see reset-native-ebpf-owner and binding postflight",
        }));
    } else {
        let _ = run_step(
            steps,
            "delete-production-dae0peer-param-aware-ebpf-program-filter",
            command_spec(production_peer_attach_target().filter_del_command(FILTER_PREF)),
        );
    }
    super::super::topology_netlink::step(steps, "delete-production-host-link", || {
        super::super::topology_netlink::delete_link(PRODUCTION_HOST_IFACE)?;
        Ok(json!({"interface": PRODUCTION_HOST_IFACE}))
    });
    super::super::topology_netlink::step(steps, "delete-production-netns", || {
        super::super::topology_netlink::delete_namespace(PRODUCTION_NETNS)?;
        Ok(json!({"netns": PRODUCTION_NETNS}))
    });
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
