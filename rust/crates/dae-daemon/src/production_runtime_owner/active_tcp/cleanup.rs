use serde_json::Value;

use super::super::command::{CommandSpec, run_step};
use super::{CLIENT_NETNS, LAN_FILTER_PREF, LAN_HOST_IFACE};

pub(in crate::production_runtime_owner) fn cleanup_active_tcp_resources(
    cleanup_steps: &mut Vec<Value>,
) {
    for (name, spec) in [
        (
            "delete-lan-ingress-param-aware-ebpf-program-filter",
            CommandSpec::new(
                "tc",
                [
                    "filter",
                    "del",
                    "dev",
                    LAN_HOST_IFACE,
                    "ingress",
                    "pref",
                    LAN_FILTER_PREF,
                ],
            ),
        ),
        (
            "delete-lan-host-clsact-qdisc",
            CommandSpec::new("tc", ["qdisc", "del", "dev", LAN_HOST_IFACE, "clsact"]),
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
