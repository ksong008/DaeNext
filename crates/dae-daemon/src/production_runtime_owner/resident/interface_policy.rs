use super::*;
pub(super) fn resident_interface_attach_options(
    options: &ProductionRuntimeOwnerOptions,
    lan_ifaces: &[String],
    wan_ifaces: &[String],
) -> (ProductionRuntimeOwnerOptions, Value) {
    let overlapping_ifaces = overlapping_interfaces(lan_ifaces, wan_ifaces);
    let same_interface_multi_role = !overlapping_ifaces.is_empty();
    let effective = options.clone();
    let auto_tcx_multi_role_admitted = same_interface_multi_role
        && options.native_ebpf_requested
        && options.native_ebpf_backend == AttachBackend::Auto;
    let explicit_tcx_same_interface = !overlapping_ifaces.is_empty()
        && options.native_ebpf_requested
        && options.native_ebpf_backend == AttachBackend::Tcx;
    let effective_backend = effective.native_ebpf_backend;
    (
        effective,
        json!({
            "name": "resident-interface-backend-policy",
            "status": "pass",
            "scope": "resident physical LAN/WAN interface attach backend selection",
            "lan_interfaces": lan_ifaces,
            "wan_interfaces": wan_ifaces,
            "overlapping_interfaces": overlapping_ifaces,
            "requested_backend": options.native_ebpf_backend.as_str(),
            "effective_backend": effective_backend.as_str(),
            "same_interface_multi_role": same_interface_multi_role,
            "auto_tcx_multi_role_admitted": auto_tcx_multi_role_admitted,
            "auto_same_interface_tc_netlink_required": false,
            "auto_downgraded": false,
            "explicit_tcx_same_interface": explicit_tcx_same_interface,
            "reason": if auto_tcx_multi_role_admitted {
                "LAN and WAN share a physical interface; auto keeps TCX candidate and relies on per-filter TCX order plus tc-netlink backend switch to preserve native TC priority semantics"
            } else if explicit_tcx_same_interface {
                "explicit tcx was requested while LAN and WAN share a physical interface; honoring explicit backend with per-filter TCX order"
            } else {
                "no resident interface backend adjustment required"
            },
            "same_interface_tc_netlink_applies_to_all_tc_roles": false,
            "same_interface_tcx_order_policy": "ingress: wan_ingress before lan_ingress; egress: lan_egress before wan_egress; tc-netlink backend switch keeps native priority/handle",
            "role_attach_plan": resident_interface_role_attach_plan(),
            "dae0_dae0peer_link_layer_unchanged": true,
            "dae0_dae0peer_attach_backend_unchanged": true,
        }),
    )
}

fn resident_interface_role_attach_plan() -> Value {
    json!({
        "schemaVersion": 1,
        "startupOrdering": "resident startup attaches physical interface roles before resident dataplane workers start",
        "tcPriorityOrdering": [
            {
                "direction": "ingress",
                "roles": [
                    {"role": "wan_ingress", "priority": 1, "handleMinor": 2},
                    {"role": "lan_ingress", "priority": 2, "handleMinor": 4}
                ]
            },
            {
                "direction": "egress",
                "roles": [
                    {"role": "lan_egress", "priority": 1, "handleMinor": 2},
                    {"role": "wan_egress", "priority": 2, "handleMinor": 4}
                ]
            }
        ],
        "tcxOrderEvidence": "native attach reports tcx_order_verified and tcx_program_order per role",
    })
}

pub(super) fn overlapping_interfaces(lan_ifaces: &[String], wan_ifaces: &[String]) -> Vec<String> {
    let mut overlaps = Vec::new();
    for lan in lan_ifaces {
        let lan = lan.trim();
        if lan.is_empty() || overlaps.iter().any(|seen| seen == lan) {
            continue;
        }
        if wan_ifaces.iter().any(|wan| wan.trim() == lan) {
            overlaps.push(lan.to_owned());
        }
    }
    overlaps
}
