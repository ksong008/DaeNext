use super::*;
pub(super) fn run_contract() -> LoaderOutput {
    let tc_matrix =
        dae_ebpf_support::dae_tc_attach_matrix(dae_ebpf_support::DaeTcAttachMatrixInput {
            object: "runtime-pinned-program".to_owned(),
            lan_iface: "lan".to_owned(),
            wan_iface: "wan".to_owned(),
            host_iface: "dae0".to_owned(),
            peer_iface: "dae0peer".to_owned(),
            peer_netns: "daens".to_owned(),
            section_prefix: dae_ebpf_support::TcAttachSectionPrefix::Classifier,
            link_layer: dae_ebpf_support::TcAttachLayer::L2,
            flip: 0,
            is_reload: false,
        });
    LoaderOutput::ok(format!(
        "{}\n",
        json!({
            "name": "rust-aya-bpf-loader-go-adoption-contract",
            "binary": "dae-aya-bpf-loader",
            "compiled_native_ebpf": cfg!(feature = "native-ebpf"),
            "scope": "Rust/Aya loads a selected daemon eBPF object and pins all maps/programs for Go control-plane adoption",
            "go_userspace_outbound_remains_authoritative": true,
            "go_bpf_loader_removed_when_opted_in": true,
            "kernel_ebpf_program_rewrite": true,
            "rust_aya_skeleton_object_supported": true,
            "default_object_source": BpfObjectSource::RustAyaSkeleton.as_str(),
            "supported_object_sources": [
                BpfObjectSource::CAya.as_str(),
                BpfObjectSource::RustAyaSkeleton.as_str(),
            ],
            "required_pins": {
                "maps": "pin_root/maps/<map_name>",
                "programs": "pin_root/programs/<program_name>"
            },
            "object_source": {
                "c-aya": "explicit --object compatibility source for an Aya-compatible C eBPF object; no longer embedded by default",
                "rust-aya-skeleton": "default embedded Rust/Aya eBPF object built from rust/crates/dae-ebpf-program"
            },
            "param_source": {
                "tproxy_port": "host-order u16, converted to BPF big-endian PARAM",
                "control_plane_pid": "Go control-plane pid",
                "dae0_ifindex": "initialized dae0 ifindex",
                "dae_netns_id": "initialized dae netns id",
                "dae0peer_mac": "initialized dae0peer mac",
                "has_bpf_get_current_task": "Go feature probe result"
            },
            "maps": dae_ebpf_support::map_catalog().iter().map(|spec| json!({
                "name": spec.name,
                "type": spec.map_type,
                "key_size": spec.key_size,
                "value_size": spec.value_size,
                "max_entries": spec.max_entries,
                "flags": spec.flags,
                "pinning": spec.pinning,
                "role": format!("{:?}", spec.role()),
            })).collect::<Vec<_>>(),
            "tc_programs": tc_matrix.iter().map(|line| json!({
                "role": line.role.as_str(),
                "section": line.native.section,
                "program_name": line.native.program_name,
                "direction": line.native.target.direction.as_str(),
                "priority": line.native.priority,
                "handle": line.native.handle,
                "tcx_order": line.native.tcx_order.as_str(),
            })).collect::<Vec<_>>(),
            "cgroup_programs": dae_ebpf_support::dae_cgroup_attach_matrix().iter().map(|line| json!({
                "role": line.role.section_tail(),
                "section": line.section,
                "program_name": line.program_name,
                "bpf_attach_type": line.role.bpf_attach_type(),
                "aya_program_kind": line.aya_program_kind.as_str(),
            })).collect::<Vec<_>>(),
            "listener_smoke": "listen_socket_map key 0/1 remains updated by tproxy-listener helper; Rust skeleton only preserves map ABI",
            "routing_smoke": "routing-map/domain-routing-map helpers remain userspace-owned; Rust skeleton only preserves map ABI",
        })
    ))
}

pub(super) fn run_cgroup_monitor_contract() -> LoaderOutput {
    LoaderOutput::ok(format!(
        "{}\n",
        json!({
            "name": "rust-cgroup-pname-monitor-attach-contract",
            "binary": "dae-aya-bpf-loader",
            "scope": "Rust attaches pinned cgroup pname monitor programs and pins bpf_link objects for Go control-plane lifetime ownership",
            "go_pname_routing_semantics_remain_authoritative": true,
            "kernel_ebpf_program_rewrite": false,
            "link_lifetime": "pinned under --link-root; Go control-plane removes the pin root on close/reload cleanup",
            "program_source": "--program-root/<program_name> from Rust/Aya-loaded pinned programs",
            "cgroup_source": "--cgroup-path, normally the first cgroup2 mount from /proc/mounts",
            "attach_matrix": dae_ebpf_support::dae_cgroup_attach_matrix().iter().map(|line| json!({
                "role": line.role.section_tail(),
                "section": line.section,
                "program_name": line.program_name,
                "go_attach_type": line.go_attach_type,
                "bpf_attach_type": line.role.bpf_attach_type(),
                "aya_program_kind": line.aya_program_kind.as_str(),
                "attach_mode": line.attach_mode,
            })).collect::<Vec<_>>(),
        })
    ))
}

pub(super) fn run_tc_attach_contract() -> LoaderOutput {
    let matrix = dae_ebpf_support::dae_tc_attach_matrix(dae_ebpf_support::DaeTcAttachMatrixInput {
        object: "runtime-pinned-program".to_owned(),
        lan_iface: "lan".to_owned(),
        wan_iface: "wan".to_owned(),
        host_iface: "dae0".to_owned(),
        peer_iface: "dae0peer".to_owned(),
        peer_netns: "daens".to_owned(),
        section_prefix: dae_ebpf_support::TcAttachSectionPrefix::Tc,
        link_layer: dae_ebpf_support::TcAttachLayer::L2,
        flip: 0,
        is_reload: false,
    });
    LoaderOutput::ok(format!(
        "{}\n",
        json!({
            "name": "rust-tc-tcx-attach-pin-contract",
            "binary": "dae-aya-bpf-loader",
            "scope": "Rust/Aya attaches pinned TC sched classifier programs for LAN/WAN/dae0/dae0peer and pins TCX bpf_link lifetime for Go control-plane cleanup",
            "go_userspace_outbound_remains_authoritative": true,
            "go_routing_dns_sniff_group_remain_authoritative": true,
            "kernel_ebpf_program_rewrite": false,
            "backend": "auto attempts tcx first and falls back to tc_netlink; explicit tcx is strict; explicit tc/tc_netlink uses tc_netlink",
            "link_lifetime": {
                "tcx": "pinned under --link-root/link; Go control-plane removes link root on close/reload cleanup",
                "tc_netlink": "persistent kernel filter; Go control-plane deletes by priority/handle/name on close/reload cleanup"
            },
            "attach_matrix": matrix.iter().map(|line| json!({
                "role": line.role.as_str(),
                "filter_name": line.go_filter_name,
                "program_name": line.native.program_name,
                "direction": line.native.target.direction.as_str(),
                "priority": line.native.priority,
                "handle": line.native.handle,
                "tcx_order": line.native.tcx_order.as_str(),
                "netns": line.native.target.netns,
            })).collect::<Vec<_>>(),
        })
    ))
}

pub(super) fn run_tproxy_listener_contract() -> LoaderOutput {
    LoaderOutput::ok(format!(
        "{}\n",
        json!({
            "name": "rust-tproxy-listener-sockmap-handoff-contract",
            "binary": "dae-aya-bpf-loader",
            "scope": "Rust opens TCP/UDP tproxy listeners in the caller netns, writes listen_socket_map key 0/1, and hands listener fds back to Go userspace handlers",
            "go_userspace_tcp_udp_handlers_remain_authoritative": true,
            "go_routing_dns_sniff_group_outbound_remain_authoritative": true,
            "kernel_ebpf_program_rewrite": false,
            "listen_socket_map": {
                "key_0": "tcp listener fd",
                "key_1": "udp socket fd",
                "map_type": "BPF_MAP_TYPE_SOCKMAP",
                "max_entries": 2
            },
            "socket_options": {
                "ip_transparent": true,
                "so_reuseaddr": true,
                "ip_recvorigdstaddr_or_ipv6_recvorigdstaddr": true
            },
            "handoff": "open-handoff sends TCP/UDP listener fds over SCM_RIGHTS; update-map accepts inherited fds for reload listener reuse",
            "fallback": "Go listener open and Go listen_socket_map update remain available when the helper fails",
        })
    ))
}
