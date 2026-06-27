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
            "name": "rust-ebpf-loader-native-runtime-contract",
            "binary": "dae-ebpf-loader",
            "compiled_native_ebpf": cfg!(feature = "native-ebpf"),
            "scope": "Rust/Aya loads the selected daemon eBPF object and pins all maps/programs for native control-plane ownership",
            "native_userspace_outbound_ready": true,
            "native_bpf_loader_enabled_for_product": true,
            "kernel_ebpf_program_rewrite": true,
            "rust_aya_loader_object_supported": true,
            "default_object_source": RUST_AYA_LOADER_OBJECT_SOURCE,
            "supported_object_sources": [RUST_AYA_LOADER_OBJECT_SOURCE],
            "required_pins": {
                "maps": "pin_root/maps/<map_name>",
                "programs": "pin_root/programs/<program_name>"
            },
            "object_source": {
                "rust-aya-loader": "default Rust/Aya eBPF loader object built from crates/dae-ebpf-program"
            },
            "param_source": {
                "tproxy_port": "host-order u16, converted to BPF big-endian PARAM",
                "control_plane_pid": "native control-plane pid",
                "dae0_ifindex": "initialized dae0 ifindex",
                "dae_netns_id": "initialized dae netns id",
                "dae0peer_mac": "initialized dae0peer mac",
                "has_bpf_get_current_task": "native feature probe result",
                "task_struct_mm_offset": "target BTF task_struct.mm byte offset for current_task argv[0] pname mode",
                "mm_struct_arg_start_offset": "target BTF mm_struct.arg_start byte offset for current_task argv[0] pname mode"
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
            "listener_smoke": "listen_socket_map TCP/UDP family keys remain updated by tproxy-listener helper; Rust Aya loader only preserves map ABI",
            "routing_smoke": "routing-map/domain-routing-map helpers remain userspace-owned; Rust Aya loader only preserves map ABI",
        })
    ))
}

pub(super) fn run_cgroup_monitor_contract() -> LoaderOutput {
    LoaderOutput::ok(format!(
        "{}\n",
        json!({
            "name": "rust-cgroup-pname-monitor-attach-contract",
            "binary": "dae-ebpf-loader",
            "scope": "Rust attaches pinned cgroup pname monitor programs and pins bpf_link objects for native control-plane lifetime ownership",
            "native_pname_routing_semantics_ready": true,
            "pname_source": "runtime_selected",
            "preferred_pname_source": "current_task_argv0_basename",
            "pname_semantics": "argv0_basename_when_enhanced_else_non_core_task_comm",
            "core_enabled": false,
            "core_enabled_source": "daemon enhanced object load result",
            "official_argv_semantics_implemented": true,
            "fallback_source": "bpf_get_current_comm",
            "target_btf_offsets_required_for_argv0": true,
            "kernel_ebpf_program_rewrite": false,
            "link_lifetime": "pinned under --link-root; native control-plane removes the pin root on close/reload cleanup",
            "program_source": "--program-root/<program_name> from Rust/Aya-loaded pinned programs",
            "cgroup_source": "--cgroup-path, normally the first cgroup2 mount from /proc/mounts",
            "attach_matrix": dae_ebpf_support::dae_cgroup_attach_matrix().iter().map(|line| json!({
                "role": line.role.section_tail(),
                "section": line.section,
                "program_name": line.program_name,
                "attach_type": line.attach_type,
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
            "binary": "dae-ebpf-loader",
            "scope": "Rust/Aya attaches pinned TC sched classifier programs for LAN/WAN/dae0/dae0peer and pins TCX bpf_link lifetime for native control-plane cleanup",
            "native_userspace_outbound_ready": true,
            "native_routing_dns_sniff_group_ready": true,
            "kernel_ebpf_program_rewrite": false,
            "backend": "auto attempts tcx first and falls back to tc_netlink; explicit tcx is strict; explicit tc/tc_netlink uses tc_netlink",
            "link_lifetime": {
                "tcx": "pinned under --link-root/link; native control-plane removes link root on close/reload cleanup",
                "tc_netlink": "persistent kernel filter; native control-plane deletes by priority/handle/name on close/reload cleanup"
            },
            "attach_matrix": matrix.iter().map(|line| json!({
                "role": line.role.as_str(),
                "filter_name": line.filter_name,
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
            "binary": "dae-ebpf-loader",
            "scope": "Rust opens dual-stack TCP/UDP tproxy listeners in the caller netns, writes listen_socket_map family keys with those fds, and hands listener fds back to native userspace handlers",
            "native_userspace_tcp_udp_handlers_ready": true,
            "native_routing_dns_sniff_group_outbound_ready": true,
            "kernel_ebpf_program_rewrite": false,
            "listen_socket_map": {
                "key_0": "tcp listener fd for tcp4 packets",
                "key_1": "tcp listener fd for tcp6 packets",
                "key_2": "udp socket fd for udp4 packets",
                "key_3": "udp socket fd for udp6 packets",
                "map_type": "BPF_MAP_TYPE_SOCKMAP",
                "max_entries": 4
            },
            "socket_options": {
                "ip_transparent": true,
                "so_reuseaddr": true,
                "ip_recvorigdstaddr_or_ipv6_recvorigdstaddr": true
            },
            "handoff": "open-handoff sends TCP/UDP listener fds over SCM_RIGHTS; update-map accepts inherited fds for reload listener reuse",
            "restore_path": "native listener open and native listen_socket_map update remain available when the helper fails",
        })
    ))
}
