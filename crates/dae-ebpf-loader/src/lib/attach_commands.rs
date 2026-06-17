use super::*;
pub(crate) fn run_cgroup_monitor_attach_pin(
    options: CgroupMonitorAttachPinOptions,
) -> LoaderOutput {
    let reports = match dae_ebpf_support::attach_pin_cgroup_monitor(
        dae_ebpf_support::PinnedCgroupAttachOptions {
            program_root: &options.program_root,
            link_root: &options.link_root,
            cgroup_path: &options.cgroup_path,
        },
    ) {
        Ok(reports) => reports,
        Err(err) => return LoaderOutput::error(format!("cgroup monitor attach-pin failed: {err}")),
    };
    LoaderOutput::ok(format!(
        "{}\n",
        json!({
            "status": "pass",
            "loader": "rust",
            "scope": "cgroup-pname-monitor-attach-pin",
            "program_root": options.program_root,
            "link_root": options.link_root,
            "cgroup_path": options.cgroup_path,
            "links": reports.iter().map(|report| json!({
                "role": report.role.section_tail(),
                "program_name": report.program_name,
                "program_path": report.program_path,
                "link_path": report.link_path,
                "section": report.section,
                "attach_type": report.attach_type,
                "attach_mode": report.attach_mode,
                "attached": report.attached,
                "pinned": report.pinned,
            })).collect::<Vec<_>>(),
        })
    ))
}

#[cfg(feature = "native-ebpf")]
pub(crate) fn run_tc_attach_pin(options: TcAttachPinOptions) -> LoaderOutput {
    let spec = dae_ebpf_support::TcNativeAttachSpec {
        target: dae_ebpf_support::TcAttachTarget {
            iface: options.iface.clone(),
            netns: options.netns.clone(),
            direction: options.direction,
        },
        object: "runtime-pinned-program".to_owned(),
        section: options.program_name.clone(),
        program_name: options.program_name.clone(),
        priority: options.priority,
        handle: options.handle,
        tcx_order: dae_ebpf_support::TcxAttachOrder::from_tc_priority(options.priority),
        protocol: dae_ebpf_support::ETH_P_ALL,
        direct_action: true,
        clsact_required: true,
        netns_enter_required: options.netns.is_some(),
        link_lifetime_owned_by_backend: true,
    };
    let report = match dae_ebpf_support::attach_pin_aya_sched_classifier(
        dae_ebpf_support::PinnedTcAttachOptions {
            program_root: &options.program_root,
            link_root: &options.link_root,
            spec: &spec,
            requested_backend: options.backend,
        },
    ) {
        Ok(report) => report,
        Err(err) => return LoaderOutput::error(format!("tc attach-pin failed: {err}")),
    };
    LoaderOutput::ok(format!(
        "{}\n",
        json!({
            "status": "pass",
            "loader": "rust-aya",
            "scope": "tc-tcx-attach-pin",
            "program_root": options.program_root,
            "link_root": options.link_root,
            "filter_name": options.filter_name,
            "requested_backend": report.requested_backend.as_str(),
            "backend": report.backend.as_str(),
            "backend_switch_used": report.backend_switch_used,
            "backend_switch_error": report.backend_switch_error,
            "program_id": report.program_id,
            "program_name": report.program_name,
            "program_path": report.program_path,
            "iface": report.iface,
            "netns": report.netns,
            "netns_entered": report.netns_entered,
            "direction": report.direction.as_str(),
            "priority": report.priority,
            "handle": report.handle,
            "tcx_order": report.tcx_order.as_str(),
            "tcx_query_revision": report.tcx_query_revision,
            "tcx_order_verified": report.tcx_order_verified,
            "tcx_program_order": report.tcx_program_order.iter().map(|entry| json!({
                "id": entry.id,
                "name": entry.name,
                "tag": entry.tag,
            })).collect::<Vec<_>>(),
            "link_path": report.link_path,
            "tc_filter_persistent": report.tc_filter_persistent,
            "clsact_added_or_present": report.clsact_added_or_present,
        })
    ))
}

#[cfg(not(feature = "native-ebpf"))]
pub(crate) fn run_tc_attach_pin(_options: TcAttachPinOptions) -> LoaderOutput {
    LoaderOutput::error("tc-attach attach-pin requires dae-ebpf-loader feature native-ebpf")
}

pub(crate) fn run_tproxy_listener_open_handoff(
    options: TproxyListenerOpenHandoffOptions,
) -> LoaderOutput {
    let handoff = match dae_ebpf_support::open_tproxy_listener_set_and_update_sockmap_by_id(
        options.map_id,
        options.port,
    ) {
        Ok(handoff) => handoff,
        Err(err) => {
            return LoaderOutput::error(format!("tproxy listener open-handoff failed: {err}"));
        }
    };
    let payload = json!({
        "status": "pass",
        "loader": "rust",
        "scope": "tproxy-listener-open-handoff",
        "map_id": handoff.map.id,
        "map_name": handoff.map.name,
        "port": options.port,
        "keys_updated": handoff.keys_updated,
        "tcp_listener_fd": handoff.tcp_listener_fd,
        "udp_socket_fd": handoff.udp_socket_fd,
        "tcp_options": {
            "ip_transparent": handoff.tcp_options.ip_transparent,
            "so_reuseaddr": handoff.tcp_options.so_reuseaddr,
            "ip_recvorigdstaddr": handoff.tcp_options.ip_recvorigdstaddr,
            "ipv6_recvorigdstaddr": handoff.tcp_options.ipv6_recvorigdstaddr,
            "original_dst_capture_ready": handoff.tcp_options.original_dst_capture_ready,
        },
        "udp_options": {
            "ip_transparent": handoff.udp_options.ip_transparent,
            "so_reuseaddr": handoff.udp_options.so_reuseaddr,
            "ip_recvorigdstaddr": handoff.udp_options.ip_recvorigdstaddr,
            "ipv6_recvorigdstaddr": handoff.udp_options.ipv6_recvorigdstaddr,
            "original_dst_capture_ready": handoff.udp_options.original_dst_capture_ready,
        },
        "native_userspace_handlers_ready": true,
    });
    let payload = format!("{payload}\n");
    if let Err(err) = send_fd_handoff(
        options.handoff_fd,
        payload.as_bytes(),
        &[
            handoff.listeners.tcp_listener.as_raw_fd(),
            handoff.listeners.udp_socket.as_raw_fd(),
        ],
    ) {
        return LoaderOutput::error(format!("send tproxy listener fd handoff failed: {err}"));
    }
    LoaderOutput::ok(payload)
}

pub(crate) fn run_tproxy_listener_update_map(
    options: TproxyListenerUpdateMapOptions,
) -> LoaderOutput {
    let map = match dae_ebpf_support::update_listen_socket_map_by_id(
        options.map_id,
        options.tcp_fd,
        options.udp_fd,
    ) {
        Ok(map) => map,
        Err(err) => {
            return LoaderOutput::error(format!("tproxy listener update-map failed: {err}"));
        }
    };
    LoaderOutput::ok(format!(
        "{}\n",
        json!({
            "status": "pass",
            "loader": "rust",
            "scope": "tproxy-listener-update-map",
            "map_id": map.id,
            "map_name": map.name,
            "keys_updated": [0, 1],
            "tcp_fd": options.tcp_fd,
            "udp_fd": options.udp_fd,
            "native_userspace_handlers_ready": true,
        })
    ))
}
