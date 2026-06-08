fn parse_load_pin_options(args: &[String]) -> Result<BpfLoaderLoadPinOptions, String> {
    let mut object = None;
    let mut object_source = None;
    let mut pin_root = None;
    let mut tproxy_port = None;
    let mut control_plane_pid = None;
    let mut dae0_ifindex = None;
    let mut dae_netns_id = None;
    let mut dae0peer_mac = None;
    let mut has_bpf_get_current_task = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--object" => {
                object = Some(parse_next_path(&mut iter, "bpf-loader load-pin --object")?)
            }
            "--object-source" => {
                object_source = Some(BpfObjectSource::parse(next_value(
                    &mut iter,
                    "bpf-loader load-pin --object-source",
                )?)?)
            }
            "--pin-root" => {
                pin_root = Some(parse_next_path(
                    &mut iter,
                    "bpf-loader load-pin --pin-root",
                )?)
            }
            "--tproxy-port" => {
                tproxy_port = Some(parse_next::<u16>(
                    &mut iter,
                    "bpf-loader load-pin --tproxy-port",
                )?)
            }
            "--control-plane-pid" => {
                control_plane_pid = Some(parse_next::<u32>(
                    &mut iter,
                    "bpf-loader load-pin --control-plane-pid",
                )?)
            }
            "--dae0-ifindex" => {
                dae0_ifindex = Some(parse_next::<u32>(
                    &mut iter,
                    "bpf-loader load-pin --dae0-ifindex",
                )?)
            }
            "--dae-netns-id" => {
                dae_netns_id = Some(parse_next::<u32>(
                    &mut iter,
                    "bpf-loader load-pin --dae-netns-id",
                )?)
            }
            "--dae0peer-mac" => {
                dae0peer_mac = Some(parse_mac(next_value(
                    &mut iter,
                    "bpf-loader load-pin --dae0peer-mac",
                )?)?)
            }
            "--has-bpf-get-current-task" => {
                has_bpf_get_current_task = Some(parse_bool(next_value(
                    &mut iter,
                    "bpf-loader load-pin --has-bpf-get-current-task",
                )?)?)
            }
            _ if arg.starts_with("--object=") => object = Some(parse_path_value(arg)?),
            _ if arg.starts_with("--object-source=") => {
                object_source = Some(BpfObjectSource::parse(split_value(arg)?)?)
            }
            _ if arg.starts_with("--pin-root=") => pin_root = Some(parse_path_value(arg)?),
            _ if arg.starts_with("--tproxy-port=") => tproxy_port = Some(parse_value(arg)?),
            _ if arg.starts_with("--control-plane-pid=") => {
                control_plane_pid = Some(parse_value(arg)?)
            }
            _ if arg.starts_with("--dae0-ifindex=") => dae0_ifindex = Some(parse_value(arg)?),
            _ if arg.starts_with("--dae-netns-id=") => dae_netns_id = Some(parse_value(arg)?),
            _ if arg.starts_with("--dae0peer-mac=") => {
                dae0peer_mac = Some(parse_mac(split_value(arg)?)?)
            }
            _ if arg.starts_with("--has-bpf-get-current-task=") => {
                has_bpf_get_current_task = Some(parse_bool(split_value(arg)?)?)
            }
            _ => return Err(format!("unsupported bpf-loader load-pin argument: {arg}")),
        }
    }
    if object_source == Some(BpfObjectSource::CAya) && object.is_none() {
        return Err("bpf-loader load-pin --object-source=c-aya requires --object".to_owned());
    }
    Ok(BpfLoaderLoadPinOptions {
        object,
        object_source,
        pin_root: pin_root.ok_or_else(|| "missing bpf-loader load-pin --pin-root".to_owned())?,
        tproxy_port: tproxy_port
            .ok_or_else(|| "missing bpf-loader load-pin --tproxy-port".to_owned())?,
        control_plane_pid: control_plane_pid
            .ok_or_else(|| "missing bpf-loader load-pin --control-plane-pid".to_owned())?,
        dae0_ifindex: dae0_ifindex
            .ok_or_else(|| "missing bpf-loader load-pin --dae0-ifindex".to_owned())?,
        dae_netns_id: dae_netns_id
            .ok_or_else(|| "missing bpf-loader load-pin --dae-netns-id".to_owned())?,
        dae0peer_mac: dae0peer_mac
            .ok_or_else(|| "missing bpf-loader load-pin --dae0peer-mac".to_owned())?,
        has_bpf_get_current_task: has_bpf_get_current_task
            .ok_or_else(|| "missing bpf-loader load-pin --has-bpf-get-current-task".to_owned())?,
    })
}

fn parse_map_stats_count_options(args: &[String]) -> Result<Vec<MapStatsCountRequest>, String> {
    let mut maps = Vec::new();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--map" => maps.push(parse_map_count_request(next_value(
                &mut iter,
                "map-stats count --map",
            )?)?),
            _ if arg.starts_with("--map=") => {
                maps.push(parse_map_count_request(split_value(arg)?)?)
            }
            _ => return Err(format!("unsupported map-stats count argument: {arg}")),
        }
    }
    Ok(maps)
}

fn parse_trace_load_pin_options(args: &[String]) -> Result<TraceLoaderLoadPinOptions, String> {
    let mut object = None;
    let mut pin_root = None;
    let mut ip_version = None;
    let mut l4_proto = None;
    let mut port = None;
    let mut ringbuf_size = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--object" => object = Some(parse_next_path(&mut iter, "trace-loader --object")?),
            "--pin-root" => pin_root = Some(parse_next_path(&mut iter, "trace-loader --pin-root")?),
            "--ip-version" => {
                ip_version = Some(parse_next::<u8>(&mut iter, "trace-loader --ip-version")?)
            }
            "--l4-proto" => {
                l4_proto = Some(parse_next::<u16>(&mut iter, "trace-loader --l4-proto")?)
            }
            "--port" => port = Some(parse_next::<u16>(&mut iter, "trace-loader --port")?),
            "--ringbuf-size" => {
                ringbuf_size = Some(parse_next::<u32>(&mut iter, "trace-loader --ringbuf-size")?)
            }
            _ if arg.starts_with("--object=") => object = Some(parse_path_value(arg)?),
            _ if arg.starts_with("--pin-root=") => pin_root = Some(parse_path_value(arg)?),
            _ if arg.starts_with("--ip-version=") => ip_version = Some(parse_value(arg)?),
            _ if arg.starts_with("--l4-proto=") => l4_proto = Some(parse_value(arg)?),
            _ if arg.starts_with("--port=") => port = Some(parse_value(arg)?),
            _ if arg.starts_with("--ringbuf-size=") => ringbuf_size = Some(parse_value(arg)?),
            _ => return Err(format!("unsupported trace-loader load-pin argument: {arg}")),
        }
    }
    Ok(TraceLoaderLoadPinOptions {
        object: object.ok_or_else(|| "missing trace-loader load-pin --object".to_owned())?,
        pin_root: pin_root.ok_or_else(|| "missing trace-loader load-pin --pin-root".to_owned())?,
        ip_version: ip_version
            .ok_or_else(|| "missing trace-loader load-pin --ip-version".to_owned())?,
        l4_proto: l4_proto.ok_or_else(|| "missing trace-loader load-pin --l4-proto".to_owned())?,
        port: port.ok_or_else(|| "missing trace-loader load-pin --port".to_owned())?,
        ringbuf_size: ringbuf_size
            .ok_or_else(|| "missing trace-loader load-pin --ringbuf-size".to_owned())?,
    })
}

fn parse_trace_attach_ringbuf_smoke_options(
    args: &[String],
) -> Result<TraceLoaderAttachRingbufSmokeOptions, String> {
    let mut object = None;
    let mut target = None;
    let mut program_name = Some("kprobe_skb_1".to_owned());
    let mut ip_version = Some(4_u8);
    let mut l4_proto = Some(6_u16);
    let mut port = Some(443_u16);
    let mut ringbuf_size = Some(65_536_u32);
    let mut trigger = Some(TraceLoaderAttachSmokeTrigger::LoopbackUdp);
    let mut trigger_count = Some(4_u32);
    let mut poll_attempts = Some(50_u32);
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--object" => {
                object = Some(parse_next_path(
                    &mut iter,
                    "trace-loader attach-ringbuf-smoke --object",
                )?)
            }
            "--target" => {
                target = Some(
                    next_value(&mut iter, "trace-loader attach-ringbuf-smoke --target")?.to_owned(),
                )
            }
            "--program-name" => {
                program_name = Some(
                    next_value(
                        &mut iter,
                        "trace-loader attach-ringbuf-smoke --program-name",
                    )?
                    .to_owned(),
                )
            }
            "--ip-version" => {
                ip_version = Some(parse_next::<u8>(
                    &mut iter,
                    "trace-loader attach-ringbuf-smoke --ip-version",
                )?)
            }
            "--l4-proto" => {
                l4_proto = Some(parse_next::<u16>(
                    &mut iter,
                    "trace-loader attach-ringbuf-smoke --l4-proto",
                )?)
            }
            "--port" => {
                port = Some(parse_next::<u16>(
                    &mut iter,
                    "trace-loader attach-ringbuf-smoke --port",
                )?)
            }
            "--ringbuf-size" => {
                ringbuf_size = Some(parse_next::<u32>(
                    &mut iter,
                    "trace-loader attach-ringbuf-smoke --ringbuf-size",
                )?)
            }
            "--trigger" => {
                trigger = Some(TraceLoaderAttachSmokeTrigger::parse(next_value(
                    &mut iter,
                    "trace-loader attach-ringbuf-smoke --trigger",
                )?)?)
            }
            "--trigger-count" => {
                trigger_count = Some(parse_next::<u32>(
                    &mut iter,
                    "trace-loader attach-ringbuf-smoke --trigger-count",
                )?)
            }
            "--poll-attempts" => {
                poll_attempts = Some(parse_next::<u32>(
                    &mut iter,
                    "trace-loader attach-ringbuf-smoke --poll-attempts",
                )?)
            }
            _ if arg.starts_with("--object=") => object = Some(parse_path_value(arg)?),
            _ if arg.starts_with("--target=") => target = Some(split_value(arg)?.to_owned()),
            _ if arg.starts_with("--program-name=") => {
                program_name = Some(split_value(arg)?.to_owned())
            }
            _ if arg.starts_with("--ip-version=") => ip_version = Some(parse_value(arg)?),
            _ if arg.starts_with("--l4-proto=") => l4_proto = Some(parse_value(arg)?),
            _ if arg.starts_with("--port=") => port = Some(parse_value(arg)?),
            _ if arg.starts_with("--ringbuf-size=") => ringbuf_size = Some(parse_value(arg)?),
            _ if arg.starts_with("--trigger=") => {
                trigger = Some(TraceLoaderAttachSmokeTrigger::parse(split_value(arg)?)?)
            }
            _ if arg.starts_with("--trigger-count=") => trigger_count = Some(parse_value(arg)?),
            _ if arg.starts_with("--poll-attempts=") => poll_attempts = Some(parse_value(arg)?),
            _ => {
                return Err(format!(
                    "unsupported trace-loader attach-ringbuf-smoke argument: {arg}"
                ));
            }
        }
    }
    Ok(TraceLoaderAttachRingbufSmokeOptions {
        object: object
            .ok_or_else(|| "missing trace-loader attach-ringbuf-smoke --object".to_owned())?,
        target: target
            .ok_or_else(|| "missing trace-loader attach-ringbuf-smoke --target".to_owned())?,
        program_name: program_name
            .ok_or_else(|| "missing trace-loader attach-ringbuf-smoke --program-name".to_owned())?,
        ip_version: ip_version
            .ok_or_else(|| "missing trace-loader attach-ringbuf-smoke --ip-version".to_owned())?,
        l4_proto: l4_proto
            .ok_or_else(|| "missing trace-loader attach-ringbuf-smoke --l4-proto".to_owned())?,
        port: port.ok_or_else(|| "missing trace-loader attach-ringbuf-smoke --port".to_owned())?,
        ringbuf_size: ringbuf_size
            .ok_or_else(|| "missing trace-loader attach-ringbuf-smoke --ringbuf-size".to_owned())?,
        trigger: trigger
            .ok_or_else(|| "missing trace-loader attach-ringbuf-smoke --trigger".to_owned())?,
        trigger_count: trigger_count.ok_or_else(|| {
            "missing trace-loader attach-ringbuf-smoke --trigger-count".to_owned()
        })?,
        poll_attempts: poll_attempts.ok_or_else(|| {
            "missing trace-loader attach-ringbuf-smoke --poll-attempts".to_owned()
        })?,
    })
}

fn parse_cgroup_monitor_attach_pin_options(
    args: &[String],
) -> Result<CgroupMonitorAttachPinOptions, String> {
    let mut program_root = None;
    let mut link_root = None;
    let mut cgroup_path = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--program-root" => {
                program_root = Some(parse_next_path(
                    &mut iter,
                    "cgroup-monitor attach-pin --program-root",
                )?)
            }
            "--link-root" => {
                link_root = Some(parse_next_path(
                    &mut iter,
                    "cgroup-monitor attach-pin --link-root",
                )?)
            }
            "--cgroup-path" => {
                cgroup_path = Some(parse_next_path(
                    &mut iter,
                    "cgroup-monitor attach-pin --cgroup-path",
                )?)
            }
            _ if arg.starts_with("--program-root=") => program_root = Some(parse_path_value(arg)?),
            _ if arg.starts_with("--link-root=") => link_root = Some(parse_path_value(arg)?),
            _ if arg.starts_with("--cgroup-path=") => cgroup_path = Some(parse_path_value(arg)?),
            _ => {
                return Err(format!(
                    "unsupported cgroup-monitor attach-pin argument: {arg}"
                ));
            }
        }
    }
    Ok(CgroupMonitorAttachPinOptions {
        program_root: program_root
            .ok_or_else(|| "missing cgroup-monitor attach-pin --program-root".to_owned())?,
        link_root: link_root
            .ok_or_else(|| "missing cgroup-monitor attach-pin --link-root".to_owned())?,
        cgroup_path: cgroup_path
            .ok_or_else(|| "missing cgroup-monitor attach-pin --cgroup-path".to_owned())?,
    })
}

fn parse_tc_attach_pin_options(args: &[String]) -> Result<TcAttachPinOptions, String> {
    let mut program_root = None;
    let mut link_root = None;
    let mut program_name = None;
    let mut iface = None;
    let mut netns = None;
    let mut direction = None;
    let mut priority = None;
    let mut handle = None;
    let mut backend = None;
    let mut filter_name = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--program-root" => {
                program_root = Some(parse_next_path(
                    &mut iter,
                    "tc-attach attach-pin --program-root",
                )?)
            }
            "--link-root" => {
                link_root = Some(parse_next_path(
                    &mut iter,
                    "tc-attach attach-pin --link-root",
                )?)
            }
            "--program-name" => {
                program_name =
                    Some(next_value(&mut iter, "tc-attach attach-pin --program-name")?.to_owned())
            }
            "--iface" => {
                iface = Some(next_value(&mut iter, "tc-attach attach-pin --iface")?.to_owned())
            }
            "--netns" => {
                netns = Some(next_value(&mut iter, "tc-attach attach-pin --netns")?.to_owned())
            }
            "--direction" => {
                direction = Some(parse_tc_attach_direction(next_value(
                    &mut iter,
                    "tc-attach attach-pin --direction",
                )?)?)
            }
            "--priority" => {
                priority = Some(parse_next::<u16>(
                    &mut iter,
                    "tc-attach attach-pin --priority",
                )?)
            }
            "--handle" => {
                handle = Some(parse_next::<u32>(
                    &mut iter,
                    "tc-attach attach-pin --handle",
                )?)
            }
            "--backend" => {
                backend = Some(parse_attach_backend(next_value(
                    &mut iter,
                    "tc-attach attach-pin --backend",
                )?)?)
            }
            "--filter-name" => {
                filter_name =
                    Some(next_value(&mut iter, "tc-attach attach-pin --filter-name")?.to_owned())
            }
            _ if arg.starts_with("--program-root=") => program_root = Some(parse_path_value(arg)?),
            _ if arg.starts_with("--link-root=") => link_root = Some(parse_path_value(arg)?),
            _ if arg.starts_with("--program-name=") => {
                program_name = Some(split_value(arg)?.to_owned())
            }
            _ if arg.starts_with("--iface=") => iface = Some(split_value(arg)?.to_owned()),
            _ if arg.starts_with("--netns=") => netns = Some(split_value(arg)?.to_owned()),
            _ if arg.starts_with("--direction=") => {
                direction = Some(parse_tc_attach_direction(split_value(arg)?)?)
            }
            _ if arg.starts_with("--priority=") => priority = Some(parse_value(arg)?),
            _ if arg.starts_with("--handle=") => handle = Some(parse_value(arg)?),
            _ if arg.starts_with("--backend=") => {
                backend = Some(parse_attach_backend(split_value(arg)?)?)
            }
            _ if arg.starts_with("--filter-name=") => {
                filter_name = Some(split_value(arg)?.to_owned())
            }
            _ => return Err(format!("unsupported tc-attach attach-pin argument: {arg}")),
        }
    }
    Ok(TcAttachPinOptions {
        program_root: program_root
            .ok_or_else(|| "missing tc-attach attach-pin --program-root".to_owned())?,
        link_root: link_root
            .ok_or_else(|| "missing tc-attach attach-pin --link-root".to_owned())?,
        program_name: program_name
            .ok_or_else(|| "missing tc-attach attach-pin --program-name".to_owned())?,
        iface: iface.ok_or_else(|| "missing tc-attach attach-pin --iface".to_owned())?,
        netns,
        direction: direction
            .ok_or_else(|| "missing tc-attach attach-pin --direction".to_owned())?,
        priority: priority.ok_or_else(|| "missing tc-attach attach-pin --priority".to_owned())?,
        handle: handle.ok_or_else(|| "missing tc-attach attach-pin --handle".to_owned())?,
        backend: backend.ok_or_else(|| "missing tc-attach attach-pin --backend".to_owned())?,
        filter_name,
    })
}

fn parse_tproxy_listener_open_handoff_options(
    args: &[String],
) -> Result<TproxyListenerOpenHandoffOptions, String> {
    let mut map_id = None;
    let mut port = None;
    let mut handoff_fd = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--map-id" => {
                map_id = Some(parse_next::<u32>(
                    &mut iter,
                    "tproxy-listener open-handoff --map-id",
                )?)
            }
            "--port" => {
                port = Some(parse_next::<u16>(
                    &mut iter,
                    "tproxy-listener open-handoff --port",
                )?)
            }
            "--handoff-fd" => {
                handoff_fd = Some(parse_next::<i32>(
                    &mut iter,
                    "tproxy-listener open-handoff --handoff-fd",
                )?)
            }
            _ if arg.starts_with("--map-id=") => map_id = Some(parse_value(arg)?),
            _ if arg.starts_with("--port=") => port = Some(parse_value(arg)?),
            _ if arg.starts_with("--handoff-fd=") => handoff_fd = Some(parse_value(arg)?),
            _ => {
                return Err(format!(
                    "unsupported tproxy-listener open-handoff argument: {arg}"
                ));
            }
        }
    }
    Ok(TproxyListenerOpenHandoffOptions {
        map_id: map_id.ok_or_else(|| "missing tproxy-listener open-handoff --map-id".to_owned())?,
        port: port.ok_or_else(|| "missing tproxy-listener open-handoff --port".to_owned())?,
        handoff_fd: handoff_fd
            .ok_or_else(|| "missing tproxy-listener open-handoff --handoff-fd".to_owned())?,
    })
}

fn parse_tproxy_listener_update_map_options(
    args: &[String],
) -> Result<TproxyListenerUpdateMapOptions, String> {
    let mut map_id = None;
    let mut tcp_fd = None;
    let mut udp_fd = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--map-id" => {
                map_id = Some(parse_next::<u32>(
                    &mut iter,
                    "tproxy-listener update-map --map-id",
                )?)
            }
            "--tcp-fd" => {
                tcp_fd = Some(parse_next::<i32>(
                    &mut iter,
                    "tproxy-listener update-map --tcp-fd",
                )?)
            }
            "--udp-fd" => {
                udp_fd = Some(parse_next::<i32>(
                    &mut iter,
                    "tproxy-listener update-map --udp-fd",
                )?)
            }
            _ if arg.starts_with("--map-id=") => map_id = Some(parse_value(arg)?),
            _ if arg.starts_with("--tcp-fd=") => tcp_fd = Some(parse_value(arg)?),
            _ if arg.starts_with("--udp-fd=") => udp_fd = Some(parse_value(arg)?),
            _ => {
                return Err(format!(
                    "unsupported tproxy-listener update-map argument: {arg}"
                ));
            }
        }
    }
    Ok(TproxyListenerUpdateMapOptions {
        map_id: map_id.ok_or_else(|| "missing tproxy-listener update-map --map-id".to_owned())?,
        tcp_fd: tcp_fd.ok_or_else(|| "missing tproxy-listener update-map --tcp-fd".to_owned())?,
        udp_fd: udp_fd.ok_or_else(|| "missing tproxy-listener update-map --udp-fd".to_owned())?,
    })
}

fn parse_connectivity_map_update_options(
    args: &[String],
) -> Result<ConnectivityMapUpdateOptions, String> {
    let mut map_id = None;
    let mut outbound = None;
    let mut l4_proto = None;
    let mut ip_version = None;
    let mut alive = None;
    let mut is_init = None;
    let mut dryrun = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--map-id" => {
                map_id = Some(parse_next::<u32>(
                    &mut iter,
                    "connectivity-map update --map-id",
                )?)
            }
            "--outbound" => {
                outbound = Some(parse_next::<u8>(
                    &mut iter,
                    "connectivity-map update --outbound",
                )?)
            }
            "--l4-proto" => {
                l4_proto = Some(parse_next::<u8>(
                    &mut iter,
                    "connectivity-map update --l4-proto",
                )?)
            }
            "--ip-version" => {
                ip_version = Some(parse_next::<u8>(
                    &mut iter,
                    "connectivity-map update --ip-version",
                )?)
            }
            "--alive" => {
                alive = Some(parse_bool(next_value(
                    &mut iter,
                    "connectivity-map update --alive",
                )?)?)
            }
            "--is-init" => {
                is_init = Some(parse_bool(next_value(
                    &mut iter,
                    "connectivity-map update --is-init",
                )?)?)
            }
            "--dryrun" => {
                dryrun = Some(parse_bool(next_value(
                    &mut iter,
                    "connectivity-map update --dryrun",
                )?)?)
            }
            _ if arg.starts_with("--map-id=") => map_id = Some(parse_value(arg)?),
            _ if arg.starts_with("--outbound=") => outbound = Some(parse_value(arg)?),
            _ if arg.starts_with("--l4-proto=") => l4_proto = Some(parse_value(arg)?),
            _ if arg.starts_with("--ip-version=") => ip_version = Some(parse_value(arg)?),
            _ if arg.starts_with("--alive=") => alive = Some(parse_bool(split_value(arg)?)?),
            _ if arg.starts_with("--is-init=") => is_init = Some(parse_bool(split_value(arg)?)?),
            _ if arg.starts_with("--dryrun=") => dryrun = Some(parse_bool(split_value(arg)?)?),
            _ => {
                return Err(format!(
                    "unsupported connectivity-map update argument: {arg}"
                ));
            }
        }
    }
    Ok(ConnectivityMapUpdateOptions {
        map_id: map_id.ok_or_else(|| "missing connectivity-map update --map-id".to_owned())?,
        outbound: outbound
            .ok_or_else(|| "missing connectivity-map update --outbound".to_owned())?,
        l4_proto: l4_proto
            .ok_or_else(|| "missing connectivity-map update --l4-proto".to_owned())?,
        ip_version: ip_version
            .ok_or_else(|| "missing connectivity-map update --ip-version".to_owned())?,
        alive: alive.ok_or_else(|| "missing connectivity-map update --alive".to_owned())?,
        is_init: is_init.ok_or_else(|| "missing connectivity-map update --is-init".to_owned())?,
        dryrun: dryrun.ok_or_else(|| "missing connectivity-map update --dryrun".to_owned())?,
    })
}

fn parse_map_count_request(value: &str) -> Result<MapStatsCountRequest, String> {
    let (name, id) = value
        .split_once(':')
        .ok_or_else(|| format!("bad map-stats count --map {value:?}; want name:id"))?;
    if name.trim().is_empty() {
        return Err(format!("bad map-stats count --map {value:?}; empty name"));
    }
    let id = id
        .parse::<u32>()
        .map_err(|err| format!("bad map id in --map {value:?}: {err}"))?;
    Ok(MapStatsCountRequest {
        name: name.to_owned(),
        id,
    })
}

fn next_value<'a>(
    iter: &mut impl Iterator<Item = &'a String>,
    name: &str,
) -> Result<&'a str, String> {
    iter.next()
        .map(String::as_str)
        .ok_or_else(|| format!("missing {name}"))
}

fn parse_next<'a, T: std::str::FromStr>(
    iter: &mut impl Iterator<Item = &'a String>,
    name: &str,
) -> Result<T, String>
where
    T::Err: std::fmt::Display,
{
    next_value(iter, name)?
        .parse()
        .map_err(|err| format!("bad {name}: {err}"))
}

fn parse_next_path<'a>(
    iter: &mut impl Iterator<Item = &'a String>,
    name: &str,
) -> Result<PathBuf, String> {
    Ok(PathBuf::from(next_value(iter, name)?))
}

fn parse_value<T: std::str::FromStr>(arg: &str) -> Result<T, String>
where
    T::Err: std::fmt::Display,
{
    split_value(arg)?
        .parse()
        .map_err(|err| format!("bad {arg}: {err}"))
}

fn parse_path_value(arg: &str) -> Result<PathBuf, String> {
    Ok(PathBuf::from(split_value(arg)?))
}

fn split_value(arg: &str) -> Result<&str, String> {
    arg.split_once('=')
        .map(|(_, value)| value)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("missing value for {arg}"))
}

fn parse_bool(value: &str) -> Result<bool, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(format!("bad bool value: {value}")),
    }
}

fn parse_tc_attach_direction(value: &str) -> Result<dae_ebpf_support::TcAttachDirection, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "ingress" => Ok(dae_ebpf_support::TcAttachDirection::Ingress),
        "egress" => Ok(dae_ebpf_support::TcAttachDirection::Egress),
        _ => Err(format!("bad tc attach direction: {value}")),
    }
}

fn parse_attach_backend(value: &str) -> Result<dae_ebpf_support::AttachBackend, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "" | "auto" => Ok(dae_ebpf_support::AttachBackend::Auto),
        "tcx" => Ok(dae_ebpf_support::AttachBackend::Tcx),
        "tc" | "tc-netlink" | "tc_netlink" => Ok(dae_ebpf_support::AttachBackend::TcNetlink),
        _ => Err(format!("bad tc attach backend: {value}")),
    }
}

fn parse_mac(value: &str) -> Result<[u8; 6], String> {
    let mut mac = [0_u8; 6];
    let parts = value.split(':').collect::<Vec<_>>();
    if parts.len() != mac.len() {
        return Err(format!("bad mac address: {value}"));
    }
    for (index, part) in parts.iter().enumerate() {
        if part.len() != 2 {
            return Err(format!("bad mac address: {value}"));
        }
        mac[index] =
            u8::from_str_radix(part, 16).map_err(|err| format!("bad mac address: {err}"))?;
    }
    Ok(mac)
}
