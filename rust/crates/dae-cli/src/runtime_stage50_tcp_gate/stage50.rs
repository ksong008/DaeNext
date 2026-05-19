use super::*;

pub(super) fn stage50_report(opts: &Stage50Options) -> Value {
    let mut blockers = Vec::new();
    let mut checks = Vec::new();
    push_check(
        &mut checks,
        "isolated-root-under-tmp",
        tmp_root_allowed(&opts.root),
        json!({"path": path_string(&opts.root)}),
        &mut blockers,
        "stage50 root must be an absolute /tmp child path",
    );
    push_check(
        &mut checks,
        "root-gate-acknowledged",
        !opts.execute_smoke || opts.ack_root_gate,
        json!({"execute_smoke": opts.execute_smoke, "ack_root_gate": opts.ack_root_gate}),
        &mut blockers,
        "stage50 root-gated smoke requires --ack-root-gate",
    );
    for tool in ["ip", "tc", "python3", "sysctl"] {
        push_check(
            &mut checks,
            &format!("tool-{tool}-available"),
            command_exists(tool),
            json!({"tool": tool}),
            &mut blockers,
            "required host tool is missing",
        );
    }
    push_check(
        &mut checks,
        "source-object-present",
        opts.source_object.exists(),
        json!({"path": path_string(&opts.source_object)}),
        &mut blockers,
        "stage50 source eBPF object is missing",
    );
    push_check(
        &mut checks,
        "tproxy-port-valid",
        opts.tproxy_port != 0,
        json!({"tproxy_port": opts.tproxy_port}),
        &mut blockers,
        "stage50 tproxy port must be non-zero",
    );
    push_check(
        &mut checks,
        "target-port-valid",
        opts.target_port != 0,
        json!({"target_port": opts.target_port}),
        &mut blockers,
        "stage50 target port must be non-zero",
    );
    if opts.execute_smoke {
        push_check(
            &mut checks,
            "stage50-resource-names-free",
            resource_leftovers().is_empty(),
            json!({"leftovers": resource_leftovers()}),
            &mut blockers,
            "stage50 temporary or production names are already in use",
        );
        push_check(
            &mut checks,
            "tproxy-port-free",
            tproxy_port_available(opts.tproxy_port),
            json!({"tproxy_port": opts.tproxy_port}),
            &mut blockers,
            "stage50 tproxy port is already in use",
        );
    }

    let before_pin_snapshot = if opts.execute_smoke {
        bpf_dae_snapshot()
    } else {
        Vec::new()
    };
    let before_map_ids = if opts.execute_smoke && blockers.is_empty() {
        match map_ids() {
            Ok(ids) => ids,
            Err(err) => {
                blockers.push(format!("stage50 cannot snapshot BPF map ids: {err}"));
                Vec::new()
            }
        }
    } else {
        Vec::new()
    };
    let mut executed_steps = Vec::new();
    let mut cleanup_steps = Vec::new();
    let mut topology_values = Value::Null;
    let mut param_image = Value::Null;
    let mut peer_attach_show = Value::Null;
    let mut lan_attach_show = Value::Null;
    let mut host_attach_show = Value::Null;
    let mut loaded_map_handoff = Value::Null;
    let mut route_map_update = Value::Null;
    let mut tcp_accept = Value::Null;
    let mut client_traffic = Value::Null;
    let mut post_traffic_peer_stats = Value::Null;
    let mut post_traffic_lan_stats = Value::Null;
    let mut post_traffic_host_stats = Value::Null;
    let mut discovered_listen_map_id = None;
    let mut discovered_routing_map_id = None;
    let mut active_tcp_tproxy_ingress_smoke_passed = false;
    let mut original_destination_observed = false;
    let mut tcp_reply_path_succeeded = false;
    if opts.execute_smoke && blockers.is_empty() {
        let result = execute_stage50_smoke(opts, &before_map_ids);
        executed_steps = result.executed_steps;
        cleanup_steps = result.cleanup_steps;
        topology_values = result.topology_values;
        param_image = result.param_image;
        peer_attach_show = result.peer_attach_show;
        lan_attach_show = result.lan_attach_show;
        host_attach_show = result.host_attach_show;
        loaded_map_handoff = result.loaded_map_handoff;
        route_map_update = result.route_map_update;
        tcp_accept = result.tcp_accept;
        client_traffic = result.client_traffic;
        post_traffic_peer_stats = result.post_traffic_peer_stats;
        post_traffic_lan_stats = result.post_traffic_lan_stats;
        post_traffic_host_stats = result.post_traffic_host_stats;
        discovered_listen_map_id = result.discovered_listen_map_id;
        discovered_routing_map_id = result.discovered_routing_map_id;
        active_tcp_tproxy_ingress_smoke_passed = result.passed;
        original_destination_observed = result.original_destination_observed;
        tcp_reply_path_succeeded = result.tcp_reply_path_succeeded;
        if !active_tcp_tproxy_ingress_smoke_passed {
            blockers.push("stage50 active TCP tproxy ingress smoke failed".to_owned());
        }
    }
    let after_pin_snapshot = if opts.execute_smoke {
        bpf_dae_snapshot()
    } else {
        Vec::new()
    };
    let (after_map_ids, loaded_maps_cleaned) = if opts.execute_smoke {
        wait_for_loaded_map_cleanup(&[discovered_listen_map_id, discovered_routing_map_id])
    } else {
        (Vec::new(), true)
    };
    if opts.execute_smoke && !loaded_maps_cleaned {
        blockers.push("stage50 loaded BPF maps remain after cleanup".to_owned());
    }
    let leftovers = resource_leftovers();
    if opts.execute_smoke && !leftovers.is_empty() {
        blockers.push("stage50 resources remain after cleanup".to_owned());
    }
    let sys_fs_bpf_dae_mutated = before_pin_snapshot != after_pin_snapshot;
    if opts.execute_smoke && sys_fs_bpf_dae_mutated {
        blockers.push("stage50 unexpectedly mutated /sys/fs/bpf/dae".to_owned());
    }

    let mut report = Map::new();
    report.insert(
        "name".to_owned(),
        json!("stage50-active-tcp-tproxy-ingress-admission"),
    );
    report.insert("stage".to_owned(), json!("stage50"));
    report.insert(
        "evidence_class".to_owned(),
        json!("root-gated-active-tcp-tproxy-ingress-transparent-accept-smoke"),
    );
    report.insert("root".to_owned(), json!(path_string(&opts.root)));
    report.insert("execute_smoke".to_owned(), json!(opts.execute_smoke));
    report.insert(
        "root_gate_acknowledged".to_owned(),
        json!(opts.ack_root_gate),
    );
    report.insert("read_only".to_owned(), json!(!opts.execute_smoke));
    report.insert("blocked".to_owned(), json!(!blockers.is_empty()));
    report.insert(
        "active_tcp_tproxy_ingress_smoke_passed".to_owned(),
        json!(active_tcp_tproxy_ingress_smoke_passed),
    );
    report.insert(
        "active_tcp_tproxy_ingress_admitted".to_owned(),
        json!(active_tcp_tproxy_ingress_smoke_passed),
    );
    report.insert(
        "active_tcp_syn_reached_transparent_listener".to_owned(),
        json!(active_tcp_tproxy_ingress_smoke_passed),
    );
    report.insert(
        "original_destination_observed".to_owned(),
        json!(original_destination_observed),
    );
    report.insert(
        "tcp_reply_path_succeeded".to_owned(),
        json!(tcp_reply_path_succeeded),
    );
    report.insert(
        "active_tproxy_traffic_executed".to_owned(),
        json!(opts.execute_smoke),
    );
    report.insert(
        "active_tcp_tproxy_admitted".to_owned(),
        json!(active_tcp_tproxy_ingress_smoke_passed && original_destination_observed),
    );
    for key in [
        "active_udp_tproxy_admitted",
        "active_dns_tproxy_admitted",
        "route_dial_tcp_rust_control_plane_executed",
        "outbound_true_dataplane_admitted",
        "matched_go_rust_default_daemon_benchmark_recorded",
        "default_switch_allowed",
        "default_path_mutated",
        "product_chain_switch_allowed",
        "true_rust_default_daemon_admitted",
    ] {
        report.insert(key.to_owned(), json!(false));
    }
    report.insert("go_default_path_preserved".to_owned(), json!(true));
    report.insert("go_fallback_required".to_owned(), json!(true));
    report.insert("blockers".to_owned(), json!(blockers));
    report.insert("checks".to_owned(), json!(checks));
    report.insert(
        "active_tcp_contract".to_owned(),
        json!({
            "netns": PRODUCTION_NETNS,
            "host_iface": PRODUCTION_HOST_IFACE,
            "peer_iface": PRODUCTION_PEER_IFACE,
            "client_netns": CLIENT_NETNS,
            "lan_host_iface": LAN_HOST_IFACE,
            "lan_client_iface": LAN_CLIENT_IFACE,
            "peer_section": opts.peer_section,
            "host_section": opts.host_section,
            "lan_section": opts.lan_section,
            "filter_pref": STAGE50_FILTER_PREF,
            "lan_filter_pref": STAGE50_LAN_FILTER_PREF,
            "source_object": path_string(&opts.source_object),
            "param_object": path_string(&opts.param_object),
            "listen_socket_map_kernel_name": LISTEN_SOCKET_MAP_KERNEL_NAME,
            "routing_map_kernel_name": ROUTING_MAP_KERNEL_NAME,
            "routing_fallback_outbound": OUTBOUND_STAGE50_PROXY,
            "match_type_fallback": MATCH_TYPE_FALLBACK,
            "tproxy_port": opts.tproxy_port,
            "target": format!("{}:{}", opts.target_ip, opts.target_port),
            "lan_gateway_ip": DEFAULT_STAGE50_LAN_GATEWAY_IP,
            "client_ip": opts.client_ip,
            "so_mark": opts.so_mark,
            "mptcp": opts.mptcp,
            "route_dial_tcp_required_later": true,
        }),
    );
    report.insert("topology_values".to_owned(), topology_values);
    report.insert("param_image".to_owned(), param_image);
    report.insert("loaded_map_handoff".to_owned(), loaded_map_handoff);
    report.insert("route_map_update".to_owned(), route_map_update);
    report.insert("tcp_accept".to_owned(), tcp_accept);
    report.insert("client_traffic".to_owned(), client_traffic);
    report.insert(
        "post_traffic_peer_stats".to_owned(),
        post_traffic_peer_stats,
    );
    report.insert("post_traffic_lan_stats".to_owned(), post_traffic_lan_stats);
    report.insert(
        "post_traffic_host_stats".to_owned(),
        post_traffic_host_stats,
    );
    report.insert("executed_steps".to_owned(), json!(executed_steps));
    report.insert("cleanup_steps".to_owned(), json!(cleanup_steps));
    report.insert("peer_attach_show".to_owned(), peer_attach_show);
    report.insert("lan_attach_show".to_owned(), lan_attach_show);
    report.insert("host_attach_show".to_owned(), host_attach_show);
    report.insert(
        "map_id_snapshots".to_owned(),
        json!({
            "before_attach": before_map_ids,
            "after_cleanup": after_map_ids,
            "discovered_listen_map_id": discovered_listen_map_id,
            "discovered_routing_map_id": discovered_routing_map_id,
            "loaded_maps_cleaned": loaded_maps_cleaned,
        }),
    );
    report.insert(
        "temporary_resources".to_owned(),
        json!({
            "leftovers_after_cleanup": leftovers,
        }),
    );
    report.insert(
        "sys_fs_bpf_dae".to_owned(),
        json!({
            "before": before_pin_snapshot,
            "after": after_pin_snapshot,
            "mutated": sys_fs_bpf_dae_mutated,
        }),
    );
    report.insert("remaining_blockers".to_owned(), json!(remaining_blockers()));
    Value::Object(report)
}

pub(super) struct Stage50SmokeResult {
    pub(super) passed: bool,
    pub(super) original_destination_observed: bool,
    pub(super) tcp_reply_path_succeeded: bool,
    pub(super) discovered_listen_map_id: Option<u32>,
    pub(super) discovered_routing_map_id: Option<u32>,
    pub(super) executed_steps: Vec<Value>,
    pub(super) cleanup_steps: Vec<Value>,
    pub(super) topology_values: Value,
    pub(super) param_image: Value,
    pub(super) peer_attach_show: Value,
    pub(super) lan_attach_show: Value,
    pub(super) host_attach_show: Value,
    pub(super) loaded_map_handoff: Value,
    pub(super) route_map_update: Value,
    pub(super) tcp_accept: Value,
    pub(super) client_traffic: Value,
    pub(super) post_traffic_peer_stats: Value,
    pub(super) post_traffic_lan_stats: Value,
    pub(super) post_traffic_host_stats: Value,
}

pub(super) fn execute_stage50_smoke(
    opts: &Stage50Options,
    before_map_ids: &[u32],
) -> Stage50SmokeResult {
    let mut executed_steps = Vec::new();
    let mut cleanup_steps = Vec::new();
    let mut ok = true;

    ok &= setup_production_topology(&mut executed_steps, opts);
    ok &= setup_client_topology(&mut executed_steps, opts);
    let (topology_values, dae0_ifindex, dae0_mac, dae0peer_mac) =
        read_topology_values(&mut executed_steps, opts);
    ok &= topology_values["status"].as_str() == Some("pass");
    if let Some(dae0_mac) = dae0_mac {
        ok &= setup_production_ipv4_datapath(&mut executed_steps, dae0_mac);
    }
    let param_image = if let (Some(dae0_ifindex), Some(dae0peer_mac)) = (dae0_ifindex, dae0peer_mac)
    {
        write_param_image(opts, dae0_ifindex, dae0peer_mac)
    } else {
        json!({
            "status": "skipped",
            "path": path_string(&opts.param_object),
            "reason": "topology runtime PARAM values were not available",
        })
    };
    ok &= param_image["status"].as_str() == Some("pass")
        && param_image["rewritten_param_matches"]
            .as_bool()
            .unwrap_or(false);

    if ok {
        ok &= attach_peer_program(&mut executed_steps, opts);
    }
    let peer_attach_show = show_peer_program(&mut executed_steps);

    let live_handoff = if ok {
        match open_live_loaded_tproxy_listen_socket_map_in_netns(
            before_map_ids,
            opts.tproxy_port,
            PRODUCTION_NETNS,
        ) {
            Ok(handoff) => Some(handoff),
            Err(err) => {
                ok = false;
                executed_steps.push(json!({
                    "name": "open-live-loaded-tproxy-listen-socket-map",
                    "status": "fail",
                    "error": err.to_string(),
                }));
                None
            }
        }
    } else {
        None
    };
    let (loaded_map_handoff, discovered_listen_map_id) = match live_handoff.as_ref() {
        Some(handoff) => (live_handoff_json(handoff), Some(handoff.map.id)),
        None => (
            json!({
                "status": "skipped",
                "reason": "peer PARAM-aware attach did not pass",
            }),
            None,
        ),
    };

    let before_lan_map_ids = map_ids().unwrap_or_default();
    if ok {
        ok &= attach_lan_program(&mut executed_steps, opts);
    }
    let lan_attach_show = show_lan_program(&mut executed_steps);
    let (route_map_update, discovered_routing_map_id) = if ok {
        match update_stage50_routing_map(&before_lan_map_ids, opts.so_mark) {
            Ok((value, id)) => (value, Some(id)),
            Err(err) => {
                ok = false;
                (json!({"status": "fail", "error": err}), None)
            }
        }
    } else {
        (
            json!({
                "status": "skipped",
                "reason": "LAN PARAM-aware attach did not pass",
            }),
            None,
        )
    };

    if ok {
        ok &= attach_host_program(&mut executed_steps, opts);
    }
    let host_attach_show = show_host_program(&mut executed_steps);

    let (tcp_accept, client_traffic, original_destination_observed, tcp_reply_path_succeeded) =
        if ok {
            let listener = live_handoff
                .as_ref()
                .and_then(|handoff| handoff.listeners.tcp_listener.try_clone().ok());
            match listener {
                Some(listener) => run_active_tcp_probe(listener, opts),
                None => (
                    json!({"status": "fail", "error": "failed to clone tproxy TCP listener"}),
                    Value::Null,
                    false,
                    false,
                ),
            }
        } else {
            (
                json!({
                    "status": "skipped",
                    "reason": "BPF attach or routing map update did not pass",
                }),
                Value::Null,
                false,
                false,
            )
        };
    let post_traffic_peer_stats = show_peer_program_stats(&mut executed_steps);
    let post_traffic_lan_stats = show_lan_program_stats(&mut executed_steps);
    let post_traffic_host_stats = show_host_program_stats(&mut executed_steps);
    ok &= tcp_accept["status"].as_str() == Some("pass")
        && client_traffic["status"].as_str() == Some("pass")
        && original_destination_observed;

    cleanup_stage50(&mut cleanup_steps);

    let peer_output = peer_attach_show["stdout"].as_str().unwrap_or_default();
    let lan_output = lan_attach_show["stdout"].as_str().unwrap_or_default();
    let host_output = host_attach_show["stdout"].as_str().unwrap_or_default();
    Stage50SmokeResult {
        passed: ok
            && peer_attach_show["status"].as_str() == Some("pass")
            && peer_output.contains(&opts.peer_section)
            && peer_output.contains("tproxy_dae0peer")
            && lan_attach_show["status"].as_str() == Some("pass")
            && lan_output.contains(&opts.lan_section)
            && lan_output.contains("tproxy_lan_ingr")
            && host_attach_show["status"].as_str() == Some("pass")
            && host_output.contains(&opts.host_section)
            && host_output.contains("tproxy_dae0_ing")
            && resource_leftovers().is_empty(),
        original_destination_observed,
        tcp_reply_path_succeeded,
        discovered_listen_map_id,
        discovered_routing_map_id,
        executed_steps,
        cleanup_steps,
        topology_values,
        param_image,
        peer_attach_show,
        lan_attach_show,
        host_attach_show,
        loaded_map_handoff,
        route_map_update,
        tcp_accept,
        client_traffic,
        post_traffic_peer_stats,
        post_traffic_lan_stats,
        post_traffic_host_stats,
    }
}
