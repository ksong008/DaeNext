use super::*;

pub(super) fn stage54_report(opts: &Stage54Options) -> Value {
    let base = &opts.base;
    let mut blockers = Vec::new();
    let mut checks = Vec::new();
    push_check(
        &mut checks,
        "isolated-root-under-tmp",
        tmp_root_allowed(&base.root),
        json!({"path": path_string(&base.root)}),
        &mut blockers,
        "stage54 root must be an absolute /tmp child path",
    );
    push_check(
        &mut checks,
        "root-gate-acknowledged",
        !base.execute_smoke || base.ack_root_gate,
        json!({"execute_smoke": base.execute_smoke, "ack_root_gate": base.ack_root_gate}),
        &mut blockers,
        "stage54 root-gated smoke requires --ack-root-gate",
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
        base.source_object.exists(),
        json!({"path": path_string(&base.source_object)}),
        &mut blockers,
        "stage54 source eBPF object is missing",
    );
    push_check(
        &mut checks,
        "tproxy-port-valid",
        base.tproxy_port != 0,
        json!({"tproxy_port": base.tproxy_port}),
        &mut blockers,
        "stage54 tproxy port must be non-zero",
    );
    push_check(
        &mut checks,
        "target-port-is-dns",
        base.target_port == 53,
        json!({"target_port": base.target_port}),
        &mut blockers,
        "stage54 target port must be UDP/53",
    );
    push_check(
        &mut checks,
        "upstream-port-valid",
        opts.upstream_port != 0,
        json!({"upstream_port": opts.upstream_port}),
        &mut blockers,
        "stage54 upstream port must be non-zero",
    );
    if base.execute_smoke {
        push_check(
            &mut checks,
            "stage54-resource-names-free",
            resource_leftovers().is_empty(),
            json!({"leftovers": resource_leftovers()}),
            &mut blockers,
            "stage54 temporary or production names are already in use",
        );
        push_check(
            &mut checks,
            "tproxy-port-free",
            tproxy_port_available(base.tproxy_port),
            json!({"tproxy_port": base.tproxy_port}),
            &mut blockers,
            "stage54 tproxy port is already in use",
        );
        push_check(
            &mut checks,
            "upstream-port-free",
            tproxy_port_available(opts.upstream_port),
            json!({"upstream": format!("{}:{}", opts.upstream_ip, opts.upstream_port)}),
            &mut blockers,
            "stage54 local DNS upstream port is already in use",
        );
    }

    let before_pin_snapshot = if base.execute_smoke {
        bpf_dae_snapshot()
    } else {
        Vec::new()
    };
    let before_map_ids = if base.execute_smoke && blockers.is_empty() {
        match map_ids() {
            Ok(ids) => ids,
            Err(err) => {
                blockers.push(format!("stage54 cannot snapshot BPF map ids: {err}"));
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
    let mut dns_receive = Value::Null;
    let mut dns_controller = Value::Null;
    let mut dns_upstream = Value::Null;
    let mut dns_cache = stage54_dns_cache_model_json(opts);
    let mut domain_routing = Value::Null;
    let mut upstream_packet_conn = Value::Null;
    let mut client_traffic = Value::Null;
    let mut sendpkt_reply = Value::Null;
    let mut benchmark = Value::Null;
    let mut post_traffic_peer_stats = Value::Null;
    let mut post_traffic_lan_stats = Value::Null;
    let mut post_traffic_host_stats = Value::Null;
    let mut discovered_listen_map_id = None;
    let mut discovered_routing_map_id = None;
    let mut active_dns_tproxy_smoke_passed = false;
    let mut original_destination_observed = false;
    let mut dns_controller_recorded = false;
    let mut dns_upstream_query_recorded = false;
    let mut dns_response_validation_recorded = false;
    let mut dns_cache_restore_recorded = false;
    let mut domain_routing_owner_migration_recorded = false;
    let mut sendpkt_reply_recorded = false;
    let mut so_mark_observed = false;
    if base.execute_smoke && blockers.is_empty() {
        let result = execute_stage54_smoke(opts, &before_map_ids);
        executed_steps = result.executed_steps;
        cleanup_steps = result.cleanup_steps;
        topology_values = result.topology_values;
        param_image = result.param_image;
        peer_attach_show = result.peer_attach_show;
        lan_attach_show = result.lan_attach_show;
        host_attach_show = result.host_attach_show;
        loaded_map_handoff = result.loaded_map_handoff;
        route_map_update = result.route_map_update;
        dns_receive = result.dns_receive;
        dns_controller = result.dns_controller;
        dns_upstream = result.dns_upstream;
        dns_cache = result.dns_cache;
        domain_routing = result.domain_routing;
        upstream_packet_conn = result.upstream_packet_conn;
        client_traffic = result.client_traffic;
        sendpkt_reply = result.sendpkt_reply;
        benchmark = result.benchmark;
        post_traffic_peer_stats = result.post_traffic_peer_stats;
        post_traffic_lan_stats = result.post_traffic_lan_stats;
        post_traffic_host_stats = result.post_traffic_host_stats;
        discovered_listen_map_id = result.discovered_listen_map_id;
        discovered_routing_map_id = result.discovered_routing_map_id;
        active_dns_tproxy_smoke_passed = result.passed;
        original_destination_observed = result.original_destination_observed;
        dns_controller_recorded = result.dns_controller_recorded;
        dns_upstream_query_recorded = result.dns_upstream_query_recorded;
        dns_response_validation_recorded = result.dns_response_validation_recorded;
        dns_cache_restore_recorded = result.dns_cache_restore_recorded;
        domain_routing_owner_migration_recorded = result.domain_routing_owner_migration_recorded;
        sendpkt_reply_recorded = result.sendpkt_reply_recorded;
        so_mark_observed = result.so_mark_observed;
        if !active_dns_tproxy_smoke_passed {
            blockers.push("stage54 active DNS UDP/53 tproxy cache smoke failed".to_owned());
        }
    }
    let after_pin_snapshot = if base.execute_smoke {
        bpf_dae_snapshot()
    } else {
        Vec::new()
    };
    let (after_map_ids, loaded_maps_cleaned) = if base.execute_smoke {
        wait_for_loaded_map_cleanup(&[discovered_listen_map_id, discovered_routing_map_id])
    } else {
        (Vec::new(), true)
    };
    if base.execute_smoke && !loaded_maps_cleaned {
        blockers.push("stage54 loaded BPF maps remain after cleanup".to_owned());
    }
    let leftovers = resource_leftovers();
    if base.execute_smoke && !leftovers.is_empty() {
        blockers.push("stage54 resources remain after cleanup".to_owned());
    }
    let sys_fs_bpf_dae_mutated = before_pin_snapshot != after_pin_snapshot;
    if base.execute_smoke && sys_fs_bpf_dae_mutated {
        blockers.push("stage54 unexpectedly mutated /sys/fs/bpf/dae".to_owned());
    }

    let benchmark_recorded = base.execute_smoke
        && active_dns_tproxy_smoke_passed
        && benchmark["status"].as_str() == Some("pass");
    let active_dns_tproxy_admitted = active_dns_tproxy_smoke_passed
        && dns_controller_recorded
        && dns_upstream_query_recorded
        && dns_response_validation_recorded
        && dns_cache_restore_recorded
        && domain_routing_owner_migration_recorded
        && sendpkt_reply_recorded
        && so_mark_observed;
    let mut report = Map::new();
    report.insert(
        "name".to_owned(),
        json!("stage54-active-dns-tproxy-cache-admission"),
    );
    report.insert("stage".to_owned(), json!("stage54"));
    report.insert(
        "evidence_class".to_owned(),
        json!("root-gated-active-dns-udp53-cache-reload-smoke"),
    );
    report.insert("root".to_owned(), json!(path_string(&base.root)));
    report.insert("execute_smoke".to_owned(), json!(base.execute_smoke));
    report.insert(
        "root_gate_acknowledged".to_owned(),
        json!(base.ack_root_gate),
    );
    report.insert("read_only".to_owned(), json!(!base.execute_smoke));
    report.insert("blocked".to_owned(), json!(!blockers.is_empty()));
    report.insert(
        "active_dns_tproxy_smoke_passed".to_owned(),
        json!(active_dns_tproxy_smoke_passed),
    );
    report.insert(
        "active_dns_tproxy_admitted".to_owned(),
        json!(active_dns_tproxy_admitted),
    );
    report.insert(
        "active_dns_original_destination_observed".to_owned(),
        json!(original_destination_observed),
    );
    report.insert(
        "dns_controller_path_recorded".to_owned(),
        json!(dns_controller_recorded),
    );
    report.insert(
        "dns_upstream_query_recorded".to_owned(),
        json!(dns_upstream_query_recorded),
    );
    report.insert(
        "dns_response_validation_recorded".to_owned(),
        json!(dns_response_validation_recorded),
    );
    report.insert(
        "dns_cache_restore_recorded".to_owned(),
        json!(dns_cache_restore_recorded),
    );
    report.insert(
        "domain_routing_owner_migration_recorded".to_owned(),
        json!(domain_routing_owner_migration_recorded),
    );
    report.insert(
        "dns_sendpkt_reply_recorded".to_owned(),
        json!(sendpkt_reply_recorded),
    );
    report.insert(
        "dns_so_mark_upstream_socket_observed".to_owned(),
        json!(so_mark_observed),
    );
    report.insert(
        "active_dns_tproxy_benchmark_recorded".to_owned(),
        json!(benchmark_recorded),
    );
    report.insert(
        "active_tproxy_traffic_executed".to_owned(),
        json!(base.execute_smoke),
    );
    report.insert("active_udp_tproxy_admitted".to_owned(), json!(true));
    for key in [
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
        "active_dns_contract".to_owned(),
        json!({
            "netns": PRODUCTION_NETNS,
            "host_iface": PRODUCTION_HOST_IFACE,
            "peer_iface": PRODUCTION_PEER_IFACE,
            "client_netns": CLIENT_NETNS,
            "lan_host_iface": LAN_HOST_IFACE,
            "lan_client_iface": LAN_CLIENT_IFACE,
            "peer_section": base.peer_section,
            "host_section": base.host_section,
            "lan_section": base.lan_section,
            "filter_pref": STAGE50_FILTER_PREF,
            "lan_filter_pref": STAGE50_LAN_FILTER_PREF,
            "source_object": path_string(&base.source_object),
            "param_object": path_string(&base.param_object),
            "listen_socket_map_kernel_name": LISTEN_SOCKET_MAP_KERNEL_NAME,
            "routing_map_kernel_name": ROUTING_MAP_KERNEL_NAME,
            "routing_fallback_outbound": OUTBOUND_STAGE50_PROXY,
            "match_type_fallback": MATCH_TYPE_FALLBACK,
            "tproxy_port": base.tproxy_port,
            "dns_target": format!("{}:{}", base.target_ip, base.target_port),
            "dns_upstream": format!("{}:{}", opts.upstream_ip, opts.upstream_port),
            "client_ip": base.client_ip,
            "so_mark": base.so_mark,
            "mptcp_magic_network_flag": base.mptcp,
            "benchmark_iters": opts.benchmark_iters,
            "qname": opts.qname,
            "qtype": 1,
            "qclass": 1,
            "dns_nat_timeout_ms": DNS_NAT_TIMEOUT_MS,
            "anyfrom_timeout_ms": 5000,
            "restored_cache_hits_required": opts.benchmark_iters.saturating_sub(1),
        }),
    );
    report.insert("dns_receive".to_owned(), dns_receive);
    report.insert("dns_controller".to_owned(), dns_controller);
    report.insert("dns_upstream".to_owned(), dns_upstream);
    report.insert("dns_cache".to_owned(), dns_cache);
    report.insert("domain_routing".to_owned(), domain_routing);
    report.insert("upstream_packet_conn".to_owned(), upstream_packet_conn);
    report.insert("client_traffic".to_owned(), client_traffic);
    report.insert("sendpkt_reply".to_owned(), sendpkt_reply);
    report.insert("benchmark".to_owned(), benchmark);
    report.insert("topology_values".to_owned(), topology_values);
    report.insert("param_image".to_owned(), param_image);
    report.insert("loaded_map_handoff".to_owned(), loaded_map_handoff);
    report.insert("route_map_update".to_owned(), route_map_update);
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
    report.insert(
        "remaining_blockers".to_owned(),
        json!(remaining_blockers_after_stage54()),
    );
    Value::Object(report)
}

pub(super) struct Stage54SmokeResult {
    pub(super) passed: bool,
    pub(super) original_destination_observed: bool,
    pub(super) dns_controller_recorded: bool,
    pub(super) dns_upstream_query_recorded: bool,
    pub(super) dns_response_validation_recorded: bool,
    pub(super) dns_cache_restore_recorded: bool,
    pub(super) domain_routing_owner_migration_recorded: bool,
    pub(super) sendpkt_reply_recorded: bool,
    pub(super) so_mark_observed: bool,
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
    pub(super) dns_receive: Value,
    pub(super) dns_controller: Value,
    pub(super) dns_upstream: Value,
    pub(super) dns_cache: Value,
    pub(super) domain_routing: Value,
    pub(super) upstream_packet_conn: Value,
    pub(super) client_traffic: Value,
    pub(super) sendpkt_reply: Value,
    pub(super) benchmark: Value,
    pub(super) post_traffic_peer_stats: Value,
    pub(super) post_traffic_lan_stats: Value,
    pub(super) post_traffic_host_stats: Value,
}

pub(super) fn execute_stage54_smoke(
    opts: &Stage54Options,
    before_map_ids: &[u32],
) -> Stage54SmokeResult {
    let base = &opts.base;
    let mut executed_steps = Vec::new();
    let mut cleanup_steps = Vec::new();
    let mut ok = true;

    ok &= setup_production_topology(&mut executed_steps, base);
    ok &= setup_client_topology(&mut executed_steps, base);
    let (topology_values, dae0_ifindex, dae0_mac, dae0peer_mac) =
        read_topology_values(&mut executed_steps, base);
    ok &= topology_values["status"].as_str() == Some("pass");
    if let Some(dae0_mac) = dae0_mac {
        ok &= setup_production_ipv4_datapath(&mut executed_steps, dae0_mac);
    }
    let param_image = if let (Some(dae0_ifindex), Some(dae0peer_mac)) = (dae0_ifindex, dae0peer_mac)
    {
        write_param_image(base, dae0_ifindex, dae0peer_mac)
    } else {
        json!({
            "status": "skipped",
            "path": path_string(&base.param_object),
            "reason": "topology runtime PARAM values were not available",
        })
    };
    ok &= param_image["status"].as_str() == Some("pass")
        && param_image["rewritten_param_matches"]
            .as_bool()
            .unwrap_or(false);

    if ok {
        ok &= attach_peer_program(&mut executed_steps, base);
    }
    let peer_attach_show = show_peer_program(&mut executed_steps);

    let live_handoff = if ok {
        match open_live_loaded_tproxy_listen_socket_map_in_netns(
            before_map_ids,
            base.tproxy_port,
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
        ok &= attach_lan_program(&mut executed_steps, base);
    }
    let lan_attach_show = show_lan_program(&mut executed_steps);
    let (route_map_update, discovered_routing_map_id) = if ok {
        match update_stage50_routing_map(&before_lan_map_ids, base.so_mark) {
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
        ok &= attach_host_program(&mut executed_steps, base);
    }
    let host_attach_show = show_host_program(&mut executed_steps);

    let (
        dns_receive,
        dns_controller,
        dns_upstream,
        dns_cache,
        domain_routing,
        upstream_packet_conn,
        client_traffic,
        sendpkt_reply,
        benchmark,
        original_destination_observed,
        dns_controller_recorded,
        dns_upstream_query_recorded,
        dns_response_validation_recorded,
        dns_cache_restore_recorded,
        domain_routing_owner_migration_recorded,
        sendpkt_reply_recorded,
        so_mark_observed,
    ) = if ok {
        let udp_socket = live_handoff
            .as_ref()
            .and_then(|handoff| handoff.listeners.udp_socket.try_clone().ok());
        match udp_socket {
            Some(udp_socket) => run_active_dns_tproxy_cache_probe(udp_socket, opts),
            None => (
                json!({"status": "fail", "error": "failed to clone tproxy UDP socket"}),
                Value::Null,
                Value::Null,
                stage54_dns_cache_model_json(opts),
                Value::Null,
                Value::Null,
                Value::Null,
                Value::Null,
                Value::Null,
                false,
                false,
                false,
                false,
                false,
                false,
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
            Value::Null,
            stage54_dns_cache_model_json(opts),
            Value::Null,
            Value::Null,
            Value::Null,
            Value::Null,
            Value::Null,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
        )
    };
    let post_traffic_peer_stats = show_peer_program_stats(&mut executed_steps);
    let post_traffic_lan_stats = show_lan_program_stats(&mut executed_steps);
    let post_traffic_host_stats = show_host_program_stats(&mut executed_steps);
    ok &= dns_receive["status"].as_str() == Some("pass")
        && dns_controller["status"].as_str() == Some("pass")
        && dns_upstream["status"].as_str() == Some("pass")
        && dns_cache["status"].as_str() == Some("pass")
        && domain_routing["status"].as_str() == Some("pass")
        && upstream_packet_conn["status"].as_str() == Some("pass")
        && client_traffic["status"].as_str() == Some("pass")
        && sendpkt_reply["status"].as_str() == Some("pass")
        && original_destination_observed
        && dns_controller_recorded
        && dns_upstream_query_recorded
        && dns_response_validation_recorded
        && dns_cache_restore_recorded
        && domain_routing_owner_migration_recorded
        && sendpkt_reply_recorded
        && so_mark_observed;

    cleanup_stage50(&mut cleanup_steps);

    let peer_output = peer_attach_show["stdout"].as_str().unwrap_or_default();
    let lan_output = lan_attach_show["stdout"].as_str().unwrap_or_default();
    let host_output = host_attach_show["stdout"].as_str().unwrap_or_default();
    Stage54SmokeResult {
        passed: ok
            && peer_attach_show["status"].as_str() == Some("pass")
            && peer_output.contains(&base.peer_section)
            && peer_output.contains("tproxy_dae0peer")
            && lan_attach_show["status"].as_str() == Some("pass")
            && lan_output.contains(&base.lan_section)
            && lan_output.contains("tproxy_lan_ingr")
            && host_attach_show["status"].as_str() == Some("pass")
            && host_output.contains(&base.host_section)
            && host_output.contains("tproxy_dae0_ing")
            && resource_leftovers().is_empty(),
        original_destination_observed,
        dns_controller_recorded,
        dns_upstream_query_recorded,
        dns_response_validation_recorded,
        dns_cache_restore_recorded,
        domain_routing_owner_migration_recorded,
        sendpkt_reply_recorded,
        so_mark_observed,
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
        dns_receive,
        dns_controller,
        dns_upstream,
        dns_cache,
        domain_routing,
        upstream_packet_conn,
        client_traffic,
        sendpkt_reply,
        benchmark,
        post_traffic_peer_stats,
        post_traffic_lan_stats,
        post_traffic_host_stats,
    }
}
