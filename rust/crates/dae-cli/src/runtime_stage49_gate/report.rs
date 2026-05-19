use super::smoke::execute_stage49_smoke;
use super::utils::*;
use super::*;

pub(super) fn stage49_report(opts: &Stage49Options) -> Value {
    let mut blockers = Vec::new();
    let mut checks = Vec::new();
    push_check(
        &mut checks,
        "isolated-root-under-tmp",
        tmp_root_allowed(&opts.root),
        json!({"path": path_string(&opts.root)}),
        &mut blockers,
        "stage49 root must be an absolute /tmp child path",
    );
    push_check(
        &mut checks,
        "root-gate-acknowledged",
        !opts.execute_smoke || opts.ack_root_gate,
        json!({"execute_smoke": opts.execute_smoke, "ack_root_gate": opts.ack_root_gate}),
        &mut blockers,
        "stage49 root-gated smoke requires --ack-root-gate",
    );
    for tool in ["ip", "tc"] {
        push_check(
            &mut checks,
            match tool {
                "ip" => "tool-ip-available",
                _ => "tool-tc-available",
            },
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
        "stage49 source eBPF object is missing",
    );
    push_check(
        &mut checks,
        "tproxy-port-valid",
        opts.tproxy_port != 0,
        json!({"tproxy_port": opts.tproxy_port}),
        &mut blockers,
        "stage49 tproxy port must be non-zero",
    );
    push_check(
        &mut checks,
        "dae-netns-id-valid",
        opts.dae_netns_id != 0,
        json!({"dae_netns_id": opts.dae_netns_id}),
        &mut blockers,
        "stage49 dae netns id must be non-zero",
    );
    if opts.execute_smoke {
        push_check(
            &mut checks,
            "production-names-free",
            !iface_exists(PRODUCTION_HOST_IFACE)
                && !iface_exists(PRODUCTION_PEER_IFACE)
                && !netns_exists(PRODUCTION_NETNS),
            json!({
                "host_iface": PRODUCTION_HOST_IFACE,
                "peer_iface": PRODUCTION_PEER_IFACE,
                "netns": PRODUCTION_NETNS,
            }),
            &mut blockers,
            "stage49 production names are already in use",
        );
        push_check(
            &mut checks,
            "tproxy-port-free",
            tproxy_port_available(opts.tproxy_port),
            json!({"tproxy_port": opts.tproxy_port}),
            &mut blockers,
            "stage49 tproxy port is already in use",
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
                blockers.push(format!("stage49 cannot snapshot BPF map ids: {err}"));
                Vec::new()
            }
        }
    } else {
        Vec::new()
    };
    let mut executed_steps = Vec::new();
    let mut cleanup_steps = Vec::new();
    let mut param_image = Value::Null;
    let mut topology_values = Value::Null;
    let mut peer_attach_show = Value::Null;
    let mut host_attach_show = Value::Null;
    let mut loaded_map_handoff = Value::Null;
    let mut combined_production_param_listener_smoke_passed = false;
    let mut transparent_listener_socket_options_verified = false;
    let mut discovered_map_id = None;
    if opts.execute_smoke && blockers.is_empty() {
        let result = execute_stage49_smoke(opts, &before_map_ids);
        executed_steps = result.executed_steps;
        cleanup_steps = result.cleanup_steps;
        param_image = result.param_image;
        topology_values = result.topology_values;
        peer_attach_show = result.peer_attach_show;
        host_attach_show = result.host_attach_show;
        loaded_map_handoff = result.loaded_map_handoff;
        combined_production_param_listener_smoke_passed = result.passed;
        transparent_listener_socket_options_verified = result.socket_options_verified;
        discovered_map_id = result.discovered_map_id;
        if !combined_production_param_listener_smoke_passed {
            blockers
                .push("stage49 combined production-name PARAM listener smoke failed".to_owned());
        }
    }
    let after_pin_snapshot = if opts.execute_smoke {
        bpf_dae_snapshot()
    } else {
        Vec::new()
    };
    let (after_map_ids, loaded_map_cleaned) = if opts.execute_smoke {
        wait_for_loaded_map_cleanup(discovered_map_id)
    } else {
        (Vec::new(), true)
    };
    if opts.execute_smoke && !loaded_map_cleaned {
        blockers.push("stage49 loaded listen_socket_map remains after cleanup".to_owned());
    }
    let leftovers = production_resource_leftovers();
    if opts.execute_smoke && !leftovers.is_empty() {
        blockers.push("stage49 production-named resources remain after cleanup".to_owned());
    }
    let sys_fs_bpf_dae_mutated = before_pin_snapshot != after_pin_snapshot;
    if opts.execute_smoke && sys_fs_bpf_dae_mutated {
        blockers.push("stage49 unexpectedly mutated /sys/fs/bpf/dae".to_owned());
    }

    let mut report = Map::new();
    report.insert(
        "name".to_owned(),
        json!("stage49-production-param-listener-admission"),
    );
    report.insert("stage".to_owned(), json!("stage49"));
    report.insert(
        "evidence_class".to_owned(),
        json!("root-gated-combined-production-name-param-aware-transparent-listener-smoke"),
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
        "combined_production_param_listener_smoke_passed".to_owned(),
        json!(combined_production_param_listener_smoke_passed),
    );
    report.insert(
        "combined_production_param_listener_admitted".to_owned(),
        json!(combined_production_param_listener_smoke_passed),
    );
    report.insert(
        "production_name_dae0_dae0peer_attach_executed".to_owned(),
        json!(opts.execute_smoke && combined_production_param_listener_smoke_passed),
    );
    report.insert(
        "param_aware_object_load_executed".to_owned(),
        json!(opts.execute_smoke && combined_production_param_listener_smoke_passed),
    );
    report.insert(
        "transparent_listener_socket_options_verified".to_owned(),
        json!(transparent_listener_socket_options_verified),
    );
    report.insert(
        "production_param_transparent_listener_handoff_executed".to_owned(),
        json!(opts.execute_smoke && combined_production_param_listener_smoke_passed),
    );
    for key in [
        "production_default_daemon_attach_executed",
        "active_tproxy_traffic_executed",
        "active_tcp_tproxy_admitted",
        "active_udp_tproxy_admitted",
        "active_dns_tproxy_admitted",
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
        "combined_contract".to_owned(),
        json!({
            "netns": PRODUCTION_NETNS,
            "host_iface": PRODUCTION_HOST_IFACE,
            "peer_iface": PRODUCTION_PEER_IFACE,
            "peer_section": opts.peer_section,
            "host_section": opts.host_section,
            "filter_pref": STAGE49_FILTER_PREF,
            "source_object": path_string(&opts.source_object),
            "param_object": path_string(&opts.param_object),
            "listen_socket_map_kernel_name": LISTEN_SOCKET_MAP_KERNEL_NAME,
            "expected_map_type": "SockMap",
            "expected_key_size": 4,
            "expected_value_size": 8,
            "expected_max_entries": 2,
            "listener_keys": [0, 1],
            "tproxy_port": opts.tproxy_port,
            "dae_netns_id": opts.dae_netns_id,
            "required_socket_options": [
                "IP_TRANSPARENT",
                "SO_REUSEADDR",
                "IP_RECVORIGDSTADDR or IPV6_RECVORIGDSTADDR"
            ]
        }),
    );
    report.insert("topology_values".to_owned(), topology_values);
    report.insert("param_image".to_owned(), param_image);
    report.insert(
        "map_id_snapshots".to_owned(),
        json!({
            "before_attach": before_map_ids,
            "after_cleanup": after_map_ids,
            "discovered_map_id": discovered_map_id,
            "loaded_map_cleaned": loaded_map_cleaned,
        }),
    );
    report.insert("loaded_map_handoff".to_owned(), loaded_map_handoff);
    report.insert(
        "temporary_production_named_resources".to_owned(),
        json!({
            "netns": PRODUCTION_NETNS,
            "host_iface": PRODUCTION_HOST_IFACE,
            "peer_iface": PRODUCTION_PEER_IFACE,
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
    report.insert("executed_steps".to_owned(), json!(executed_steps));
    report.insert("cleanup_steps".to_owned(), json!(cleanup_steps));
    report.insert("peer_attach_show".to_owned(), peer_attach_show);
    report.insert("host_attach_show".to_owned(), host_attach_show);
    report.insert("remaining_blockers".to_owned(), json!(remaining_blockers()));
    Value::Object(report)
}
