use super::smoke::execute_stage38_smoke;
use super::utils::*;
use super::*;

pub(super) fn stage38_report(opts: &Stage38Options) -> Value {
    let mut blockers = Vec::new();
    let mut checks = Vec::new();
    push_check(
        &mut checks,
        "isolated-root-under-tmp",
        tmp_root_allowed(&opts.root),
        json!({"path": path_string(&opts.root)}),
        &mut blockers,
        "stage38 root must be an absolute /tmp child path",
    );
    push_check(
        &mut checks,
        "root-gate-acknowledged",
        !opts.execute_smoke || opts.ack_root_gate,
        json!({"execute_smoke": opts.execute_smoke, "ack_root_gate": opts.ack_root_gate}),
        &mut blockers,
        "stage38 root-gated smoke requires --ack-root-gate",
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
        "real-dae-object-present",
        opts.object_path.exists(),
        json!({"path": path_string(&opts.object_path)}),
        &mut blockers,
        "stage38 real dae eBPF object is missing",
    );
    let stage37 = read_report(
        opts.stage37_report.as_deref(),
        "loaded_listen_socket_map_handoff_smoke_passed",
    );
    push_check(
        &mut checks,
        "stage37-real-loaded-map-report-passed",
        !opts.execute_smoke || stage37.passed,
        json!({
            "path": stage37.path.clone(),
            "status": stage37.status,
            "loaded_listen_socket_map_handoff_smoke_passed": stage37.passed,
            "blockers": stage37.blockers.clone(),
        }),
        &mut blockers,
        "stage38 root-gated smoke requires a passed Stage 37 real loaded map report",
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
            "stage38 production names are already in use",
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
                blockers.push(format!("stage38 cannot snapshot BPF map ids: {err}"));
                Vec::new()
            }
        }
    } else {
        Vec::new()
    };
    let mut executed_steps = Vec::new();
    let mut cleanup_steps = Vec::new();
    let mut peer_attach_show = Value::Null;
    let mut host_attach_show = Value::Null;
    let mut loaded_map_handoff = Value::Null;
    let mut production_name_attach_handoff_smoke_passed = false;
    let mut discovered_map_id = None;
    if opts.execute_smoke && blockers.is_empty() {
        let result = execute_stage38_smoke(opts, &before_map_ids);
        executed_steps = result.executed_steps;
        cleanup_steps = result.cleanup_steps;
        peer_attach_show = result.peer_attach_show;
        host_attach_show = result.host_attach_show;
        loaded_map_handoff = result.loaded_map_handoff;
        production_name_attach_handoff_smoke_passed = result.passed;
        discovered_map_id = result.discovered_map_id;
        if !production_name_attach_handoff_smoke_passed {
            blockers.push("stage38 production-name dae attach handoff smoke failed".to_owned());
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
        blockers.push("stage38 loaded listen_socket_map remains after cleanup".to_owned());
    }
    let leftovers = production_resource_leftovers();
    if opts.execute_smoke && !leftovers.is_empty() {
        blockers.push("stage38 production-named resources remain after cleanup".to_owned());
    }
    let sys_fs_bpf_dae_mutated = before_pin_snapshot != after_pin_snapshot;
    if opts.execute_smoke && sys_fs_bpf_dae_mutated {
        blockers.push("stage38 unexpectedly mutated /sys/fs/bpf/dae".to_owned());
    }
    let production_name_dae0_dae0peer_attach_executed =
        opts.execute_smoke && production_name_attach_handoff_smoke_passed;
    let production_name_listen_socket_map_fd_update_executed =
        opts.execute_smoke && production_name_attach_handoff_smoke_passed;

    json!({
        "name": "stage38-production-dae-attach-admission",
        "stage": "stage38",
        "evidence_class": "root-gated-production-name-dae0-dae0peer-listener-handoff-smoke",
        "root": path_string(&opts.root),
        "execute_smoke": opts.execute_smoke,
        "root_gate_acknowledged": opts.ack_root_gate,
        "read_only": !opts.execute_smoke,
        "blocked": !blockers.is_empty(),
        "production_name_attach_handoff_smoke_passed": production_name_attach_handoff_smoke_passed,
        "production_name_dae0_dae0peer_attach_executed": production_name_dae0_dae0peer_attach_executed,
        "production_name_listen_socket_map_fd_update_executed": production_name_listen_socket_map_fd_update_executed,
        "production_dae0_dae0peer_attach_executed": production_name_dae0_dae0peer_attach_executed,
        "production_listen_socket_map_fd_update_executed": production_name_listen_socket_map_fd_update_executed,
        "production_default_daemon_attach_executed": false,
        "active_tproxy_traffic_executed": false,
        "live_candidate_run_allowed": false,
        "default_switch_allowed": false,
        "default_path_mutated": false,
        "product_chain_switch_allowed": false,
        "true_rust_default_daemon_admitted": false,
        "go_default_path_preserved": true,
        "go_fallback_required": true,
        "blockers": blockers,
        "checks": checks,
        "stage37_report": {
            "path": stage37.path,
            "status": stage37.status,
            "passed": stage37.passed,
            "blockers": stage37.blockers,
        },
        "production_name_contract": {
            "netns": PRODUCTION_NETNS,
            "host_iface": PRODUCTION_HOST_IFACE,
            "peer_iface": PRODUCTION_PEER_IFACE,
            "peer_section": opts.peer_section,
            "host_section": opts.host_section,
            "filter_pref": STAGE38_FILTER_PREF,
            "listen_socket_map_kernel_name": LISTEN_SOCKET_MAP_KERNEL_NAME,
            "expected_map_type": "SockMap",
            "expected_key_size": 4,
            "expected_value_size": 8,
            "expected_max_entries": 2,
            "listener_keys": [0, 1],
            "object_path": path_string(&opts.object_path),
        },
        "map_id_snapshots": {
            "before_attach": before_map_ids,
            "after_cleanup": after_map_ids,
            "discovered_map_id": discovered_map_id,
            "loaded_map_cleaned": loaded_map_cleaned,
        },
        "loaded_map_handoff": loaded_map_handoff,
        "temporary_production_named_resources": {
            "netns": PRODUCTION_NETNS,
            "host_iface": PRODUCTION_HOST_IFACE,
            "peer_iface": PRODUCTION_PEER_IFACE,
            "leftovers_after_cleanup": leftovers,
        },
        "sys_fs_bpf_dae": {
            "before": before_pin_snapshot,
            "after": after_pin_snapshot,
            "mutated": sys_fs_bpf_dae_mutated,
        },
        "executed_steps": executed_steps,
        "cleanup_steps": cleanup_steps,
        "peer_attach_show": peer_attach_show,
        "host_attach_show": host_attach_show,
        "remaining_blockers": remaining_blockers(),
    })
}
