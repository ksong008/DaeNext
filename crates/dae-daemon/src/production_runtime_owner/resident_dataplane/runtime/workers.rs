use super::*;
pub(crate) fn start_resident_dataplane_workers(
    handoff: &LiveLoadedTproxyListenSocketMap,
    config: &Config,
    artifact_dir: &Path,
    routing_tuple_map_id: Option<u32>,
) -> (Value, Option<ResidentDataplaneRuntime>) {
    let event_file = artifact_dir.join("resident-production-dataplane-events.jsonl");
    let _ = fs::remove_file(&event_file);
    let plan = match build_resident_dataplane_plan(config) {
        Ok(plan) => plan,
        Err(err) => {
            return (
                json!({
                    "status": "fail",
                    "enabled": false,
                    "error": err,
                    "event_file": path_string(&event_file),
                }),
                None,
            );
        }
    };
    if !plan.enabled {
        return (
            json!({
                "status": "pass",
                "enabled": false,
                "reason": plan.unsupported_reason,
                "event_file": path_string(&event_file),
            }),
            None,
        );
    }
    let Some(default_group) = plan.default_proxy_group().cloned() else {
        return (
            json!({
                "status": "fail",
                "enabled": true,
                "error": "resident dataplane plan is enabled without a default proxy group plan",
                "event_file": path_string(&event_file),
            }),
            None,
        );
    };
    let Some(default_proxy) = default_group.default_proxy_snapshot() else {
        return (
            json!({
                "status": "fail",
                "enabled": true,
                "error": "resident dataplane plan is enabled without an admitted default proxy candidate",
                "event_file": path_string(&event_file),
            }),
            None,
        );
    };
    let routing_matcher = match build_resident_userspace_routing_matcher(config) {
        Ok(matcher) => matcher,
        Err(err) => {
            return (
                json!({
                    "status": "fail",
                    "enabled": true,
                    "error": err,
                    "event_file": path_string(&event_file),
                }),
                None,
            );
        }
    };

    let tcp_listener = match handoff.listeners.tcp_listener.try_clone() {
        Ok(listener) => listener,
        Err(err) => {
            return (
                json!({
                    "status": "fail",
                    "enabled": true,
                    "error": format!("clone resident TCP listener: {err}"),
                    "event_file": path_string(&event_file),
                }),
                None,
            );
        }
    };
    let udp_socket = match handoff.listeners.udp_socket.try_clone() {
        Ok(socket) => socket,
        Err(err) => {
            return (
                json!({
                    "status": "fail",
                    "enabled": true,
                    "error": format!("clone resident UDP socket: {err}"),
                    "event_file": path_string(&event_file),
                }),
                None,
            );
        }
    };

    let reload_generation = RESIDENT_RELOAD_GENERATION.fetch_add(1, Ordering::Relaxed);
    let metrics = Arc::new(ResidentDataplaneMetrics::default());
    let udp_sessions_active = Arc::new(AtomicUsize::new(0));
    let event_lock = Arc::new(Mutex::new(()));
    let mut owner = ResidentRuntimeOwner::new(
        event_file.clone(),
        Arc::clone(&event_lock),
        reload_generation,
        Arc::clone(&metrics),
        Arc::clone(&udp_sessions_active),
    );
    let proxy = Arc::new(default_proxy);
    let proxy_group = Arc::new(default_group);
    let manual_probe_plans = plan::build_resident_manual_probe_plans(config);
    let manual_probe_plan_count = manual_probe_plans
        .values()
        .filter(|plan| plan.is_ok())
        .count();
    let manual_probe_unavailable_count = manual_probe_plans
        .len()
        .saturating_sub(manual_probe_plan_count);
    let runtime_groups = plan
        .proxies
        .values()
        .cloned()
        .map(Arc::new)
        .collect::<Vec<_>>();
    let health_groups = runtime_groups
        .iter()
        .filter(|group| group.needs_background_checks())
        .cloned()
        .collect::<Vec<_>>();
    let dns = Arc::new(plan.dns);
    let tcp_router = match ResidentTcpRouter::new(
        plan.proxies,
        routing_tuple_map_id,
        routing_matcher,
        plan.tcp_dial_mode,
        plan.sniffing_timeout,
        config.global.so_mark_from_dae,
        config.global.mptcp,
    ) {
        Ok(router) => Arc::new(router),
        Err(err) => {
            return (
                json!({
                    "status": "fail",
                    "enabled": true,
                    "error": err,
                    "event_file": path_string(&event_file),
                }),
                None,
            );
        }
    };
    let tcp_flow_stack_bytes = resident_tcp_flow_stack_bytes();
    let udp_session_limit = resident_udp_session_limit();
    let udp_session_queue_depth = resident_udp_session_queue_depth();
    {
        let stop = owner.stop_handle();
        let tcp_router = Arc::clone(&tcp_router);
        let event_file = owner.event_file();
        let event_lock = owner.event_lock();
        let metrics = owner.metrics();
        owner.register_thread(
            "tcp-accept-loop",
            "tcp-accept",
            thread::spawn(move || {
                resident_tcp_accept_loop(
                    tcp_listener,
                    tcp_router,
                    stop,
                    event_file,
                    event_lock,
                    metrics,
                    tcp_flow_stack_bytes,
                )
            }),
        );
    }
    {
        let stop = owner.stop_handle();
        let proxy_group = Arc::clone(&proxy_group);
        let dns = Arc::clone(&dns);
        let event_file = owner.event_file();
        let event_lock = owner.event_lock();
        let metrics = owner.metrics();
        let active_sessions = owner.udp_sessions_active();
        owner.register_thread(
            "udp-session-manager",
            "udp-session-manager",
            thread::spawn(move || {
                resident_udp_loop(
                    udp_socket,
                    proxy_group,
                    dns,
                    stop,
                    event_file,
                    event_lock,
                    metrics,
                    active_sessions,
                    udp_session_limit,
                    udp_session_queue_depth,
                )
            }),
        );
    }
    for health_group in &health_groups {
        let stop = owner.stop_handle();
        let health_group = Arc::clone(health_group);
        let event_file = owner.event_file();
        let event_lock = owner.event_lock();
        owner.register_thread(
            "health-check-loop",
            "health-check",
            thread::spawn(move || {
                resident_group_health_check_loop(health_group, stop, event_file, event_lock)
            }),
        );
    }

    let default_proxy_utls = proxy.utls_fingerprint.as_ref().map(|fingerprint| {
        json!({
            "source": fingerprint.source,
            "requested": &fingerprint.requested,
            "name": &fingerprint.name,
            "canonical": &fingerprint.canonical,
            "family": &fingerprint.family,
            "client": &fingerprint.client,
            "randomized": fingerprint.randomized,
            "alpn_policy": &fingerprint.alpn_policy,
        })
    });
    let start = json!({
        "status": "pass",
        "enabled": true,
        "tcp_worker_started": true,
        "udp_session_manager_started": true,
        "tcp_flow_stack_bytes": tcp_flow_stack_bytes,
        "tcp_flow_stack_bytes_env": RESIDENT_TCP_FLOW_STACK_BYTES_ENV,
        "udp_session_limit": udp_session_limit,
        "udp_session_limit_env": RESIDENT_UDP_SESSION_LIMIT_ENV,
        "udp_session_queue_depth": udp_session_queue_depth,
        "udp_session_queue_depth_env": RESIDENT_UDP_SESSION_QUEUE_DEPTH_ENV,
        "event_file": path_string(&event_file),
        "reload_generation": reload_generation,
        "runtime_owner": owner.task_registry_value(),
        "routing_tuple_map_id": routing_tuple_map_id,
        "tcp_dial_mode": tcp_router.dial_mode_name(),
        "tcp_sniffing_timeout": format!("{:?}", tcp_router.sniffing_timeout()),
        "proxy_count": tcp_router.proxy_count(),
        "health_check_worker_count": health_groups.len(),
        "manual_probe_plan_count": manual_probe_plan_count,
        "manual_probe_unavailable_count": manual_probe_unavailable_count,
        "default_group": {
            "group": proxy_group.group_name,
            "group_policy": proxy_group.group_policy_name(),
            "candidate_count": proxy_group.candidate_count(),
            "admitted_candidate_count": proxy_group.admitted_candidate_count(),
            "annotation_latency_offset_count": proxy_group.annotation_latency_offset_count(),
            "alive_state_wired": proxy_group.alive_state_wired(),
            "latency_state_wired": proxy_group.latency_state_wired(),
            "background_check_required": proxy_group.needs_background_checks(),
            "check_interval": format!("{:?}", proxy_group.check_interval()),
        },
        "default_proxy": {
            "protocol": proxy.protocol,
            "group": proxy.group_name,
            "group_policy": proxy.group_policy,
            "node_tag": proxy.node_tag,
            "server_host": proxy.server_host,
            "server_port": proxy.server_port,
            "server_name": proxy.server_name,
            "transport": proxy.net,
            "tls": proxy.tls,
            "flow": proxy.flow,
            "alpn": proxy.alpn,
            "allow_insecure": proxy.allow_insecure,
            "utls_fingerprint": default_proxy_utls,
            "mark": proxy.mark,
            "mptcp": proxy.mptcp,
            "executableGraph": proxy.executable_graph_value_for_reload_generation(reload_generation),
            "runtimeComponents": proxy.runtime_component_evidence_value_for_reload_generation(reload_generation),
        },
        "scope": "resident worker consumes live tproxy TCP/UDP sockets and relays through admitted Rust proxy handlers; unsupported protocols fail explicitly instead of faking proxy success",
    });
    (
        start,
        Some(ResidentDataplaneRuntime {
            owner,
            groups: runtime_groups,
            manual_probe_plans,
        }),
    )
}
